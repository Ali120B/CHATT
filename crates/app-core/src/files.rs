//! Files (Phase 9): encrypted chunked transfer with integrity + resume.
//!
//! Each file gets a random 32-byte file key. Plaintext is chunked, every
//! chunk is sealed with that key bound to its index
//! (`seal_group(key, index, chunk)` — sequence binding defeats reorder and
//! replay), and a SHA-256 manifest covers the plaintext. The file key itself
//! travels inside the normal (DM- or group-encrypted) FileOffer, so file
//! bytes are never exposed to the coordinator, relay, or mailbox.

use anyhow::{Context, Result, bail};
use chat_crypto::ChunkManifest;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 56 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileOfferBody {
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub manifest: ChunkManifest,
    pub file_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    pub received_chunks: usize,
    pub total_chunks: usize,
    pub complete: bool,
}

/// Split + seal a file for sending. Returns the offer and one sealed blob
/// per chunk (each becomes a FILE_CHUNK envelope).
pub fn prepare_offer(
    file_id: &str,
    filename: &str,
    mime_type: &str,
    data: &[u8],
) -> Result<(FileOfferBody, Vec<Vec<u8>>)> {
    if data.len() as u64 > MAX_FILE_BYTES {
        bail!("file exceeds the 25 MB V1 limit");
    }
    if filename.trim().is_empty() || filename.len() > 255 {
        bail!("bad filename");
    }
    let file_key = chat_crypto::random_32();
    let manifest = ChunkManifest::build(data, CHUNK_BYTES as u32);
    let mut sealed = Vec::new();
    for (index, chunk) in data.chunks(CHUNK_BYTES).enumerate() {
        sealed.push(chat_crypto::seal_group(&file_key, index as u64, chunk)?);
    }
    Ok((
        FileOfferBody {
            file_id: file_id.to_string(),
            filename: sanitize_filename(filename),
            mime_type: if mime_type.is_empty() {
                "application/octet-stream".to_string()
            } else {
                mime_type.to_string()
            },
            size_bytes: data.len() as u64,
            sha256_hex: chat_crypto::sha256_hex(data),
            manifest,
            file_key,
        },
        sealed,
    ))
}

/// Seal one plaintext chunk for transport (index-bound, file-keyed).
pub fn seal_chunk(file_key: &[u8; 32], index: u32, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
    chat_crypto::seal_group(file_key, index as u64, chunk)
}

pub fn sanitize_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let clean: String = base
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | '\0'))
        .take(255)
        .collect();
    if clean.is_empty() {
        "file".to_string()
    } else {
        clean
    }
}

pub fn part_path(files_dir: &Path, file_id: &str) -> PathBuf {
    files_dir.join(format!("{file_id}.part"))
}

pub fn sidecar_path(files_dir: &Path, file_id: &str) -> PathBuf {
    files_dir.join(format!("{file_id}.received.json"))
}

fn read_received(files_dir: &Path, file_id: &str) -> Vec<u32> {
    std::fs::read(sidecar_path(files_dir, file_id))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_received(files_dir: &Path, file_id: &str, have: &[u32]) -> Result<()> {
    std::fs::create_dir_all(files_dir)?;
    std::fs::write(sidecar_path(files_dir, file_id), serde_json::to_vec(have)?)?;
    Ok(())
}

/// Apply one received chunk: authenticate, hash-check against the manifest,
/// write at its offset, and finalize (hash-verify + rename) when complete.
pub fn apply_chunk(
    files_dir: &Path,
    offer: &FileOfferBody,
    index: u32,
    sealed: &[u8],
) -> Result<FileProgress> {
    let total = offer.manifest.chunk_hashes.len();
    if index as usize >= total {
        bail!("chunk index out of range");
    }
    let chunk = chat_crypto::open_group(&offer.file_key, index as u64, sealed)
        .context("chunk failed authentication")?;
    if !offer.manifest.verify_chunk(index as usize, &chunk) {
        bail!("chunk {index} hash mismatch");
    }
    std::fs::create_dir_all(files_dir)?;
    let part = part_path(files_dir, &offer.file_id);
    let mut have = read_received(files_dir, &offer.file_id);
    // A part file without a sidecar is stale (previous crash): restart it so
    // offsets can never mix generations of the same transfer.
    let fresh = have.is_empty() && part.exists();
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(fresh)
            .open(&part)?;
        file.seek(SeekFrom::Start(index as u64 * CHUNK_BYTES as u64))?;
        file.write_all(&chunk)?;
    }
    if !have.contains(&index) {
        have.push(index);
        have.sort_unstable();
        write_received(files_dir, &offer.file_id, &have)?;
    }
    let complete = have.len() == total;
    if complete {
        finalize(files_dir, offer)?;
    }
    Ok(FileProgress {
        received_chunks: have.len(),
        total_chunks: total,
        complete,
    })
}

/// Indices the receiver is still missing (for FileAccept resume).
pub fn missing_chunks(files_dir: &Path, offer: &FileOfferBody) -> Vec<u32> {
    let have = read_received(files_dir, &offer.file_id);
    (0..offer.manifest.chunk_hashes.len() as u32)
        .filter(|i| !have.contains(i))
        .collect()
}

fn finalize(files_dir: &Path, offer: &FileOfferBody) -> Result<PathBuf> {
    use std::io::Read;
    let part = part_path(files_dir, &offer.file_id);
    let mut bytes = Vec::with_capacity(offer.size_bytes as usize);
    std::fs::File::open(&part)?.read_to_end(&mut bytes)?;
    bytes.truncate(offer.size_bytes as usize);
    if chat_crypto::sha256_hex(&bytes) != offer.sha256_hex {
        bail!("assembled file failed integrity check");
    }
    let dest = files_dir.join(&offer.filename);
    // Never overwrite an existing download; disambiguate instead.
    let mut final_dest = dest.clone();
    let mut counter = 1;
    while final_dest.exists() {
        let stem = dest.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let ext = dest.extension().and_then(|e| e.to_str()).unwrap_or("");
        final_dest = if ext.is_empty() {
            files_dir.join(format!("{stem} ({counter})"))
        } else {
            files_dir.join(format!("{stem} ({counter}).{ext}"))
        };
        counter += 1;
    }
    std::fs::rename(&part, &final_dest)?;
    let _ = std::fs::remove_file(sidecar_path(files_dir, &offer.file_id));
    Ok(final_dest)
}

pub fn cancel_incoming(files_dir: &Path, file_id: &str) {
    let _ = std::fs::remove_file(part_path(files_dir, file_id));
    let _ = std::fs::remove_file(sidecar_path(files_dir, file_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_chunk_receive_roundtrip() {
        let dir = std::env::temp_dir().join(format!("hearth-files-{}", uuid::Uuid::new_v4()));
        let data = b"roblox replacement chat file payload".repeat(5000);
        let (offer, sealed) = prepare_offer("f1", "notes.txt", "text/plain", &data).unwrap();
        assert!(sealed.len() > 1);
        let mut last = None;
        for (index, blob) in sealed.iter().enumerate() {
            last = Some(apply_chunk(&dir, &offer, index as u32, blob).unwrap());
        }
        let progress = last.unwrap();
        assert!(progress.complete);
        assert_eq!(progress.received_chunks, progress.total_chunks);
        let received = std::fs::read(dir.join("notes.txt")).unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let dir = std::env::temp_dir().join(format!("hearth-files-{}", uuid::Uuid::new_v4()));
        let (offer, sealed) = prepare_offer("f2", "a.bin", "", b"0123456789").unwrap();
        let mut bad = sealed[0].clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(apply_chunk(&dir, &offer, 0, &bad).is_err());
        assert!(missing_chunks(&dir, &offer).contains(&0));
    }

    #[test]
    fn oversize_file_refused() {
        let big = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
        assert!(prepare_offer("f3", "big.bin", "", &big).is_err());
    }
}
