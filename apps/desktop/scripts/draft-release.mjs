#!/usr/bin/env node
// Hearth release pipeline (run via `npm run build` from apps/desktop).
//
// 1. `tauri build` — produces the native installer for THIS machine:
//    - Linux x64   -> AppImage (+ .deb) in src-tauri/target/release/bundle/
//    - Windows x64 -> NSIS setup .exe (and .msi) in the same layout
// 2. Uploads the AppImage / setup.exe to a GitHub **draft** release `v<version>`
//    (creates it if missing) using the `gh` CLI.
//
// Cross-platform note: one machine builds one OS. Push a tag (`git tag v1.0.0
// && git push origin v1.0.0`) and .github/workflows/release.yml builds Linux
// + Windows in CI and attaches both to the same draft release.
//
// Requires: `gh` CLI installed and authenticated (`gh auth login`).
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync, accessSync, constants } from "node:fs";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tauriConf = JSON.parse(
  (await import("node:fs")).readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8"),
);
const version = tauriConf.version;
const tag = `v${version}`;

function run(cmd, args, opts = {}) {
  console.log(`$ ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit", cwd: root, ...opts });
}

function gh(args) {
  return execFileSync("gh", args, { cwd: root, encoding: "utf8" });
}

// 0. sanity: gh available + authed
try {
  gh(["auth", "status"]);
} catch {
  console.error("ERROR: `gh` CLI not found or not authenticated. Run `gh auth login` first.");
  process.exit(1);
}

// 1. native build for this OS
// Sanitize PATH first: linuxdeploy scans every entry and aborts on
// unreadable ones (e.g. another user's home dir).
process.env.PATH = (process.env.PATH || "")
  .split(delimiter)
  .filter((entry) => {
    try {
      accessSync(entry, constants.R_OK | constants.X_OK);
      return true;
    } catch {
      return false;
    }
  })
  .join(delimiter);
run("npx", ["tauri", "build"]);

// 2. collect artifacts: AppImage (linux) + NSIS setup.exe (windows)
// NOTE: in a Cargo workspace, `target/` lives at the workspace root, NOT
// under src-tauri — so probe upward instead of assuming one location.
const bundleDirs = [];
{
  let dir = root;
  for (let depth = 0; depth < 4; depth++) {
    for (const sub of ["src-tauri/target/release/bundle", "target/release/bundle"]) {
      const candidate = join(dir, sub);
      if (existsSync(candidate) && !bundleDirs.includes(candidate)) {
        bundleDirs.push(candidate);
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
}
const wanted = [];
for (const bundleDir of bundleDirs) {
  for (const sub of ["appimage", "nsis"]) {
    const dir = join(bundleDir, sub);
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir)) {
      const lower = file.toLowerCase();
      const isAppImage = sub === "appimage" && lower.endsWith(".appimage");
      const isExe = sub === "nsis" && lower.endsWith("-setup.exe");
      if ((isAppImage || isExe) && statSync(join(dir, file)).size > 0) {
        wanted.push(join(dir, file));
      }
    }
  }
}
if (wanted.length === 0) {
  console.error(
    `ERROR: no AppImage/setup.exe found under any of:\n - ${bundleDirs.join("\n - ") || "(no bundle dirs found)"}\nBuild may have failed.`,
  );
  process.exit(1);
}
console.log("Artifacts:\n - " + wanted.join("\n - "));

// 3. draft release (create or reuse), then upload
let exists = true;
try {
  gh(["release", "view", tag]);
} catch {
  exists = false;
}
if (!exists) {
  const notesFile = join(root, "..", "..", ".github", "RELEASE_NOTES.md");
  const args = ["release", "create", tag, "--draft", "--title", `Hearth ${tag}`];
  if (existsSync(notesFile)) args.push("--notes-file", notesFile);
  else args.push("--notes", `Hearth ${tag} draft.`);
  gh(args);
  console.log(`Created draft release ${tag}.`);
}
gh(["release", "upload", tag, "--clobber", ...wanted]);
console.log(`Uploaded to draft release ${tag}. Review + publish at: gh release view ${tag} --web`);
