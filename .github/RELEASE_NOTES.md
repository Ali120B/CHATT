# Hearth (draft release notes)

Local-first, P2P-first encrypted chat overlay for desktop — a Roblox-chat replacement that floats on top of your game.

## Install

- **Linux (x64):** download the `.AppImage`, `chmod +x`, run. (Alt+click “Stay on top” pin in the pill bar; tray icon included.)
- **Windows (x64):** download the `-setup.exe` installer and run it.

Press `Alt+/` anywhere to summon Hearth, even mid-game. (Some Wayland compositors refuse global shortcuts — use the tray icon instead; Settings reports status.)

## First run

1. Create a local identity (username + display name).
2. Share invite codes with a friend (Friends tab → Copy).
3. Chat. Everything is end-to-end encrypted; history lives in local SQLite only.

No account needed. For offline delivery while a friend is away, one of you can deploy the optional Cloudflare worker (`cloud/worker/README.md`).

## Notes

- Voice/video calls are intentionally out of scope.
- Group encryption is V1 hybrid AEAD with per-epoch rotation (MLS migration documented in `plan.md`).
- Please test on a second machine/network and report connection issues with the Diagnostics output (Friends → Settings → Diagnostics).

## Credits

Built by **Ali120B** — alibashmail2010@yahoo.com
