# Wander Installer

**One-click installer for [Wander](https://github.com/faisal-nabulsi/Wander)** — the free iPhone location spoofer.

Plug in your iPhone, sign in with your Apple ID, and click **Install Wander**. It signs and installs the app and drops in the pairing file automatically. That's the whole app — nothing else.

## Use

1. Install **usbmuxd** for your platform:
   - **Windows:** [iTunes](https://apple.co/ms) (for the USB drivers)
   - **macOS:** already included
   - **Linux:** via your package manager if not already present
2. Download Wander Installer for your OS from [Releases](https://github.com/faisal-nabulsi/Wander-Installer/releases).
3. Plug in your iPhone (USB), tap **Trust**, sign in with your Apple ID, and click **Install Wander**.
4. Then, on the phone: turn on **Developer Mode** (*Settings → Privacy & Security → Developer Mode*), open **LocalDevVPN**, and open **Wander**.

> A free Apple ID signature lasts 7 days. Re-run Wander Installer to refresh it before it expires (or see the Wander README for the SideStore auto-refresh option).

## Build from source

```bash
npm install
npm run tauri build   # or: npm run tauri dev
```
Requires Node + the Rust toolchain (Tauri).

## Credits & License

Wander Installer is a rebranded fork of **[iloader](https://github.com/nab138/iloader)** by nab138 — huge thanks to that project, which does the heavy lifting (Apple-ID signing, install, and pairing). iloader's source is under the **MIT License** (see [LICENSE](LICENSE)); see [LICENSE-BRANDING](LICENSE-BRANDING) for branding/attribution terms. Wander Installer is **not affiliated with or endorsed by** the iloader project.
