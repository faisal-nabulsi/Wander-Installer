# Automating the 7-day refresh (design notes)

A free Apple ID signature lasts **7 days**. After that, Wander stops opening until it's re-signed. Here are the three ways Wander Installer can handle that, cheapest → best-for-users.

## Option 1 — Re-run the installer (shipping now)
The user re-opens Wander Installer once a week and clicks Install Wander again.
- ✅ Zero extra code, zero background processes.
- ❌ Manual, and needs the computer + cable each time.

## Option 2 — Background re-sign agent (no UI, tethered to the computer)
Wander Installer sets up a tiny OS scheduled job — **launchd** on macOS, **Task Scheduler** on Windows — that wakes on a timer, and if the iPhone is reachable (USB or same Wi-Fi) and the Apple ID is saved in the keyring, silently re-signs + reinstalls Wander using the same `isideload` engine.
- ✅ Fully automatic, no UI (this is exactly what you asked for).
- ✅ No extra app on the phone.
- ❌ The **computer** has to be on and the phone reachable within each 7-day window. (This is how AltServer works.)
- **Effort:** medium. Reuse the existing `sideload()` path with `resign_immediately = true`; add an agent installer + a headless "refresh" entrypoint.

## Option 3 — Install via SideStore for on-device refresh (untethered)
**Important correction:** SideStore only auto-refreshes apps **it installed itself**. It will *not* refresh a copy of Wander that Wander Installer sideloaded directly. So for untethered refresh, Wander has to be **installed through SideStore**:
1. Wander Installer installs **SideStore** (one click) and places the pairing file into it — iloader already does exactly this.
2. Then Wander is installed **from inside SideStore** using our source (`.../apps.json`). SideStore now manages Wander and refreshes it **on the phone, no computer**, forever.

- ✅ Truly untethered — after first setup, **no computer ever again**.
- ⚠️ Trade-off: this is **not** the one-click *direct* install — Wander comes from SideStore (an extra "open SideStore → install Wander" step), and SideStore lives on the phone.
- **Effort:** low — reuses `install_sidestore_operation` + our existing SideStore source.

## Recommendation
There's an unavoidable fork here: **one-click direct install** (what ships now) and **untethered no-computer refresh** can't both be true — untethered refresh needs an on-device re-signer (a SideStore-like app), which means Wander has to be a *SideStore-managed* app.

- **If minimal one-click matters most:** keep the direct install (done) + a weekly re-run, or add **Option 2** (silent background re-sign agent — automatic, but needs the computer on).
- **If no-computer-ever matters most:** go **Option 3** — Wander Installer sets SideStore up, and Wander installs/refreshes through it.

None of these remove the **one-time** computer bootstrap (Apple requires a computer to first sign an app onto a non-jailbroken iPhone) or the **Developer Mode** toggle (Apple requires the user to enable it by hand). Those are Apple-imposed and unavoidable for every tool, including the paid ones.
