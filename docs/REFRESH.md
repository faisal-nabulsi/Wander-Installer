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

## Option 3 — Bundle SideStore for on-device refresh (best for untethered)
In the same one-click flow, Wander Installer installs **both Wander and a minimal SideStore**, and hands SideStore the pairing file. SideStore then refreshes Wander **on the phone, with no computer**, forever (this is the AltStore model — the installer bootstraps an on-device refresher). iloader already knows how to install SideStore, so most of this exists.
- ✅ Truly untethered — after the first setup, **no computer ever again**.
- ✅ Still one click for the user.
- ❌ SideStore lives on the phone (runs invisibly; the user doesn't have to touch it).
- **Effort:** medium. Chain `install_sidestore_operation` + `install_wander_operation`, place pairing into both, and (optionally) pre-select Wander in SideStore's auto-refresh list.

## Recommendation
- Ship **Option 1** now (done).
- Build **Option 3** next for the "no computer after setup" experience you want — it reuses code iloader already has and gives untethered refresh, which Option 2 can't.
- Keep **Option 2** as a "no second app on my phone" alternative for power users.

None of these remove the **one-time** computer bootstrap (Apple requires a computer to first sign an app onto a non-jailbroken iPhone) or the **Developer Mode** toggle (Apple requires the user to enable it by hand). Those are Apple-imposed and unavoidable for every tool, including the paid ones.
