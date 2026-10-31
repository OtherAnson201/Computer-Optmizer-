# Computer Optimizer

Tunes a Windows VPS (Windows 10 or Server 2022) to run many Roblox clients at once with as little CPU and memory per client as possible. One script applies everything, and a second one checks that it took.

> [!WARNING]
> **Only run this on a dedicated VPS, not your everyday PC.**
>
> - It changes system-wide settings and has no undo.
> - It **deletes `loader.py` and reboots the machine** 15 seconds after finishing, so keep a copy somewhere else.
> - Some paths assume you're logged in as `Administrator`.

## Usage

Needs Python 3 on Windows, with no extra packages. It asks for admin rights itself.

```
python loader.py
```

Progress is logged to `C:\ProgramData\RobloxOptimizer\worker.log`.

After the reboot, open PowerShell as administrator and check the result. It prints `[OK]` or `[FAIL]` for each setting, then a summary.

```
powershell -ExecutionPolicy Bypass -File check_opti.ps1
```

## What it changes

### Windows

- **Power:** switches to a high performance plan, turns off CPU core parking and throttling, and disables sleep and monitor timeouts.
- **Network:** widens the TCP and UDP port range to 64,511 ports and turns off network adapter power saving, which helps avoid port exhaustion with many clients.
- **Memory:** disables memory compression and page combining, and purges the standby and modified memory lists before rebooting.
- **Boot:** turns the hypervisor off and removes old `bcdedit` timer tweaks.
- **Old tweaks:** undoes settings left behind by earlier optimizers.
- **Mem Reduct:** installs [Mem Reduct](https://github.com/henrypp/memreduct) from its official GitHub release and keeps it running.

### Scheduled tasks

| Task | What it does |
|---|---|
| `TempCleanup5Min` | Clears the temp and Prefetch folders every 5 minutes |
| `MemReductAndRobloxFpsLoop` | Restarts Mem Reduct if it stops, and holds the Roblox FPS cap at 6 |
| `FarmSyncWatchdog` | Watches the FarmSync client's state file and reports when it stops updating |

It also disables Server Manager from opening at logon.

### Roblox

- **Graphics:** writes low graphics FFlags for every installed Roblox version.
- **GPU:** sets the Windows GPU preference to high performance for Roblox.
- **Game files:** replaces sounds and textures with empty stubs and removes unused shaders. The originals are kept in a `_backup` folder inside each version.
- **Cleanup:** disables the crash handler and clears old logs.

## Files

| File | Purpose |
|---|---|
| `loader.py` | Applies everything, then deletes itself and reboots |
| `check_opti.ps1` | Read-only check of the network, memory, power and boot settings |

## License

[MIT](LICENSE). Running many Roblox clients may break Roblox's terms, so use this at your own risk.
