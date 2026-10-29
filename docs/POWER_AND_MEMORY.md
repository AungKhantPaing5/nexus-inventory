# Memory modules and power controls

Inventory shows OS-visible total RAM and each installed module separately (for example 2 GB + 2 GB). Module slot, capacity, DDR, configured clock speed, manufacturer and part number come from Win32_PhysicalMemory. Blank firmware fields remain unknown; old snapshots need another updated-agent check-in.

Administrators can grant remote.power separately from inventory.read. Both permissions are required. Open a device card for Restart, Shut down and Request status. Confirm by typing the exact device name. Windows Server snapshots are deliberately excluded. Only active enrolled agents with a recent check-in and SYSTEM collector capability accept requests.

Commands expire after 15 minutes and are consumed only once at the next normal check-in (typically 10 minutes). The backend never executes a command or accepts arbitrary shell text. Queued means waiting; delivered means returned to the collector, not proof of completed shutdown. A lost response can lose a request; requests are never automatically retried. Windows may prevent shutdown due to unsaved applications. The collector invokes shutdown.exe with /t 0 and without /f; no automatic forced closure is requested.

## Existing office deployment

1. On Ubuntu: git pull --ff-only; docker compose up -d --build nexus. Keep all existing volumes, secrets and office compose settings.
2. Sign in as administrator, open Automatic rollout, download **collector update (existing PCs)**. Do not download an old enrollment batch: saved batches contain their original collectors.
3. On the AD/file server, unblock the downloaded ZIP before extracting, extract to an administrator-controlled directory and review Update-NexusCollector.ps1.
4. From elevated PowerShell in the extracted directory run .\Update-NexusCollector.ps1. Default public directory is C:\Program Files\NexusDeployment\public. It backs up the collector and rollout XML, updates the collector SHA256 pin, and preserves all enrollment tokens and CA settings. No per-client installation or new GPO task required.
5. Existing SYSTEM tasks fetch the new collector at the next run. RAM modules appear and power buttons enable after a fresh check-in. To accelerate, invoke the existing Nexus task remotely on reachable clients.

Do not issue shutdown/restart solely to test deployment on active office machines. Backend tests cover permission/CSRF checks, confirmation, capability, server exclusion, duplicate requests, one-time delivery and expiration. Actual Windows execution needs office validation on an appropriate test workstation.
