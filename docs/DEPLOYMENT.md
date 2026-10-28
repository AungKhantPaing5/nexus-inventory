# KMD deployment guide

## Layout

Run the Docker stack on a supported Linux VM (Ubuntu 24.04 LTS is a suitable deployment target), separate from the 2012 R2 domain controller. The collector runs locally on endpoints and sends an outbound HTTPS request. The app can browse AD OUs/users over verified LDAPS or StartTLS using a read-only service account. It does not join AD or provide AD login/SSO. AD/GPO also distributes an approved collector task. See [AD setup](ACTIVE_DIRECTORY.md).

Only TCP 443 to the inventory VM is required for inventory check-ins. RDP runs directly from the administrator's workstation to an endpoint over the office LAN/VPN; opening 3389 publicly is not required. This release does not provide interactive browser screen control, command execution, remote restart or shutdown.

## Start

1. Install Docker Engine and Compose plugin on the Linux VM. Follow official Docker instructions: https://docs.docker.com/engine/install/ubuntu/
2. `python3 setup.py`. Use the internal DNS name and actual LAN IP of the VM. Initial administrator email is `itsupport@kmdcomputer.com`. Enter your chosen initial password when prompted; nothing echoes. The supplied password is intentionally absent from source and commit history. Existing databases are never reset by changing bootstrap credentials.
3. Add an internal DNS A record for the inventory hostname pointing to the VM.
4. `docker compose up -d --build` then `docker compose ps`.
5. Caddy issues an internal certificate. Export **only the root certificate**, not its private key:

   ```sh
   docker compose cp gateway:/data/caddy/pki/authorities/local/root.crt ./nexus-root.crt
   ```

6. Inspect/verify the certificate fingerprint, then distribute the trusted root certificate to administrator PCs and endpoints through your approved GPO (Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities). Never bypass certificate warnings or disable validation. Alternatively use your organization's existing trusted TLS certificate and adapt Caddy's `tls` directive.
7. Open `https://YOUR-INTERNAL-HOSTNAME`. Login and create named accounts with minimum required permissions.

`BIND_IP` defaults to 127.0.0.1 until you explicitly choose a VM LAN address in setup. Only the gateway is published; the app and SQLite database are internal. No database TCP port is opened. Docker uses a named persistent volume for inventory, users, tokens, sessions and audit records. Do not run `docker compose down -v` unless you intend to delete all persistent data.

## Permissions

| Permission | Grants |
|---|---|
| Administrator | All permissions plus account creation, permission changes, disabling accounts and password reset |
| inventory.read | Device and software details |
| inventory.import | Manual JSON import |
| inventory.export | CSV export; also requires inventory.read |
| remote.rdp | Generate audited RDP connection files; also requires inventory.read |
| audit.read | Latest 500 audit events |
| directory.read | Read AD organizational units and user details; AD connection settings remain admin-only |
| agents.manage | Enroll/rotate/revoke endpoint tokens and download collectors |

Permissions are checked by the API on every request. Account edits revoke that user's active sessions. At least one active administrator must remain. Password changes invalidate all that user's sessions. Login is account-rate-limited to ten failures per 15-minute window. Sessions expire after eight hours. SQLite contains salted PBKDF2 password hashes and SHA-256 token hashes, not reusable passwords or bearer tokens.

## GPO collector rollout

For central deployment without touching each PC, use the new [Automatic rollout](AUTOMATIC_ROLLOUT.md) bundle and one computer GPO. The following is the optional manual enrollment path.

Pilot one Windows 11, one Windows 7, one Server 2008 and one Server 2019 machine first.

1. In Nexus, Enroll device with its exact computer name; save that computer's unique token. A token cannot submit records for another name. Re-enrollment invalidates the old token. Revoke a token when decommissioning a computer.
2. Copy the appropriate collector to `C:\ProgramData\Nexus\collector.ps1`. Put that computer's config XML in `C:\ProgramData\Nexus\endpoint.xml`. Do not put tokens in SYSVOL/NETLOGON, a shared GPO command line, source control or a share readable by all domain users. Deliver each secret using an approved per-computer provisioning process. Restrict its NTFS ACL to SYSTEM and authorized administrators; the collector's output should have the same restriction.
3. Create a GPO Scheduled Task (computer scope) targeting a test OU. Run as SYSTEM using 64-bit Windows PowerShell, with a ten-minute trigger and a startup trigger. Do not provide a domain admin password. Use your organization's script-signing/execution policy; no `ExecutionPolicy Bypass` is required by this design.
4. Program: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`
5. Arguments:

   ```text
   -NoProfile -NonInteractive -File "C:\ProgramData\Nexus\collector.ps1" -ConfigPath "C:\ProgramData\Nexus\endpoint.xml" -OutputPath "C:\ProgramData\Nexus\inventory.json"
   ```

6. Confirm the first check-in appears as Recent. If transmission fails, use the saved JSON through the authenticated Import action. Do not weaken TLS for old endpoints.

No check-in for 20 minutes yields Stale. A manual import is Snapshot. These labels represent observation freshness, not proof that a computer is currently switched on/off. Repeated periodic check-ins update the same device row. Historical full snapshots and lifetime power-on totals are not retained; uptime is calculated from the Windows last-boot timestamp. Snapshot `collectedAt` comes from endpoint time; server `receivedAt` is recorded separately.

## Compatibility and data limits

| Endpoint | Collector path | Prerequisites / limits |
|---|---|---|
| Windows 7 | Legacy Windows PowerShell script | PowerShell 2.0+, .NET with System.Web.Extensions; reliable HTTPS requires OS/.NET TLS 1.2 updates and trusted CA |
| Windows 8/8.1/10/11 | Either script, normally collector.ps1 | Windows PowerShell 3–5.1; both files intentionally use the same conservative implementation |
| Server 2008 / 2008 R2 | Legacy script | PowerShell 2.0 and appropriate .NET must be installed; use offline JSON if modern TLS is unavailable |
| Server 2012 R2 / 2019 | Standard collector | Windows PowerShell, WMI access and trusted CA |

Scripts target **Windows PowerShell**, not PowerShell 7. These versions are design targets; no physical Windows/AD test environment was available during development. WMI and firmware may not expose DDR generation or disk media type. Such values stay Unknown rather than being inferred from capacity or model. Get-PhysicalDisk is used only when available; older WMI paths usually report disk type as unknown. Registry inventory covers machine-wide software and the collector account's HKCU; SYSTEM cannot enumerate all users' private installed apps or Store apps. Domain membership/current interactive user are read from WMI; the separate Active Directory browser reads OUs/users on demand. AD SSO is not implemented. Multi-session RDS user attribution may be incomplete.

The legacy Windows versions are outside this app's control: assess their patch/TLS state before enabling automatic check-ins. No Windows credentials are stored by Nexus. RDP host support depends on edition and endpoint configuration.

## Backup and restore

Back up the database with SQLite's online backup API while running:

```sh
docker compose exec -T nexus python -c "import sqlite3; s=sqlite3.connect('/data/nexus.db'); d=sqlite3.connect('/tmp/nexus-backup.db'); s.backup(d); d.close(); s.close()"
docker compose cp nexus:/tmp/nexus-backup.db ./nexus-backup.db
```

The backup contains inventory, user password hashes and audit records: store it encrypted under restricted access. Back up `/data/nexus.ad.key` separately with restricted access as well: it decrypts the saved AD bind credential. The SQLite backup alone cannot restore that credential without this key. Back up Caddy data securely too; it includes the CA private key. Do not publish backups.

For restore, stop the application and use a controlled admin maintenance container to replace `/data/nexus.db` in the named volume, preserving owner uid 10001. Remove stale WAL/SHM only after shutdown, then restart. Test restoration on a separate stack before relying on backups. Upgrade with `docker compose up -d --build`; current schema initialization is additive but future migrations must be reviewed.
