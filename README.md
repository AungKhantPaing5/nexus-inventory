# Nexus Inventory — KMD

Self-hosted 3D-style IT asset dashboard, Docker Compose, persistent SQLite, administrator-managed accounts and granular permissions. Includes authenticated per-device Windows collectors, server-side CSV export, software inventory, audit history and RDP connection-file generation.

## Quick start

```sh
python3 setup.py
docker compose up -d --build
```

Use `itsupport@kmdcomputer.com` and enter your initial password in the **local setup prompt**. No default password is committed. Setup writes an ignored bootstrap secret and environment configuration. Trust the generated internal CA using the procedure in [Deployment guide](docs/DEPLOYMENT.md), then open the configured HTTPS hostname.

**This repository is the self-hosted application.** The earlier hosted Site is a separate visual prototype and does not automatically connect to this server.

## Implemented

- Server-backed device inventory: CPU, RAM/DDR when available, disks/media when available, PC/domain/user, OS, installed desktop software, last boot and uptime.
- Users: create/edit accounts, enable/disable, reset password, individual API-enforced permissions; protect last active administrator.
- Password hashing, expiring HttpOnly sessions, CSRF protection, origin validation, login throttling, scoped revocable device token hashes.
- Local Windows WMI collectors, offline JSON import and scheduled HTTPS check-ins.
- Persistent audit log for administrative actions and RDP downloads.
- RDP file download launches the administrator's existing RDP client; **no browser remote-control gateway is included**.

AD 2012 R2 can distribute the task via GPO; the application can browse OUs/users over verified LDAPS or StartTLS. AD sign-in/SSO is not implemented. Win7–11 and Server 2008–2019 are collector design targets with prerequisites, not a claim of completed OS testing. See the compatibility table and data limitations in the deployment guide.

## Active Directory OU browser

Open **Active Directory → AD settings** as an administrator, enter your DC DNS hostname, Base DN and read-only bind account, paste its CA certificate, then **Save settings → Test saved connection**. Browse OUs, include/exclude sub-OUs, search users and inspect enabled/disabled status, department and direct groups. Grant `directory.read` to allow other Nexus accounts to view directory users. Bind passwords are encrypted, never returned by the settings API.

See [AD setup guide](docs/ACTIVE_DIRECTORY.md) for Windows Server 2012 R2 prerequisites, permissions, secure configuration and upgrade steps.

## AD computers and observed user devices

Open **AD computers** to see domain computer accounts by OU, even before collectors are deployed. The **Entire configured base** selection also includes `CN=Computers`. Directory account state is separate from collector freshness. With `inventory.read`, matching collected data appears alongside each AD computer.

In **Active Directory → Users**, open **User & devices** to see machines whose latest collector record identifies that user. Matching uses SID where available, otherwise an exact UPN or a domain-qualified username using the domain's verified DNS/NetBIOS identity. It never assigns ownership or guesses links from a bare username. Re-run updated collectors to add optional user SID reporting; existing records can still match qualified names.

See [AD setup guide](docs/ACTIVE_DIRECTORY.md#computers-and-observed-user-devices) for limits and deployment steps.

## One-time AD/GPO automatic rollout

Use **Automatic rollout** as a Nexus administrator to prepare all eligible AD computers in an OU/Base DN at once. Download the protected ZIP, run its staging installer on the named Windows AD/file server, then create one SYSTEM computer GPO task. Each PC retrieves its own token/config using its domain machine identity, trusts the pinned Nexus CA and runs the collector automatically. No manual client enrollment or shared token is required.

The installer creates administrator-controlled public assets and per-computer-SID protected private config shares. Existing and revoked tokens are not rotated/reactivated. Encrypted bundle history supports reliable re-download. New AD computers added later need another central bundle; there is no unattended directory reconciliation in this release.

See [Automatic rollout guide](docs/AUTOMATIC_ROLLOUT.md) for installation, the single GPO task, scope, access controls and validation limits.

## Tests

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

The tests exercise the real WSGI API and SQLite database using an isolated temporary database: login/CSRF, permission enforcement, persistence, scoped device check-ins, revocation, last-admin protection session invalidation, encrypted AD configuration, read-only AD transport and OU/user browsing against LDAP fixtures. No Windows, Docker daemon or AD integration is simulated as a successful real-world deployment.
