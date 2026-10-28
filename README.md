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

AD 2012 R2 can distribute the task via GPO; the application does not yet implement LDAP/AD sign-in or OU discovery. Win7–11 and Server 2008–2019 are collector design targets with prerequisites, not a claim of completed OS testing. See the compatibility table and data limitations in the deployment guide.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests exercise the real WSGI API and SQLite database using an isolated temporary database: login/CSRF, permission enforcement, persistence, scoped device check-ins, revocation, last-admin protection and session invalidation. No Windows, Docker daemon or AD integration is simulated as a successful real-world deployment.
