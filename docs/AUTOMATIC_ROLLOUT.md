# Automatic domain rollout — one AD-side setup, no manual PC enrollment

This package deploys inventory collection to existing Windows domain computers through one computer-side GPO scheduled task. Nexus creates each machine's token automatically; a Windows deployment server applies per-computer NTFS permissions. Domain PCs retrieve their own config as their computer account. No domain-admin password, Nexus administrator password or shared enrollment token is placed in a GPO, SYSVOL or endpoint script.

## 1. Prepare a bundle in Nexus

Upgrade the Docker app (`git pull --ff-only`, then `docker compose up -d --build nexus`) and hard-refresh the browser. Sign in as a Nexus administrator and open **Automatic rollout**.

- Select the computer OU/Base DN and whether to include children. Entire configured base includes `CN=Computers`. A user-only Base DN cannot see computer OUs outside it.
- Enter the FQDN of the Windows server where you will stage the files, e.g. `kmd.kmd.com`. That machine requires the ActiveDirectory PowerShell and SmbShare modules (the existing 2012 R2 AD server is a deployment target).
- Upload the Nexus gateway's **nexus-root.crt**, not the AD CA certificate. Obtain it from the existing Docker gateway as before. Verify that it is the intended Nexus CA before distributing trust.
- Workstations are selected by default. Windows Server accounts are optional. Disabled/unknown accounts, non-Windows records, unsupported names, missing computer SIDs and already enrolled/revoked names are skipped with reasons.
- Click Prepare and download the ZIP. Existing tokens, including DHCP-Server, are never rotated or reactivated by bulk preparation.

The archive contains device secrets. Keep the ZIP and extracted files in an administrator-only folder. Bundles are retained encrypted in the Nexus database for reliable re-download from Automatic rollout history; back up the matching `/data/nexus.ad.key`. Do not email/post these ZIPs or place them in SYSVOL or a broadly readable share. Creating a bundle does not deploy to clients or change AD.

## 2. Stage on the named Windows AD/file server

Log on to that server as an authorized elevated deployment administrator. Extract the ZIP to a protected local folder (example `C:\NexusRollout`). After reviewing the scripts, remove download blocking from these trusted scripts where your RemoteSigned policy requires it:

```powershell
Get-ChildItem C:\NexusRollout -Filter *.ps1 -Recurse | Unblock-File
& C:\NexusRollout\Install-NexusDeployment.ps1
```

Do not change an AllSigned GPO or use ExecutionPolicy Bypass to run the scripts. In an AllSigned environment, have the approved publisher sign the bootstrap/collector and update their hashes in the controlled rollout assets before publishing them. Re-review/update signatures and hashes on each code update.

The installer validates that it is running on the bundle's named server, resolves every computer account in AD again and checks its SID before copying credentials. It creates a dedicated `C:\Program Files\NexusDeployment` directory by default and two shares:

| Share | Contents | Effective file access |
|---|---|---|
| `\\SERVER\NexusAgent$` | Bootstrap, collector, CA and non-secret rollout settings | Authenticated read; Administrators/SYSTEM write |
| `\\SERVER\NexusEnroll$\PC-NAME\endpoint.xml` | Only that PC's token | That computer SID read; Administrators/SYSTEM full control |

The private share uses a broad read-only share ACL plus strict per-machine NTFS ACLs; the NTFS layer is what prevents another PC/user reading a token. Private share root grants traverse only, without inheriting a general read grant. Access-based enumeration is enabled. Domain users do not receive per-computer file read access. Never loosen these NTFS ACLs to solve a failed check-in. Check SMB reachability, domain secure channel, DNS and time instead. Source ZIPs also remain sensitive even after staging.

The installer does not modify or link existing GPOs. It prints the exact task command line for your chosen host. New bundles merge into the managed directory without removing previously staged configs. It rejects unrelated folders/shares and does not remove or reset your existing Zabbix, Nexus, AD or DHCP services.

SMB must already be permitted from the target clients to this domain/file server on your office network. No Internet-facing SMB access is required. The installer does not enable SMB1, change firewall policy or weaken authentication.

## 3. Create one computer GPO on AD

Open `gpmc.msc`. Create a new GPO such as **Nexus Automatic Inventory**, linked to the computer OU(s) you intend to inventory. For computers still in default `CN=Computers`, that container cannot be linked: link at a suitable parent/domain and use a reviewed computer security group/filter to select targets. Do not move production server/DC objects just to deploy this task.

Edit:

**Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks → New → Scheduled Task (At least Windows 7)**

- Action: Update.
- Name: `Nexus Automatic Inventory`.
- Run as: `NT AUTHORITY\SYSTEM`. Run with highest privileges. No saved domain administrator password.
- Configure for Windows 7 / Server 2008 R2 compatibility when targeting Win7–11; validate legacy Server 2008 separately before including it.
- Trigger 1: At startup, with a short delay (e.g. 2 minutes) if offered.
- Trigger 2: Daily; repeat every 10 minutes, indefinitely; enabled.
- Program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
- Arguments (replace SERVER with the bundle's share hostname; installer prints this):

```text
-NoProfile -NonInteractive -File "\\SERVER\NexusAgent$\Start-Nexus.ps1" -PublicShare "\\SERVER\NexusAgent$"
```

- Conditions: clear AC-power-only and stop-on-battery restrictions for laptops.
- Settings: run as soon as possible after a missed start; if already running, do not start another instance. A sensible execution time limit (e.g. 5 minutes) prevents stuck collectors accumulating.

The scheduled task runs every ten minutes after GPO processing, even if startup happened before the network became ready. Remote script execution must be allowed by your existing organizational signing/zone policy. If FQDN UNC scripts are blocked by RemoteSigned/AllSigned, use your approved signed-script process; do not disable execution policy. An alternative is approved computer-side GPO File preferences to copy the non-secret public assets to an administrator-only local directory before scheduling the bootstrap there, preserving `-PublicShare` and verification settings. Never distribute private configs with general GPO File preferences.

## 4. What happens on clients automatically

At the next applicable computer policy refresh/startup:

1. The SYSTEM task reads the public bootstrap and settings using the machine's domain identity.
2. It verifies asset SHA256 values from the administrator-controlled settings, installs the pinned Nexus root CA and locks `C:\Program Files\NexusAgent` to SYSTEM/Administrators.
3. It retrieves only `NexusEnroll$\ITS-COMPUTER-NAME\endpoint.xml`. NTFS grants only that computer SID the read access.
4. It checks the configured Nexus URL/computer name and runs the local collector, which sends an HTTPS check-in with that PC's unique token.
5. Later runs reuse the protected local config if the private file is temporarily unavailable. The public share/approved scripts must still be reachable. An already-enrolled machine can reuse its old `C:\ProgramData\Nexus\endpoint.xml` if present and matching the same Nexus URL; tokens are not rotated.

No one needs to log on to each PC, manually download a collector, generate each token or import a certificate on each PC. Ordinary user credentials are not used for collection. User-to-device links use the console identity reported at collection time, not SYSTEM's identity.

The settings hashes are integrity checks within a trusted AD administrator-controlled distribution channel; they do not replace Authenticode or defend against an administrator who can alter both scripts and settings. Restrict public-share write rights and retain your code-signing controls.

## 5. Verify and extend

- In Nexus, AD computers with collected inventory show Recent/Stale/Snapshot instead of Collector not linked.
- All devices shows CPU/RAM/storage/software once check-ins arrive; User & devices shows observed identity matches.
- Read task result and `C:\Program Files\NexusAgent\run.log` on a client when troubleshooting. `Check-in accepted.` means success. A missing config means that PC was excluded/skipped/not yet included in a staged bundle.
- Existing enrolled PCs with neither a staged config nor a valid local config are not automatically recovered from token hashes. Re-provision those explicitly using the existing enrollment/token-rotation workflow. An intentionally revoked token remains revoked.
- For AD computers added later, prepare another bundle and stage it centrally. Already enrolled names are skipped; the existing GPO applies automatically. This release does not continuously reconcile new AD accounts in the background.
- Domain renames, deleted/recreated computer accounts and password/token rotations need administrator review. Do not copy another computer's endpoint.xml.

There is no guarantee of morning data until target PCs receive the GPO, can reach the SMB shares/DNS/HTTPS endpoint, and successfully run their collector. Offline PCs and old OS/.NET builds without modern TLS do not report. No security protection is bypassed to make them report.

## Validation limits

Python tests exercise bulk scope, partial-query rejection, encrypted resumable ZIPs, per-machine manifest/config generation, existing/revoked-token preservation, download authorization and successful check-in with a generated token. The two new deployment PowerShell scripts pass a tree-sitter grammar parse. They are intended for AD 2012 R2 staging / Windows PowerShell 2+ endpoints, but there is no Windows/AD environment or actual PowerShell runtime in the development host. Actual NTFS/SMB denial tests and GPO application must be verified in your domain before broad rollout. They are not claimed as completed automated checks.
