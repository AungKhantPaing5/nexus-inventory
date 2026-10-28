# Active Directory OU and user browser

Nexus reads organizational units and user objects from AD using LDAPS (normally TCP 636) or mandatory StartTLS (normally TCP 389). The bind connection is read-only and referral following is disabled. The domain controller's CA chain and DNS hostname are verified; there is no insecure LDAP / ignore-certificate switch.

## Upgrade your existing Docker installation

```sh
git pull --ff-only
docker compose up -d --build
```

Keep the existing named data volume. Startup adds the `directory_settings` table without deleting inventory or accounts. Existing administrators automatically retain all privileges; existing non-admin users do not automatically gain `directory.read`.

## Windows Server 2012 R2 prerequisites

1. Ensure the selected DC supports TLS 1.2, has current applicable updates and a valid AD LDAP server certificate with Server Authentication usage. Its SAN must include the DC hostname you will enter in Nexus. Use your organization's certificate management process; do not disable verification to work around a missing certificate.
2. From the Docker VM, make sure the DC DNS name resolves and the selected LDAP port is reachable. Add internal DNS settings to the `nexus` service in Compose if Docker's normal DNS cannot resolve your AD zone. Both internal DNS and a network route to the DC are required.
3. Create a dedicated service account, e.g. `svc-nexus@YOUR-AD-DOMAIN`. A Domain Admin account is unnecessary. Grant only the ability to read the target Base DN, OU objects and required user attributes. Standard AD directory read permissions often already provide this; confirm against your domain's actual delegated ACLs.
4. Export the issuing CA/root/intermediate public certificates as a PEM bundle. Do not upload a certificate private key.

Reference: [Microsoft LDAPS certificate requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority), [ldap3 TLS verification](https://ldap3.readthedocs.io/en/latest/ssltls.html).

## Configure through Nexus

Sign in with the existing Nexus administrator and open **Active Directory → AD settings**.

| Field | Example only |
|---|---|
| Enable directory connection | Checked |
| Domain controller DNS name | `dc01.example.local` |
| TLS connection | LDAPS |
| Port | `636` |
| Base DN | `DC=example,DC=local` |
| Bind account | `svc-nexus@example.local` |
| Bind password | Enter your AD service-account password locally |
| Trusted AD CA certificate bundle | PEM public CA certificate(s) |

These are examples, not your actual domain values. For a restricted view, set Base DN to an OU such as `OU=Staff,DC=example,DC=local`. The browse API rejects requests outside that Base DN. The DC's own ACLs remain authoritative.

Click **Save settings**, then **Test saved connection**. A successful test verifies TLS, credentials and readability of the configured Base DN. If the app reports DNS, certificate or bind failures, fix those on the server/DC before browsing. Saving settings alone is not evidence that a connection succeeded.

The app's HTTPS certificate/CA and the DC's LDAP certificate/CA are separate. Enter the AD CA here. Leaving the CA field blank uses the container's system CA store, which generally does not trust private company CAs unless you have installed them there.

The saved password field remains blank in the UI and API; blank preserves an existing password. Changing the DC, port, TLS mode, bind identity or CA requires re-entering the password to avoid silently forwarding an existing secret to a changed destination. Passwords are encrypted with Fernet and a mode-0600 key in `/data/nexus.ad.key` (or `AD_KEY_FILE`). Restrict and back up the data volume and key. Someone with access to both the database and key can decrypt the credential; encryption does not defend against a compromised application host.

## Browse OUs and users

- The OU panel lists AD organizational units with their full DNs to disambiguate repeated names. Select an OU to read its users.
- **Entire configured base** includes user containers such as `CN=Users`, even though those are not OUs.
- **Include sub-OUs** searches the selected subtree. Turning it off reads only direct child users.
- Search display name, username, UPN or email. Search text is escaped as LDAP filter data.
- User rows show display name, `sAMAccountName`, email, department and enabled/disabled state. Details include UPN, title, telephone, description, direct group DNs and approximate replicated last-logon time.
- The group list is the direct `memberOf` attribute. It does not include the primary group or recursively compute nested/effective group membership.
- `lastLogonTimestamp` is replicated and approximate; it is not a live login/session or precise audit record.
- AD queries use 200-entry server pages on one connection to handle AD's usual result-size limits. Browser pages show 100 returned users at a time. Safety limits are 5,000 OUs, 10,000 users and a bounded query time; a visible warning indicates incomplete results. Narrow the Base DN/selected OU/search instead of assuming a capped result is complete.
- Browse requests read from AD on demand; they do not persist a full directory snapshot. Disconnected AD returns an error rather than silently showing old directory records.

## Permissions and scope

`directory.read` grants OU and user browsing. Only administrators may read/change connection settings or run the saved connection test. The same directory Base DN applies to all authorized viewers; per-viewer OU restrictions are not implemented. Use a restricted Base DN and service-account ACL if needed.

This feature does not create Nexus accounts for AD users, grant them application permissions, implement AD authentication/SSO or modify AD users/groups. It can correlate user identities with the latest endpoint inventory snapshots as described below. This observation is not an ownership or authorization assignment.

Audit records include configuration changes (without credentials), connection tests and read counts. Do not enable LDAP protocol debug logging in production, as detailed traces may contain directory information.

## Back up the credential key

Alongside the existing SQLite online backup, securely export the key:

```sh
docker compose cp nexus:/data/nexus.ad.key ./nexus-ad-credential.key
chmod 600 ./nexus-ad-credential.key
```

Keep this key separately from shared reports and source control. If restoring a saved AD configuration, restore the matching key to the configured path with owner uid 10001 and mode 0600. A missing/corrupt/mismatched key causes a clear error; it never falls back to plaintext. Alternatively re-enter the service-account password under a restored valid/new key.

## Verification limits

Automated tests cover SQLite settings/API permissions, encryption/redaction, DN boundaries, nested/direct OU scope, search filter injection handling, AD-sized paging, account status and TLS-before-bind behavior using LDAP fixtures and transport mocks. They are not a test against your actual AD 2012 R2 server. Docker image startup and a real DC certificate/network/bind must be verified in your environment.


## Computers and observed user devices

Upgrade the existing stack without replacing its `.env`, DNS overrides, certificates, enrollment tokens or persistent data:

```sh
cd /opt/nexus-inventory
git pull --ff-only
docker compose up -d --build nexus
```

Hard-refresh the browser (Ctrl+F5). Use **AD computers** in the sidebar or **Active Directory → Computers**. Select an OU and choose whether to include sub-OUs. **Entire configured base** includes the default `CN=Computers` container. A Base DN restricted to a user-only OU cannot show computer accounts in other OUs; choose a common parent Base DN when that is intended and permitted.

Computer rows include name, DNS hostname, OS recorded in AD, enabled/disabled account state and approximate replicated last-logon time. The AD `managedBy` attribute is shown only as directory metadata, not as proof of ownership or logged-on user. Hardware, apps and current reachability cannot be obtained from an AD computer object alone. An AD record may remain after a PC has been retired.

An inventory row is linked to a computer account only when its computer name (short name, computer account without `$`, or AD DNS hostname) and reported DNS domain match. Domain-mismatched / workgroup machines are not joined by short name alone. The inventory field is hidden unless the caller also has `inventory.read`. **Collector not linked** means no matching report; it does not mean the computer is powered off. Default AD computer search cap is 10,000 entries with the same time and paging protections as user queries.

To see a user's machines, open **Active Directory → Users → User & devices → Observed devices**. This API requires both `directory.read` and `inventory.read`, resolves the selected user again from AD within the configured Base DN, and compares it with the latest saved report per endpoint:

1. If AD and collector both supply a SID, require exact SID equality. A different SID blocks a name-based fallback.
2. Otherwise accept an exact UPN, or the exact `DNS-domain\sAMAccountName` / verified `NetBIOS-domain\sAMAccountName` identity.
3. The actual NetBIOS domain is read from AD RootDSE / Configuration Partitions cross-reference. It is not guessed from the first DNS label. If that optional metadata is unreadable, SID/UPN/DNS-qualified matching remains available.
4. Bare usernames, empty users and unrelated local `PC\user` accounts are not linked.

Each result shows matched identity, matching method, snapshot collection time, server receipt time and Recent/Stale/Snapshot status. Links describe the console user observed at that collection time. They do not indicate ownership, all live RDP sessions or all users who have ever used the machine. A later report for a different user replaces that association. Full login history is not retained. Collector/import metadata is administrative inventory data, not an authentication source.

The updated collectors optionally translate `Win32_ComputerSystem.UserName` to a SID; if translation fails they continue collecting with the qualified username. Use Windows PowerShell as before. Download the updated collector to each endpoint; keep that endpoint's existing `endpoint.xml` and token. Review/unblock this downloaded script when your RemoteSigned policy requires it, or sign it according to an AllSigned policy. Trust the existing Nexus CA and run the collector while the intended user is signed into the console. Do not use the scheduled-task service account's identity as the observed user.

A Server 2008/Win7–11 real-machine compatibility test of the new optional SID translation was not available during development. API and LDAP fixture tests exercise computer paging/scopes, domain collisions, user identity resolution, SID conflicts, stale snapshot behavior and permission boundaries. Your office deployment must still verify actual AD computers, collector reports and account formats.


For unattended client configuration after one central AD-side setup, use **Automatic rollout** and follow [the bulk rollout guide](AUTOMATIC_ROLLOUT.md). This creates credentials for AD computer accounts in bulk, stages them with per-computer NTFS access and uses one SYSTEM GPO task. It does not create AD user login accounts in Nexus.
