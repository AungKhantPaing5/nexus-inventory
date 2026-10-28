"""Interactive local setup. Secrets are never committed."""
from pathlib import Path
import getpass, os, re
host=input('Internal DNS name (e.g. inventory.kmd.local): ').strip()
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host):raise SystemExit('Invalid hostname')
bind=input('Server LAN IP to bind (default 127.0.0.1): ').strip() or '127.0.0.1'
import ipaddress
ipaddress.IPv4Address(bind)
pw=getpass.getpass('Initial admin password (at least 12 characters): ')
if len(pw)<12 or pw!=getpass.getpass('Confirm password: '):raise SystemExit('Password mismatch or too short')
p=Path('secrets');p.mkdir(exist_ok=True);os.chmod(p,0o700)
f=p/'admin_password.txt';f.write_text(pw);os.chmod(f,0o600)
# Docker bind-mounted Compose secrets must be readable by container uid 10001.
# The parent secrets directory remains 0700 on the host.
os.chmod(f,0o644)
Path('.env').write_text('SITE_HOST='+host+'\nAPP_ORIGIN=https://'+host+'\nBIND_IP='+bind+'\n')
os.chmod('.env',0o600)
print('Setup complete. Run docker compose up -d --build. Admin: itsupport@kmdcomputer.com')
