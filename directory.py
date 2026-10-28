"""Read-only Active Directory browser. TLS verification is always required."""
import json
import os
import re
import ssl
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ldap3
from cryptography.fernet import Fernet, InvalidToken
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

DEFAULTS = {'enabled': False, 'host': '', 'port': 636, 'tls_mode': 'ldaps',
            'base_dn': '', 'bind_user': '', 'ca_pem': ''}


class DirectoryError(Exception):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def dn_parts(dn):
    try:
        if not isinstance(dn, str) or not dn.strip() or len(dn) > 2048:
            raise ValueError()
        return tuple((a.casefold(), v.casefold(), sep) for a, v, sep in parse_dn(dn.strip(), escape=False, strip=True))
    except Exception:
        raise DirectoryError('Invalid distinguished name (DN). Use OU=IT,DC=example,DC=local format.') from None


def within_base(dn, base):
    child, parent = dn_parts(dn), dn_parts(base)
    return len(child) >= len(parent) and child[-len(parent):] == parent


def load_settings(c):
    row = c.execute('SELECT payload FROM directory_settings WHERE id=1').fetchone()
    return {**DEFAULTS, **(json.loads(row[0]) if row else {})}


def public_settings(c):
    cfg = load_settings(c)
    return {k: cfg[k] for k in DEFAULTS} | {'password_set': bool(cfg.get('password_cipher'))}


def key_file(db):
    return Path(os.getenv('AD_KEY_FILE', str(Path(db).with_suffix('.ad.key'))))


def cipher(db, create=False):
    path = key_file(db)
    if create and not path.exists():
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(Fernet.generate_key())
    try:
        return Fernet(path.read_bytes())
    except (OSError, ValueError):
        raise DirectoryError('AD credential key is unavailable. Restore the key or re-enter the bind password.', 503) from None


def save_settings(c, db, values):
    if not isinstance(values, dict):
        raise DirectoryError('Invalid AD settings.')
    old = load_settings(c)
    cfg = {k: values.get(k, old[k]) for k in DEFAULTS}
    if not isinstance(cfg['enabled'], bool):
        raise DirectoryError('Enabled must be true or false.')
    for k in ['host', 'base_dn', 'bind_user', 'ca_pem', 'tls_mode']:
        if not isinstance(cfg[k], str):
            raise DirectoryError('Invalid setting: ' + k)
        cfg[k] = cfg[k].strip()
    if cfg['tls_mode'] not in ['ldaps', 'starttls']:
        raise DirectoryError('Choose LDAPS or StartTLS. Unencrypted LDAP is not supported.')
    try:
        cfg['port'] = int(cfg['port'])
        if not 1 <= cfg['port'] <= 65535: raise ValueError()
    except (ValueError, TypeError):
        raise DirectoryError('Invalid LDAP port.') from None
    if cfg['host'] and (len(cfg['host']) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', cfg['host'])):
        raise DirectoryError('Enter a DC DNS hostname only, without a URL, slash or port.')
    if cfg['base_dn']:
        dn_parts(cfg['base_dn'])
    if len(cfg['bind_user']) > 1024 or any(ord(x) < 32 for x in cfg['bind_user']):
        raise DirectoryError('Invalid bind account. Use a UPN or full account DN.')
    if len(cfg['ca_pem']) > 100000:
        raise DirectoryError('CA bundle is too large.')
    if cfg['ca_pem']:
        try:
            ssl.create_default_context(cadata=cfg['ca_pem'])
        except (ssl.SSLError, ValueError):
            raise DirectoryError('Invalid PEM CA certificate bundle.') from None
    pw = values.get('password', '')
    if not isinstance(pw, str) or len(pw) > 4096:
        raise DirectoryError('Invalid bind password.')
    # Never forward an existing secret to a changed endpoint or account implicitly.
    identity = ('host', 'port', 'tls_mode', 'bind_user', 'ca_pem')
    changed = any(cfg[k] != old[k] for k in identity)
    if changed and old.get('password_cipher') and not pw:
        raise DirectoryError('Re-enter the bind password when changing the DC, TLS trust, port or bind account.')
    cfg['password_cipher'] = (cipher(db, create=True).encrypt(pw.encode()).decode() if pw else old.get('password_cipher', ''))
    if cfg['enabled'] and not all([cfg['host'], cfg['base_dn'], cfg['bind_user'], cfg['password_cipher']]):
        raise DirectoryError('DC hostname, Base DN, bind account and password are required.')
    c.execute('INSERT INTO directory_settings(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload', (json.dumps(cfg),))
    return {k: cfg[k] for k in DEFAULTS} | {'password_set': bool(cfg['password_cipher'])}


@contextmanager
def open_directory(cfg, db):
    if not cfg['enabled']:
        raise DirectoryError('AD connection is not configured or is disabled. Ask an administrator to open AD settings.', 409)
    conn = None
    try:
        try:
            password = cipher(db).decrypt(cfg['password_cipher'].encode()).decode()
        except (InvalidToken, KeyError, UnicodeError):
            raise DirectoryError('Cannot decrypt AD credentials. Restore the AD key or re-enter the bind password.', 503) from None
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=cfg['ca_pem'] or None,
                        sni=cfg['host'], ssl_options=[ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1])
        server = ldap3.Server(cfg['host'], port=cfg['port'], use_ssl=cfg['tls_mode'] == 'ldaps',
                              tls=tls, get_info=ldap3.NONE, connect_timeout=5)
        conn = ldap3.Connection(server, user=cfg['bind_user'], password=password, read_only=True,
                                auto_referrals=False, raise_exceptions=True, receive_timeout=8,
                                auto_bind=False)
        conn.open()
        if conn.closed:
            raise DirectoryError('Cannot open the AD connection. Check DC DNS, network and TLS certificate.', 502)
        if cfg['tls_mode'] == 'starttls' and not conn.start_tls():
            raise DirectoryError('AD StartTLS negotiation failed. No bind was attempted.', 502)
        if not conn.bind():
            raise DirectoryError('AD bind failed. Check the read-only account and password.', 502)
        yield conn
    except DirectoryError:
        raise
    except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
        raise DirectoryError('AD bind failed. Check the read-only account and password.', 502) from None
    except (ldap3.core.exceptions.LDAPException, ssl.SSLError, OSError):
        # LDAP diagnostics can contain account identifiers; return a bounded generic message.
        raise DirectoryError('AD request failed. Check DC DNS, port, trusted CA, hostname, TLS and read permissions.', 502) from None
    finally:
        if conn is not None:
            try: conn.unbind()
            except Exception: pass


def scalar(attrs, name, default=''):
    value = attrs.get(name, default)
    if isinstance(value, list):
        value = value[0] if value else default
    return value


def search_entries(conn, base, filter_text, attributes, scope=ldap3.SUBTREE, limit=10000):
    """Follow AD's RFC2696 pages on the same connection; never silently truncate."""
    rows = []
    cookie = None
    deadline = time.monotonic() + 20
    seen = set()
    while True:
        conn.search(base, filter_text, search_scope=scope, attributes=attributes,
                    paged_size=200, paged_criticality=True, paged_cookie=cookie, time_limit=5)
        if conn.result.get('result', 0) != 0:
            raise DirectoryError('AD search did not complete. Check Base DN and service-account read permissions.', 502)
        entries = [x for x in conn.response if x.get('type') == 'searchResEntry']
        remaining = limit - len(rows)
        rows.extend(entries[:remaining])
        overflow = len(entries) > remaining
        more = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
        if len(rows) >= limit:
            return rows, bool(more) or overflow
        if not more:
            return rows, False
        if time.monotonic() >= deadline:
            return rows, True
        if more in seen:
            raise DirectoryError('AD returned a repeated paging cookie. Retry the directory query.', 502)
        seen.add(more)
        cookie = more


def filetime(value):
    try:
        n = int(value)
        if n <= 0 or n >= 9223372036854775807: return ''
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n//10)).isoformat()
    except (ValueError, TypeError, OverflowError):
        return value.isoformat() if isinstance(value, datetime) else ''


def verify_base(conn, base):
    conn.search(base, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['distinguishedName'], time_limit=5)
    if conn.result.get('result', 0) != 0 or not any(x.get('type') == 'searchResEntry' for x in conn.response):
        raise DirectoryError('Configured Base DN does not exist or is not readable.', 502)


def test_connection(cfg, db):
    with open_directory(cfg, db) as conn:
        verify_base(conn, cfg['base_dn'])
        return {'ok': True, 'message': 'TLS, bind and Base DN read succeeded.', 'base_dn': cfg['base_dn']}


def list_ous(cfg, db):
    with open_directory(cfg, db) as conn:
        verify_base(conn, cfg['base_dn'])
        entries, truncated = search_entries(conn, cfg['base_dn'], '(objectClass=organizationalUnit)', ['ou', 'name', 'description'], limit=5000)
    result = [{'dn': x['dn'], 'name': str(scalar(x['attributes'], 'ou', scalar(x['attributes'], 'name', x['dn']))),
               'description': str(scalar(x['attributes'], 'description')),
               'depth': max(0, len(dn_parts(x['dn']))-len(dn_parts(cfg['base_dn'])))} for x in entries]
    return {'base_dn': cfg['base_dn'], 'ous': sorted(result, key=lambda x: (x['name'].casefold(),x['dn'].casefold())),
            'truncated': truncated}


def list_users(cfg, db, selected='', query='', nested=True):
    if not cfg['enabled']:
        raise DirectoryError('AD connection is not configured or is disabled. Ask an administrator to open AD settings.', 409)
    selected = selected or cfg['base_dn']
    if not within_base(selected, cfg['base_dn']):
        raise DirectoryError('Selected OU must be within the configured Base DN.', 403)
    if not isinstance(query, str) or len(query) > 200:
        raise DirectoryError('Search must be 200 characters or fewer.')
    f = '(&(objectCategory=person)(objectClass=user)'
    if query:
        q = escape_filter_chars(query)
        f += f'(|(displayName=*{q}*)(sAMAccountName=*{q}*)(userPrincipalName=*{q}*)(mail=*{q}*))'
    f += ')'
    fields = ['displayName','sAMAccountName','userPrincipalName','mail','department','title',
              'telephoneNumber','userAccountControl','lastLogonTimestamp','description','memberOf']
    with open_directory(cfg, db) as conn:
        if dn_parts(selected) != dn_parts(cfg['base_dn']):
            conn.search(selected, '(objectClass=organizationalUnit)', search_scope=ldap3.BASE, attributes=['ou'], time_limit=5)
            if conn.result.get('result', 0) != 0 or not any(x.get('type') == 'searchResEntry' for x in conn.response):
                raise DirectoryError('Selected OU no longer exists or is not readable.', 404)
        entries, truncated = search_entries(conn, selected, f, fields, ldap3.SUBTREE if nested else ldap3.LEVEL)
    users = []
    for x in entries:
        a = x['attributes']
        try: enabled = not bool(int(scalar(a, 'userAccountControl', '')) & 2)
        except (ValueError,TypeError): enabled = None
        groups = a.get('memberOf', [])
        if not isinstance(groups, list): groups = [groups]
        users.append({'dn': x['dn'], 'name': str(scalar(a,'displayName',scalar(a,'sAMAccountName'))),
                      'username': str(scalar(a,'sAMAccountName')), 'upn': str(scalar(a,'userPrincipalName')),
                      'email': str(scalar(a,'mail')), 'department': str(scalar(a,'department')),
                      'title': str(scalar(a,'title')), 'phone': str(scalar(a,'telephoneNumber')),
                      'description': str(scalar(a,'description')), 'enabled': enabled,
                      'last_logon_replicated': filetime(scalar(a,'lastLogonTimestamp')),
                      'groups': [str(g) for g in groups]})
    return {'ou': selected, 'include_nested': nested, 'users': sorted(users,key=lambda x:(x['name'].casefold(),x['username'].casefold())),
            'truncated': truncated, 'count': len(users)}
