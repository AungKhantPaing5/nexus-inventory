"""Nexus LAN inventory WSGI application; authenticated WSGI service with read-only AD browsing."""
import directory
import csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time
from pathlib import Path
from contextlib import contextmanager
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent
DB = os.getenv('DATABASE_PATH', '/data/nexus.db')
ORIGIN = os.getenv('APP_ORIGIN', 'https://localhost')
PERMS = ['inventory.read','inventory.import','inventory.export','remote.rdp','audit.read','agents.manage','directory.read']
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')

@contextmanager
def connect():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    try:
        with c:
            yield c
    finally:
        c.close()

def password_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', value.encode(), salt.encode(), 600000).hex()

def password_ok(value, stored):
    return hmac.compare_digest(password_hash(value, stored.split(':')[0]), stored)

def digest(s): return hashlib.sha256(s.encode()).hexdigest()

def initialize():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE COLLATE NOCASE,password TEXT,admin INTEGER,permissions TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),csrf TEXT,expires REAL);
        CREATE TABLE IF NOT EXISTS devices(name TEXT PRIMARY KEY COLLATE NOCASE,payload TEXT,received REAL,source TEXT);
        CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY,name TEXT UNIQUE COLLATE NOCASE,token TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at REAL,actor TEXT,action TEXT,target TEXT);
        CREATE TABLE IF NOT EXISTS directory_settings(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY,count INTEGER,started REAL);
        ''')
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            f = os.getenv('ADMIN_PASSWORD_FILE')
            pw = Path(f).read_text().strip() if f else os.getenv('ADMIN_PASSWORD','')
            if len(pw) < 12: raise RuntimeError('Set ADMIN_PASSWORD_FILE to an initial password of at least 12 characters')
            c.execute('INSERT INTO users(email,password,admin,permissions) VALUES(?,?,1,?)', (os.getenv('ADMIN_EMAIL','itsupport@kmdcomputer.com'),password_hash(pw),json.dumps(PERMS)))

def log(c, actor, action, target=''):
    c.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',(time.time(),actor,action,str(target)[:500]))

def public_user(u): return {k:u[k] for k in ['id','email','admin','active']} | {'permissions':json.loads(u['permissions'])}

class Fail(Exception):
    def __init__(self, status, message): self.status,self.message=status,message

def valid_records(data):
    records = data if isinstance(data,list) else [data]
    if not 1 <= len(records) <= 1000: raise Fail(400,'Import 1–1000 devices per request')
    clean=[]
    for d in records:
        if not isinstance(d,dict) or not NAME.fullmatch(str(d.get('name',''))): raise Fail(400,'Invalid computer name')
        apps=d.get('apps',[])
        if not isinstance(apps,list) or len(apps)>5000 or any(not isinstance(a,dict) or not isinstance(a.get('name'),str) for a in apps): raise Fail(400,'Invalid apps array')
        fields=['name','type','user','cpu','ddr','storage','uptime','model','domain','ip','boot','collectedAt','os','serial','userSid']
        x={k:str(d.get(k,'Unknown'))[:4000] for k in fields}
        try: x['ram']=float(d.get('ram',0))
        except (TypeError,ValueError): raise Fail(400,'Invalid RAM')
        if not __import__('math').isfinite(x['ram']) or not 0 <= x['ram'] <= 1000000: raise Fail(400,'Invalid RAM')
        x['apps']=[{'name':a['name'][:500],'version':str(a.get('version',''))[:100]} for a in apps]
        clean.append(x)
    return clean

def inventory_record(row):
    d=json.loads(row['payload']); age=time.time()-row['received']
    d.update({'receivedAt':row['received'],'source':row['source'],
              'status':('Recent' if age<1200 else 'Stale') if row['source']=='agent' else 'Snapshot'})
    return d


def inventory_summary(row):
    d=inventory_record(row)
    keys=['name','type','domain','user','userSid','cpu','ram','ddr','storage','os','model',
          'collectedAt','receivedAt','source','status']
    return {k:d.get(k,'') for k in keys}


def application(env, start_response):
    headers=[('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY'),('Referrer-Policy','same-origin'),('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")]
    status=200; content_type='application/json'; body={}
    try:
        method=env['REQUEST_METHOD']; path=env.get('PATH_INFO','/'); now=time.time()
        if method not in ['GET','POST']: raise Fail(405,'Method not allowed')
        if path=='/health': body={'ok':True}
        elif method=='GET' and path in ['/','/app.js','/login.html']:
            p=ROOT/'static'/({'/':'index.html','/app.js':'app.js','/login.html':'login.html'}[path])
            content_type='application/javascript' if p.suffix=='.js' else 'text/html; charset=utf-8'; body=p.read_bytes()
        else:
            with connect() as c:
                length=int(env.get('CONTENT_LENGTH') or 0)
                if length>8*1024*1024 or length<0: raise Fail(413,'Request too large')
                data={}
                if method=='POST':
                    if env.get('CONTENT_TYPE','').split(';')[0]!='application/json': raise Fail(415,'Use application/json')
                    try: data=json.loads(env['wsgi.input'].read(length).decode('utf-8-sig'))
                    except (ValueError,UnicodeError): raise Fail(400,'Invalid JSON')
                if path=='/api/login' and method=='POST':
                    if env.get('HTTP_ORIGIN')!=ORIGIN: raise Fail(403,'Origin mismatch')
                    if not isinstance(data,dict): raise Fail(400,'Invalid login')
                    email=str(data.get('email',''))[:254].lower(); pw=str(data.get('password',''))[:1024]
                    key=email # Account-scoped limit also works behind a reverse proxy.
                    a=c.execute('SELECT * FROM attempts WHERE key=?',(key,)).fetchone()
                    if a and a['started']>now-900 and a['count']>=10: raise Fail(429,'Too many attempts. Retry in 15 minutes.')
                    u=c.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
                    good=password_ok(pw,u['password']) if u else password_ok(pw,password_hash('dummy-password'))
                    if not u or not good:
                        c.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN started<? THEN 1 ELSE count+1 END,started=CASE WHEN started<? THEN excluded.started ELSE started END',(key,now,now-900,now-900))
                        log(c,email,'login.failed'); c.commit(); raise Fail(401,'Invalid email or password')
                    c.execute('DELETE FROM attempts WHERE key=?',(key,)); c.execute('DELETE FROM sessions WHERE expires<?',(now,))
                    token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
                    c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(token),u['id'],csrf,now+28800)); log(c,email,'login')
                    secure='; Secure' if ORIGIN.startswith('https://') else ''
                    headers.append(('Set-Cookie',f'nexus_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{secure}'))
                    body={'user':public_user(u),'csrf':csrf}
                elif path=='/api/checkin' and method=='POST':
                    token=env.get('HTTP_AUTHORIZATION','').removeprefix('Bearer ')
                    agent=c.execute('SELECT * FROM agents WHERE token=? AND active=1',(digest(token),)).fetchone()
                    if not agent: raise Fail(401,'Invalid device token')
                    records=valid_records(data)
                    if len(records)!=1 or records[0]['name'].lower()!=agent['name'].lower(): raise Fail(403,'Token is scoped to a different device')
                    d=records[0]; c.execute('INSERT INTO devices VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,received=excluded.received,source=excluded.source',(d['name'],json.dumps(d),now,'agent'))
                    body={'ok':True}
                else:
                    cookies=SimpleCookie(); cookies.load(env.get('HTTP_COOKIE',''))
                    token=cookies['nexus_session'].value if 'nexus_session' in cookies else ''
                    session=c.execute('SELECT * FROM sessions WHERE token=? AND expires>?',(digest(token),now)).fetchone()
                    u=c.execute('SELECT * FROM users WHERE id=? AND active=1',(session['user_id'],)).fetchone() if session else None
                    if not u: raise Fail(401,'Sign in required')
                    if method=='POST' and (env.get('HTTP_ORIGIN')!=ORIGIN or not hmac.compare_digest(env.get('HTTP_X_CSRF_TOKEN',''),session['csrf'])): raise Fail(403,'Invalid CSRF token or origin')
                    def require(perm):
                        if not u['admin'] and perm not in json.loads(u['permissions']): raise Fail(403,'Permission denied: '+perm)
                    def admin():
                        if not u['admin']: raise Fail(403,'Administrator required')
                    if path=='/api/me' and method=='GET': body={'user':public_user(u),'csrf':session['csrf'],'permissions':PERMS}
                    elif path=='/api/logout' and method=='POST':
                        c.execute('DELETE FROM sessions WHERE token=?',(digest(token),)); headers.append(('Set-Cookie','nexus_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')); body={'ok':True}
                    elif path=='/api/password' and method=='POST':
                        if not password_ok(str(data.get('current','')),u['password']): raise Fail(403,'Current password incorrect')
                        pw=str(data.get('password',''))
                        if not 12<=len(pw)<=1024: raise Fail(400,'Password must have 12–1024 characters')
                        c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(pw),u['id'])); c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],));log(c,u['email'],'password.changed');body={'ok':True}
                    elif path=='/api/ad/settings' and method=='GET':
                        admin(); body=directory.public_settings(c)
                    elif path=='/api/ad/settings' and method=='POST':
                        admin(); body=directory.save_settings(c, DB, data); log(c,u['email'],'ad.settings.updated')
                    elif path=='/api/ad/test' and method=='POST':
                        admin()
                        try:
                            body=directory.test_connection(directory.load_settings(c),DB)
                        except directory.DirectoryError:
                            log(c,u['email'],'ad.connection.failed'); c.commit(); raise
                        log(c,u['email'],'ad.connection.tested')
                    elif path=='/api/ad/ous' and method=='GET':
                        require('directory.read'); body=directory.list_ous(directory.load_settings(c),DB)
                        log(c,u['email'],'ad.ous.read',len(body['ous']))
                    elif path=='/api/ad/users' and method=='GET':
                        require('directory.read'); args=parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True)
                        nested=args.get('nested',['1'])[0]
                        if nested not in ['0','1']: raise Fail(400,'nested must be 0 or 1')
                        body=directory.list_users(directory.load_settings(c),DB,args.get('ou',[''])[0],args.get('q',[''])[0],nested=='1')
                        log(c,u['email'],'ad.users.read',body['count'])
                    elif path=='/api/ad/computers' and method=='GET':
                        require('directory.read'); args=parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True)
                        nested=args.get('nested',['1'])[0]
                        if nested not in ['0','1']: raise Fail(400,'nested must be 0 or 1')
                        body=directory.list_computers(directory.load_settings(c),DB,args.get('ou',[''])[0],args.get('q',[''])[0],nested=='1')
                        readable=bool(u['admin'] or 'inventory.read' in json.loads(u['permissions']))
                        body['inventory_visible']=readable
                        if readable:
                            summaries=[inventory_summary(r) for r in c.execute('SELECT * FROM devices')]
                            by_name={str(d['name']).casefold():d for d in summaries}
                        for computer in body['computers']:
                            computer['inventory']=None
                            if readable:
                                names=[computer['name'],computer['account'].rstrip('$'),computer['dns_host']]
                                candidates=[by_name[n.casefold()] for n in names if n.casefold() in by_name]
                                matches=[d for d in candidates if directory.match_computer_device(computer,d)]
                                if matches: computer['inventory']=max(matches,key=lambda d:d['receivedAt'])
                        log(c,u['email'],'ad.computers.read',body['count'])
                    elif path=='/api/ad/user-devices' and method=='GET':
                        require('directory.read'); require('inventory.read')
                        args=parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True)
                        user=directory.get_user(directory.load_settings(c),DB,args.get('dn',[''])[0]); matched=[]
                        for row in c.execute('SELECT * FROM devices ORDER BY received DESC'):
                            d=inventory_summary(row); evidence=directory.match_user_device(user,d)
                            if evidence: matched.append({**d,'match_method':evidence})
                        body={'user':user,'devices':matched,'count':len(matched),
                              'basis':'Latest console user reported per device; not ownership, live sessions or full history.'}
                        log(c,u['email'],'ad.user-devices.read',len(matched))
                    elif path=='/api/device' and method=='GET':
                        require('inventory.read'); args=parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True)
                        row=c.execute('SELECT * FROM devices WHERE name=?',(args.get('name',[''])[0],)).fetchone()
                        if not row: raise Fail(404,'Inventory not found. Run the collector on this computer first.')
                        body=inventory_record(row)
                    elif path=='/api/devices' and method=='GET':
                        require('inventory.read'); body=[inventory_record(r) for r in c.execute('SELECT * FROM devices ORDER BY name')]
                    elif path=='/api/import' and method=='POST':
                        require('inventory.import'); records=valid_records(data)
                        for d in records: c.execute('INSERT INTO devices VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,received=excluded.received,source=excluded.source',(d['name'],json.dumps(d),now,'import'))
                        log(c,u['email'],'inventory.import',len(records));body={'count':len(records)}
                    elif path=='/api/export' and method=='GET':
                        require('inventory.export');require('inventory.read'); out=io.StringIO();w=csv.writer(out);fields=['name','domain','user','cpu','ram','ddr','storage','boot','uptime','collectedAt','os'];w.writerow(fields)
                        for r in c.execute('SELECT payload FROM devices ORDER BY name'):
                            d=json.loads(r[0]);row=[]
                            for k in fields:
                                v=str(d.get(k,''));row.append("'"+v if v.lstrip().startswith(('=','+','-','@')) else v)
                            w.writerow(row)
                        body=out.getvalue().encode('utf-8-sig');content_type='text/csv';headers.append(('Content-Disposition','attachment; filename="nexus-inventory.csv"'));log(c,u['email'],'inventory.export')
                    elif path=='/api/rdp' and method=='POST':
                        require('remote.rdp'); require('inventory.read'); name=str(data.get('name',''))
                        if not NAME.fullmatch(name) or not c.execute('SELECT 1 FROM devices WHERE name=?',(name,)).fetchone(): raise Fail(404,'Unknown device')
                        body={'content':f'full address:s:{name}\r\nprompt for credentials:i:1\r\nauthentication level:i:2\r\n'};log(c,u['email'],'remote.rdp.download',name)
                    elif path=='/api/users' and method=='GET': admin();body=[public_user(x) for x in c.execute('SELECT * FROM users ORDER BY email')]
                    elif path=='/api/users' and method=='POST':
                        admin();email=str(data.get('email','')).lower().strip();perms=data.get('permissions',[]);uid=data.get('id');is_admin=bool(data.get('admin',False));active=bool(data.get('active',True));pw=str(data.get('password',''))
                        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(email)>254: raise Fail(400,'Invalid email')
                        if not isinstance(perms,list) or any(p not in PERMS for p in perms): raise Fail(400,'Invalid permissions')
                        if pw and not 12<=len(pw)<=1024: raise Fail(400,'Password must have 12–1024 characters')
                        if uid:
                            old=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
                            if not old: raise Fail(404,'User not found')
                            if old['admin'] and old['active'] and not(is_admin and active) and c.execute('SELECT COUNT(*) FROM users WHERE admin=1 AND active=1').fetchone()[0]<=1: raise Fail(400,'Keep at least one active administrator')
                            c.execute('UPDATE users SET email=?,admin=?,permissions=?,active=? WHERE id=?',(email,is_admin,json.dumps(perms),active,uid))
                            if pw:c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(pw),uid))
                            c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
                        else:
                            if not pw:raise Fail(400,'Initial password required')
                            c.execute('INSERT INTO users(email,password,admin,permissions,active) VALUES(?,?,?,?,?)',(email,password_hash(pw),is_admin,json.dumps(perms),active))
                        log(c,u['email'],'user.updated',email);body={'ok':True}
                    elif path=='/api/agents' and method=='GET':
                        require('agents.manage');body=[dict(x) for x in c.execute('SELECT id,name,active FROM agents ORDER BY name')]
                    elif path=='/api/agents' and method=='POST':
                        require('agents.manage');name=str(data.get('name',''))
                        if not NAME.fullmatch(name):raise Fail(400,'Invalid device name')
                        if data.get('revoke'):
                            c.execute('UPDATE agents SET active=0 WHERE name=?',(name,));body={'ok':True};log(c,u['email'],'agent.revoked',name)
                        else:
                            token=secrets.token_urlsafe(32);c.execute('INSERT INTO agents(name,token) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET token=excluded.token,active=1',(name,digest(token)));body={'name':name,'token':token};log(c,u['email'],'agent.enrolled',name)
                    elif path=='/api/audit' and method=='GET':require('audit.read');body=[dict(x) for x in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')]
                    elif path in ['/collectors/collector.ps1','/collectors/collector-legacy.ps1'] and method=='GET':
                        require('agents.manage');body=(ROOT/path.lstrip('/')).read_bytes();content_type='text/plain';headers.append(('Content-Disposition','attachment; filename="'+Path(path).name+'"'))
                    else: raise Fail(404,'Not found')
    except directory.DirectoryError as ex: status=ex.status;body={'error':str(ex)}
    except Fail as ex: status=ex.status;body={'error':ex.message}
    except sqlite3.IntegrityError: status=409;body={'error':'Email already exists'}
    except Exception:
        __import__('traceback').print_exc();status=500;body={'error':'Internal server error'}
    payload=body if isinstance(body,bytes) else json.dumps(body,allow_nan=False).encode()
    from http import HTTPStatus
    headers += [('Content-Type',content_type),('Content-Length',str(len(payload)))]
    start_response(f'{status} {HTTPStatus(status).phrase}',headers);return [payload]

if __name__=='__main__':
    initialize()
    from wsgiref.simple_server import make_server
    make_server('127.0.0.1',8080,application).serve_forever()
