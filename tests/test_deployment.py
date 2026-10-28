import io
import json
import zipfile
import hashlib
import unittest
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import app
import directory
import test_directory as fixtures


def root_ca():
    key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Nexus test root')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
          .not_valid_after(datetime.now(timezone.utc)+timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class DeploymentTests(unittest.TestCase):
    login=fixtures.DirectoryApiTests.login
    def setUp(self):
        fixtures.DirectoryApiTests.setUp(self)
        self.cookie,self.csrf=self.login()
        self.ca=root_ca()
        self.computers=[{'name':n,'account':n+'$','sid':'S-1-5-21-1-2-3-'+str(i+1001),
                         'dn':'CN='+n+','+fixtures.OU,'enabled':True,'os':'Windows 11 Pro'}
                        for i,n in enumerate(['PC-01','PC-02'])]
        self.patcher=patch('directory.list_computers',side_effect=self.ad);self.patcher.start()
    def tearDown(self):self.patcher.stop();fixtures.DirectoryApiTests.tearDown(self)
    def ad(self,*args):return {'computers':self.computers,'ou':fixtures.BASE,'count':len(self.computers),'truncated':False}
    def call(self,path,data=None,cookie='',csrf=''):
        raw=json.dumps(data).encode() if data is not None else b''
        env={'REQUEST_METHOD':'POST' if data is not None else 'GET','PATH_INFO':'/api/'+path,
             'wsgi.input':io.BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json',
             'HTTP_COOKIE':cookie,'HTTP_X_CSRF_TOKEN':csrf,'HTTP_ORIGIN':app.ORIGIN}
        out={}
        def start(s,h):out.update(status=int(s.split()[0]),headers=dict(h))
        out['raw']=b''.join(app.application(env,start))
        out['body']=json.loads(out['raw']) if 'application/json' in out['headers']['Content-Type'] else None
        return out
    def prepare(self,**kw):
        return self.call('deployment/prepare',{'share_host':'dc01.example.local','ca_pem':self.ca,'nested':True,**kw},self.cookie,self.csrf)
    def test_bundle_contains_unique_configs_and_generated_token_works(self):
        r=self.prepare();self.assertEqual(r['status'],200,r);self.assertEqual(r['body']['count'],2)
        batch=r['body']['id'];download=self.call('deployment/download',{'id':batch},self.cookie,self.csrf)
        self.assertEqual(download['status'],200);self.assertEqual(download['headers']['Content-Type'],'application/zip')
        with zipfile.ZipFile(io.BytesIO(download['raw'])) as z:
            manifest=json.loads(z.read('manifest.json'));self.assertEqual(len(manifest['computers']),2)
            import xml.etree.ElementTree as ET
            a=ET.fromstring(z.read('private-configs/PC-01/endpoint.xml'))
            b=ET.fromstring(z.read('private-configs/PC-02/endpoint.xml'))
            token=a.findtext('Token');self.assertNotEqual(token,b.findtext('Token'))
            self.assertEqual(a.findtext('ComputerName'),'PC-01')
            public=b''.join(z.read(n) for n in z.namelist() if n.startswith('public/'))
            self.assertNotIn(token.encode(),public)
            self.assertNotIn(b.findtext('Token').encode(),public)
            self.assertEqual(manifest['computers'][0]['sid'],self.computers[0]['sid'])
        with app.connect() as c:
            stored=c.execute('SELECT payload FROM deployment_batches WHERE id=?',(batch,)).fetchone()[0]
            self.assertNotIn(b'PK\x03\x04',stored);self.assertNotIn(token.encode(),stored)
            self.assertEqual(c.execute('SELECT token FROM agents WHERE name=?',('PC-01',)).fetchone()[0],hashlib.sha256(token.encode()).hexdigest())
        raw=json.dumps({'name':'PC-01','apps':[]}).encode();env={'REQUEST_METHOD':'POST','PATH_INFO':'/api/checkin','wsgi.input':io.BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','HTTP_AUTHORIZATION':'Bearer '+token}
        status=[];body=b''.join(app.application(env,lambda s,h:status.append(s)));self.assertTrue(status[0].startswith('200'),body)
        self.assertEqual(self.call('deployment/download',{'id':batch},self.cookie,self.csrf)['raw'],download['raw'])
    def test_existing_and_revoked_agents_unchanged_and_resumable(self):
        with app.connect() as c:
            c.execute('INSERT INTO agents(name,token,active) VALUES(?,?,0)',('PC-01','old-hash'))
        first=self.prepare();self.assertEqual(first['body']['count'],1)
        second=self.prepare();self.assertEqual(second['body']['count'],0)
        with app.connect() as c:
            old=c.execute('SELECT token,active FROM agents WHERE name=?',('PC-01',)).fetchone()
            self.assertEqual(tuple(old),('old-hash',0))
        batches=self.call('deployment/batches',cookie=self.cookie)['body'];self.assertEqual(len(batches),2)
        self.assertEqual(self.call('deployment/download',{'id':first['body']['id']},self.cookie,self.csrf)['status'],200)
    def test_partial_or_invalid_scope_ca_does_not_enroll(self):
        with patch('directory.list_computers',return_value={'truncated':True,'computers':self.computers}):
            self.assertEqual(self.prepare()['status'],400)
        self.assertEqual(self.prepare(ca_pem='sha256 Fingerprint=abc')['status'],400)
        self.assertEqual(self.prepare(share_host='server/../../bad')['status'],400)
        with app.connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM agents').fetchone()[0],0)
    def test_scope_skip_rules_and_no_traversal(self):
        self.computers += [dict(self.computers[0],name='../Bad',account='../Bad$'),
                           dict(self.computers[0],name='SERVER',account='SERVER$',os='Windows Server 2019'),
                           dict(self.computers[0],name='DISABLED',account='DISABLED$',enabled=False),
                           dict(self.computers[0],name='NOSID',account='NOSID$',sid=''),
                           dict(self.computers[0],name='CON',account='CON$')]
        r=self.prepare();self.assertEqual(r['body']['count'],2);self.assertEqual(r['body']['skipped_count'],5)
        r=self.prepare(include_servers=True);self.assertEqual(r['body']['count'],1)
    def test_permissions_and_csrf(self):
        self.call('users',{'email':'agent-manager@example.local','password':'manager-test-password','permissions':['agents.manage','directory.read']},self.cookie,self.csrf)
        mc,ms=self.login('agent-manager@example.local','manager-test-password')
        self.assertEqual(self.call('deployment/batches',cookie=mc)['status'],403)
        self.assertEqual(self.call('deployment/prepare',{'share_host':'x','ca_pem':self.ca},mc,ms)['status'],403)
        self.assertEqual(self.call('deployment/download',{'id':'a'*32},mc,ms)['status'],403)
        self.assertEqual(self.call('deployment/prepare',{},self.cookie)['status'],403)
        self.assertEqual(self.call('deployment/batches')['status'],401)
    def test_failure_building_bundle_rolls_back_enrollment(self):
        with patch('deployment.zipfile.ZipFile',side_effect=directory.DirectoryError('Packaging unavailable',503)):
            self.assertEqual(self.prepare()['status'],503)
        with app.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM agents').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM deployment_batches').fetchone()[0],0)
