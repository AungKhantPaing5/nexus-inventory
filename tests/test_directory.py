import io
import json
import os
import ssl
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch, MagicMock

import ldap3
import app
import directory

BASE='DC=example,DC=local'
OU='OU=IT,'+BASE
CHILD='OU=Support,'+OU
CONFIG={'enabled':True,'host':'dc01.example.local','port':636,'tls_mode':'ldaps',
        'base_dn':BASE,'bind_user':'svc-nexus@example.local','password':'directory-fixture-only-password','ca_pem':''}


def mock_directory():
    conn=ldap3.Connection(ldap3.Server('mock',get_info=ldap3.NONE),client_strategy=ldap3.MOCK_SYNC,read_only=True)
    conn.strategy.add_entry(BASE,{'objectClass':['domain'],'dc':'example','distinguishedName':BASE})
    for dn,name in [(OU,'IT'),(CHILD,'Support'),('OU=HR,'+BASE,'HR')]:
        conn.strategy.add_entry(dn,{'objectClass':['organizationalUnit'],'ou':name,'name':name,'distinguishedName':dn})
    for dn,attrs in [
        ('CN=Alice,'+OU,{'displayName':'Alice Test','sAMAccountName':'alice','mail':'alice@example.local','userPrincipalName':'alice@example.local','department':'IT','userAccountControl':'512','memberOf':['CN=IT-Staff,'+BASE],'lastLogonTimestamp':'133485408000000000'}),
        ('CN=Bob,'+CHILD,{'displayName':'Bob Disabled','sAMAccountName':'bob','userAccountControl':'514'}),
        ('CN=Hnin,'+'OU=HR,'+BASE,{'displayName':'Hnin HR','sAMAccountName':'hnin','userAccountControl':'512'})]:
        conn.strategy.add_entry(dn,{'objectClass':['person','user'],'objectCategory':'person',**attrs})
    conn.bind()
    return conn


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.conn=mock_directory()
        self.patcher=patch('directory.open_directory',side_effect=lambda *args:nullcontext(self.conn))
        self.patcher.start()
    def tearDown(self):self.patcher.stop();self.conn.unbind()
    def test_ou_listing(self):
        data=directory.list_ous(CONFIG,'unused')
        self.assertEqual({x['name'] for x in data['ous']},{'IT','Support','HR'})
        self.assertFalse(data['truncated'])
    def test_nested_and_direct_users(self):
        direct=directory.list_users(CONFIG,'unused',OU,nested=False)
        nested=directory.list_users(CONFIG,'unused',OU,nested=True)
        self.assertEqual([u['username'] for u in direct['users']],['alice'])
        self.assertEqual({u['username'] for u in nested['users']},{'alice','bob'})
        self.assertTrue(next(u for u in nested['users'] if u['username']=='alice')['enabled'])
        self.assertFalse(next(u for u in nested['users'] if u['username']=='bob')['enabled'])
        self.assertEqual(direct['users'][0]['groups'],['CN=IT-Staff,'+BASE])
        self.assertTrue(direct['users'][0]['last_logon_replicated'].startswith('2024-'))
    def test_search_and_injection(self):
        self.assertEqual(directory.list_users(CONFIG,'unused',OU,'alice')['count'],1)
        # ldap3's mock re-parses decoded filter values and cannot represent literal
        # parentheses safely. Validate the real filter compiler at this boundary.
        payload='*)(|(objectClass=*))'
        with patch('directory.search_entries',return_value=([],False)) as search:
            self.assertEqual(directory.list_users(CONFIG,'unused',OU,payload)['count'],0)
            filter_text=search.call_args.args[2]
            from ldap3.operation.search import parse_filter
            parse_filter(filter_text,None,auto_escape=False,auto_encode=False,validator=None,check_names=False)
            self.assertNotIn(payload,filter_text)
            self.assertIn(r'\2a\29\28|\28objectClass=\2a\29\29',filter_text)
    def test_base_boundary_and_missing_ou(self):
        for dn in ['OU=IT,DC=outside,DC=local','OU=IT,DC=notexample,DC=local','OU=IT,DC=example,DC=local.evil']:
            with self.assertRaises(directory.DirectoryError):directory.list_users(CONFIG,'unused',dn)
        with self.assertRaises(directory.DirectoryError):directory.list_users(CONFIG,'unused','OU=Deleted,'+BASE)
        self.assertTrue(directory.within_base('OU=Child,OU=My\\,Team,'+BASE,'OU=My\\,Team,'+BASE))
    def test_real_paged_mock_search(self):
        for i in range(220):
            self.conn.strategy.add_entry('CN=Paged'+str(i)+','+OU,{'objectClass':['person','user'],'objectCategory':'person','sAMAccountName':'paged'+str(i),'displayName':'Paged '+str(i),'userAccountControl':'512'})
        data=directory.list_users(CONFIG,'unused',OU)
        self.assertEqual(data['count'],222);self.assertFalse(data['truncated'])
    def test_connection_base_validation(self):
        self.assertTrue(directory.test_connection(CONFIG,'unused')['ok'])
        with self.assertRaises(directory.DirectoryError):directory.test_connection({**CONFIG,'base_dn':'DC=missing,DC=local'},'unused')
    def test_cap_reports_truncation(self):
        rows,truncated=directory.search_entries(self.conn,BASE,'(objectClass=user)',['sAMAccountName'],limit=2)
        self.assertEqual(len(rows),2);self.assertTrue(truncated)


class DirectoryApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();app.DB=self.tmp.name+'/nexus.db';app.ORIGIN='https://inventory.test'
        os.environ['ADMIN_PASSWORD']='test-only-password-1234';app.initialize()
    def tearDown(self):self.tmp.cleanup()
    def call(self,path,data=None,cookie='',csrf=''):
        route,_,query=path.partition('?');raw=json.dumps(data).encode() if data is not None else b''
        env={'REQUEST_METHOD':'POST' if data is not None else 'GET','PATH_INFO':'/api/'+route,
             'QUERY_STRING':query,'wsgi.input':io.BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),
             'CONTENT_TYPE':'application/json','HTTP_COOKIE':cookie,'HTTP_X_CSRF_TOKEN':csrf,'HTTP_ORIGIN':app.ORIGIN}
        out={}
        def start(status,headers):out.update(status=int(status.split()[0]),headers=dict(headers))
        out['body']=json.loads(b''.join(app.application(env,start)));return out
    def login(self,email='itsupport@kmdcomputer.com',password='test-only-password-1234'):
        r=self.call('login',{'email':email,'password':password});self.assertEqual(r['status'],200,r)
        return r['headers']['Set-Cookie'].split(';')[0],r['body']['csrf']
    def test_encrypted_config_and_no_secret_in_response(self):
        cookie,csrf=self.login();r=self.call('ad/settings',CONFIG,cookie,csrf)
        self.assertEqual(r['status'],200,r);self.assertTrue(r['body']['password_set'])
        self.assertNotIn(CONFIG['password'],json.dumps(r))
        with app.connect() as c:
            stored=c.execute('SELECT payload FROM directory_settings').fetchone()[0]
            cfg=directory.load_settings(c)
        self.assertNotIn(CONFIG['password'],stored)
        self.assertEqual(directory.cipher(app.DB).decrypt(cfg['password_cipher'].encode()).decode(),CONFIG['password'])
        self.assertEqual(os.stat(directory.key_file(app.DB)).st_mode & 0o777,0o600)
        r=self.call('ad/settings',{'base_dn':OU},cookie,csrf);self.assertEqual(r['status'],200)
        r=self.call('ad/settings',{'host':'other.example.local'},cookie,csrf);self.assertEqual(r['status'],400)
        r=self.call('ad/settings',{'tls_mode':'plain','password':'x'},cookie,csrf);self.assertEqual(r['status'],400)
        r=self.call('ad/settings',{'ca_pem':'bad certificate','password':'x'},cookie,csrf);self.assertEqual(r['status'],400)
    def test_permission_and_csrf_enforcement(self):
        cookie,csrf=self.login()
        self.assertEqual(self.call('ad/settings',CONFIG,cookie)['status'],403)
        self.call('users',{'email':'ad-viewer@example.local','password':'viewer-test-password','permissions':['directory.read']},cookie,csrf)
        vc,vs=self.login('ad-viewer@example.local','viewer-test-password')
        self.assertEqual(self.call('ad/settings',cookie=vc)['status'],403)
        self.assertEqual(self.call('ad/settings',CONFIG,vc,vs)['status'],403)
        self.assertEqual(self.call('ad/test',{},vc,vs)['status'],403)
        self.assertEqual(self.call('ad/ous',cookie=vc)['status'],409)
        self.call('users',{'email':'no-ad@example.local','password':'viewer-test-password','permissions':['inventory.read']},cookie,csrf)
        nc,ns=self.login('no-ad@example.local','viewer-test-password')
        self.assertEqual(self.call('ad/ous',cookie=nc)['status'],403)
        self.assertEqual(self.call('ad/users',cookie=nc)['status'],403)
    def test_api_reads_mock_ad_and_audits(self):
        cookie,csrf=self.login();self.call('ad/settings',CONFIG,cookie,csrf)
        conn=mock_directory()
        with patch('directory.open_directory',side_effect=lambda *args:nullcontext(conn)):
            self.assertEqual(self.call('ad/test',{},cookie,csrf)['status'],200)
            self.assertEqual(len(self.call('ad/ous',cookie=cookie)['body']['ous']),3)
            from urllib.parse import urlencode
            r=self.call('ad/users?'+urlencode({'ou':OU,'nested':'0','q':'alice'}),cookie=cookie)
            self.assertEqual(r['status'],200,r);self.assertEqual(r['body']['count'],1)
        conn.unbind()
        rows=self.call('audit',cookie=cookie)['body'];self.assertTrue(any(a['action']=='ad.users.read' for a in rows))


class TransportTests(unittest.TestCase):
    def test_certificate_validation_and_no_bind_before_starttls(self):
        fake=MagicMock();fake.closed=False;fake.start_tls.return_value=False
        with patch('directory.cipher') as cp,patch('directory.ldap3.Server') as server,patch('directory.ldap3.Connection',return_value=fake):
            cp.return_value.decrypt.return_value=CONFIG['password'].encode()
            with self.assertRaises(directory.DirectoryError):
                with directory.open_directory({**CONFIG,'tls_mode':'starttls','password_cipher':'fixture'},'unused'):pass
            fake.bind.assert_not_called();fake.unbind.assert_called_once()
            tls=server.call_args.kwargs['tls'];self.assertEqual(tls.validate,ssl.CERT_REQUIRED)
            self.assertEqual(tls.sni,CONFIG['host'])
            self.assertFalse(server.call_args.kwargs['use_ssl'])
    def test_ldaps_readonly_no_referrals(self):
        fake=MagicMock();fake.closed=False;fake.bind.return_value=True
        with patch('directory.cipher') as cp,patch('directory.ldap3.Server') as server,patch('directory.ldap3.Connection',return_value=fake) as connection:
            cp.return_value.decrypt.return_value=CONFIG['password'].encode()
            with directory.open_directory({**CONFIG,'password_cipher':'fixture'},'unused'):pass
            self.assertTrue(server.call_args.kwargs['use_ssl'])
            self.assertTrue(connection.call_args.kwargs['read_only']);self.assertFalse(connection.call_args.kwargs['auto_referrals'])
            fake.bind.assert_called_once();fake.start_tls.assert_not_called()

if __name__=='__main__':unittest.main()
