import io, json, os, tempfile, unittest
import app

class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();app.DB=cls.tmp.name+'/test.db';app.ORIGIN='https://inventory.test'
        os.environ['ADMIN_PASSWORD']='test-only-password-1234';app.initialize()
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def call(self,path,data=None,cookie='',csrf='',bearer='',origin=True):
        env={'REQUEST_METHOD':'POST' if data is not None else 'GET','PATH_INFO':'/api/'+path,'wsgi.input':io.BytesIO(),'HTTP_COOKIE':cookie}
        if data is not None:
            raw=json.dumps(data).encode();env.update({'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','wsgi.input':io.BytesIO(raw),'HTTP_X_CSRF_TOKEN':csrf})
        if origin:env['HTTP_ORIGIN']=app.ORIGIN
        if bearer:env['HTTP_AUTHORIZATION']='Bearer '+bearer
        result={}
        def start(status,headers):result.update(status=int(status.split()[0]),headers=dict(headers))
        result['raw']=b''.join(app.application(env,start))
        try:result['body']=json.loads(result['raw'])
        except ValueError:result['body']=None
        return result
    def login(self,email='itsupport@kmdcomputer.com',password='test-only-password-1234'):
        r=self.call('login',{'email':email,'password':password});self.assertEqual(r['status'],200,r)
        return r['headers']['Set-Cookie'].split(';')[0],r['body']['csrf']
    def test_anonymous_and_csrf(self):
        self.assertEqual(self.call('devices')['status'],401)
        cookie,csrf=self.login()
        self.assertEqual(self.call('import',[],cookie= cookie)['status'],403)
        self.assertEqual(self.call('import',[],cookie=cookie,csrf=csrf,origin=False)['status'],403)
        self.assertEqual(self.call('login',{'email':'x','password':'x'},origin=False)['status'],403)
    def test_permissions_and_persistence(self):
        cookie,csrf=self.login()
        r=self.call('users',{'email':'viewer@example.com','password':'viewer-test-password','permissions':['inventory.read']},cookie,csrf)
        self.assertEqual(r['status'],200,r)
        vc,vs=self.login('viewer@example.com','viewer-test-password')
        self.assertEqual(self.call('users',cookie=vc)['status'],403)
        self.assertEqual(self.call('import',{'name':'PC-VIEW','apps':[]},vc,vs)['status'],403)
        self.assertEqual(self.call('agents',{'name':'PC-VIEW'},vc,vs)['status'],403)
        self.assertEqual(self.call('export',cookie=vc)['status'],403)
        self.assertEqual(self.call('rdp',{'name':'PC-VIEW'},vc,vs)['status'],403)
        self.assertEqual(self.call('devices',cookie=vc)['status'],200)
        self.assertEqual(self.call('import',{'name':'REAL-PC','apps':[{'name':'Office'}],'ram':16},cookie,csrf)['status'],200)
        app.initialize()
        records=self.call('devices',cookie=cookie)['body'];self.assertTrue(any(d['name']=='REAL-PC' and d['status']=='Snapshot' for d in records))
    def test_scoped_agent_token(self):
        cookie,csrf=self.login();token=self.call('agents',{'name':'AGENT-01'},cookie,csrf)['body']['token']
        self.assertEqual(self.call('checkin',{'name':'AGENT-02','apps':[]},bearer=token)['status'],403)
        self.assertEqual(self.call('checkin',{'name':'AGENT-01','apps':[]},bearer=token)['status'],200)
        records=self.call('devices',cookie=cookie)['body'];self.assertTrue(any(d['name']=='AGENT-01' and d['status']=='Recent' for d in records))
        self.assertEqual(self.call('agents',{'name':'AGENT-01','revoke':True},cookie,csrf)['status'],200)
        self.assertEqual(self.call('checkin',{'name':'AGENT-01','apps':[]},bearer=token)['status'],401)
    def test_admin_protection_and_audit(self):
        cookie,csrf=self.login();u=self.call('me',cookie=cookie)['body']['user']
        r=self.call('users',{'id':u['id'],'email':u['email'],'admin':False,'active':False,'permissions':[]},cookie,csrf)
        self.assertEqual(r['status'],400)
        rows=self.call('audit',cookie=cookie)['body'];self.assertGreater(len(rows),0)
    def test_validation_and_rdp(self):
        cookie,csrf=self.login()
        for d in [{'name':'bad\r\nname','apps':[]},{'name':'PC','apps':'invalid'},{'name':'PC','ram':float('nan'),'apps':[]}]:
            self.assertEqual(self.call('import',d,cookie,csrf)['status'],400)
        self.call('import',{'name':'RDP-PC','apps':[]},cookie,csrf)
        r=self.call('rdp',{'name':'RDP-PC'},cookie,csrf);self.assertEqual(r['status'],200);self.assertIn('authentication level:i:2',r['body']['content'])
        self.assertEqual(self.call('rdp',{'name':'bad\naddress'},cookie,csrf)['status'],404)
    def test_session_revocation(self):
        cookie,csrf=self.login()
        self.call('users',{'email':'revoke@example.com','password':'revoke-test-password','permissions':['inventory.read']},cookie,csrf)
        vc,vs=self.login('revoke@example.com','revoke-test-password')
        user=next(x for x in self.call('users',cookie=cookie)['body'] if x['email']=='revoke@example.com')
        self.assertEqual(self.call('users',{**user,'active':False},cookie,csrf)['status'],200)
        self.assertEqual(self.call('me',cookie=vc)['status'],401)
    def test_password_hash_and_token_storage(self):
        with app.connect() as c:
            u=c.execute('SELECT password FROM users LIMIT 1').fetchone()[0]
        self.assertNotEqual(u,os.environ['ADMIN_PASSWORD']);self.assertTrue(app.password_ok(os.environ['ADMIN_PASSWORD'],u))
    def test_memory_modules_and_power_queue(self):
        cookie,csrf=self.login()
        token=self.call('agents',{'name':'POWER-PC'},cookie,csrf)['body']['token']
        payload={'name':'POWER-PC','type':'Desktop','apps':[],'powerAgent':True,'memoryModules':[{'capacityGB':2,'slot':'DIMM1'},{'capacityGB':2,'slot':'DIMM2'}]}
        self.assertEqual(self.call('checkin',payload,bearer=token)['status'],200)
        device=next(d for d in self.call('devices',cookie=cookie)['body'] if d['name']=='POWER-PC')
        self.assertEqual([m['capacityGB'] for m in device['memoryModules']],[2,2])
        request={'name':'POWER-PC','action':'restart','confirm':'POWER-PC'}
        self.assertEqual(self.call('power',request,cookie=cookie)['status'],403)
        self.assertEqual(self.call('power',{**request,'confirm':'other'},cookie,csrf)['status'],400)
        self.assertEqual(self.call('power',{**request,'action':'shell'},cookie,csrf)['status'],400)
        self.assertEqual(self.call('power',request,cookie,csrf)['status'],200)
        self.assertEqual(self.call('power',request,cookie,csrf)['status'],409)
        first=self.call('checkin',payload,bearer=token)['body']
        self.assertEqual(first['command']['action'],'restart')
        self.assertNotIn('command',self.call('checkin',payload,bearer=token)['body'])
        self.call('power',request,cookie,csrf)
        with app.connect() as c:c.execute("UPDATE power_commands SET expires=0 WHERE name='POWER-PC'")
        self.assertNotIn('command',self.call('checkin',payload,bearer=token)['body'])
        self.call('checkin',{**payload,'type':'Server'},bearer=token)
        self.assertEqual(self.call('power',request,cookie,csrf)['status'],403)
        self.call('users',{'email':'power-viewer@example.com','password':'viewer-test-password','permissions':['inventory.read']},cookie,csrf)
        vc,vs=self.login('power-viewer@example.com','viewer-test-password')
        self.assertEqual(self.call('power',request,vc,vs)['status'],403)

    def test_six_character_passwords(self):
        cookie,csrf=self.login()
        base={'email':'six@example.com','permissions':['inventory.read']}
        self.assertEqual(self.call('users',{**base,'password':'12345'},cookie,csrf)['status'],400)
        self.assertEqual(self.call('users',{**base,'password':'123456'},cookie,csrf)['status'],200)
        vc,vs=self.login('six@example.com','123456')
        self.assertEqual(self.call('password',{'current':'123456','password':'abcde'},vc,vs)['status'],400)
        self.assertEqual(self.call('password',{'current':'123456','password':'abcdef'},vc,vs)['status'],200)
        self.login('six@example.com','abcdef')

    def test_user_ou_device_filter(self):
        from unittest.mock import patch
        cookie,csrf=self.login()
        self.call('import',[{'name':'OU-MATCH','userSid':'S-1-5-21-1-2-3-1000','apps':[]}, {'name':'OU-OTHER','userSid':'S-1-5-21-1-2-3-1001','apps':[]}],cookie,csrf)
        result={'users':[{'sid':'S-1-5-21-1-2-3-1000'}],'truncated':False,'ou':'OU=HR,DC=kmd,DC=com'}
        with patch('app.directory.load_settings',return_value={}), patch('app.directory.list_users',return_value=result):
            r=self.call('ad/ou-devices',cookie=cookie)
            self.assertEqual(r['status'],200,r)
            self.assertEqual(r['body']['names'],['OU-MATCH'])
            result['truncated']=True
            self.assertEqual(self.call('ad/ou-devices',cookie=cookie)['status'],409)
        self.call('users',{'email':'ou-viewer@example.com','password':'123456','permissions':['inventory.read']},cookie,csrf)
        vc,vs=self.login('ou-viewer@example.com','123456')
        self.assertEqual(self.call('ad/ou-devices',cookie=vc)['status'],403)

    def test_rate_limit(self):
        for i in range(10):self.assertEqual(self.call('login',{'email':'blocked@example.com','password':'wrong'})['status'],401)
        self.assertEqual(self.call('login',{'email':'blocked@example.com','password':'wrong'})['status'],429)

if __name__=='__main__':unittest.main()
