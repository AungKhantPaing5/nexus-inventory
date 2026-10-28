import unittest
from contextlib import nullcontext
from unittest.mock import patch
from urllib.parse import urlencode
import ldap3
import app
import directory
from test_directory import mock_directory, CONFIG, BASE, OU, CHILD
import test_directory as fixtures


def add_computers(conn):
    for name,dn,dns,flags in [('PC-01',OU,'pc-01.example.local','4096'),
                              ('PC-02',CHILD,'pc-02.example.local','4098'),
                              ('PC-03','CN=Computers,'+BASE,'pc-03.example.local','4096')]:
        conn.strategy.add_entry('CN='+name+','+dn,{
            'objectClass':['computer'],'name':name,'sAMAccountName':name+'$',
            'dNSHostName':dns,'operatingSystem':'Windows 11 Pro',
            'operatingSystemVersion':'10.0','userAccountControl':flags,
            'managedBy':'CN=Alice,'+OU})


class ComputerDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.conn=mock_directory();add_computers(self.conn)
        self.patcher=patch('directory.open_directory',side_effect=lambda *args:nullcontext(self.conn));self.patcher.start()
    def tearDown(self):self.patcher.stop();self.conn.unbind()
    def test_direct_nested_and_default_container(self):
        d=directory.list_computers(CONFIG,'unused',OU,nested=False)
        self.assertEqual([x['name'] for x in d['computers']],['PC-01'])
        d=directory.list_computers(CONFIG,'unused',OU)
        self.assertEqual({x['name'] for x in d['computers']},{'PC-01','PC-02'})
        self.assertFalse(next(x for x in d['computers'] if x['name']=='PC-02')['enabled'])
        d=directory.list_computers(CONFIG,'unused')
        self.assertEqual(d['count'],3)
        self.assertEqual(directory.list_computers(CONFIG,'unused',query='pc-03')['count'],1)
    def test_computer_paging(self):
        for i in range(205):
            self.conn.strategy.add_entry('CN=Bulk'+str(i)+','+OU,{'objectClass':['computer'],'name':'Bulk'+str(i),'sAMAccountName':'Bulk'+str(i)+'$'})
        d=directory.list_computers(CONFIG,'unused');self.assertEqual(d['count'],208);self.assertFalse(d['truncated'])
    def test_computer_scope_and_escaping(self):
        with self.assertRaises(directory.DirectoryError):directory.list_computers(CONFIG,'unused','OU=X,DC=other,DC=local')
        with self.assertRaises(directory.DirectoryError):directory.list_computers(CONFIG,'unused','OU=Deleted,'+BASE)
        with patch('directory.search_entries',return_value=([],False)) as s:
            directory.list_computers(CONFIG,'unused',query='*)(objectClass=*)')
            self.assertNotIn('*)(objectClass=*)',s.call_args.args[2])
    def test_resolve_user_and_domain_discovery(self):
        # Configuration read failure is allowed; DNS identity still comes from DC RDNs.
        u=directory.get_user(CONFIG,'unused','CN=Alice,'+OU)
        self.assertEqual(u['username'],'alice');self.assertEqual(u['domain']['dns'],'example.local')
        with self.assertRaises(directory.DirectoryError):directory.get_user(CONFIG,'unused','CN=PC-01,'+OU)
        with self.assertRaises(directory.DirectoryError):directory.get_user(CONFIG,'unused','CN=Alice,DC=other,DC=local')
    def test_netbios_from_crossref_not_dns_label(self):
        responses=[[{'type':'searchResEntry','attributes':{'configurationNamingContext':['CN=Configuration,'+BASE]}}], [{'type':'searchResEntry','attributes':{'nETBIOSName':['CORP']}}]]
        class Connection:
            def search(self,*args,**kwargs):self.response=responses.pop(0)
        ident=directory.domain_identity(Connection(),OU)
        self.assertEqual(ident,{'dns':'example.local','netbios':'CORP'})


class IdentityMatchingTests(unittest.TestCase):
    def setUp(self):
        self.u={'username':'alice','upn':'alice@people.example','sid':'S-1-5-21-1-2-3-1001',
                'domain':{'dns':'example.local','netbios':'CORP'}}
    def test_qualified_name_upn_sid_and_conflict(self):
        for observed,expected in [('CORP\\ALICE','Domain-qualified username'),('example.local\\alice','Domain-qualified username'),('ALICE@people.example','UPN'),('OTHER\\alice',''),('PC-01\\alice',''),('alice',''),('','')]:
            self.assertEqual(directory.match_user_device(self.u,{'user':observed}),expected)
        self.assertEqual(directory.match_user_device(self.u,{'user':'renamed','userSid':self.u['sid']}),'SID')
        self.assertEqual(directory.match_user_device(self.u,{'user':'CORP\\alice','userSid':'S-1-5-21-9-9-9-1001'}),'')
        u={**self.u,'domain':{'dns':'example.local','netbios':''}}
        self.assertEqual(directory.match_user_device(u,{'user':'EXAMPLE\\alice'}),'')
    def test_binary_sid(self):
        raw=bytes([1,5])+int(5).to_bytes(6,'big')+b''.join(n.to_bytes(4,'little') for n in [21,1,2,3,1001])
        self.assertEqual(directory.sid_string(raw),self.u['sid'])
        self.assertEqual(directory.sid_string(raw[:-1]),'')
        self.assertEqual(directory.entry_sid({'attributes':{'objectSid':['\\x01formatted']},'raw_attributes':{'objectSid':[raw]}}),self.u['sid'])
    def test_computer_domain_boundary(self):
        c={'dn':'CN=PC-01,'+OU,'name':'PC-01','account':'PC-01$','dns_host':'pc-01.example.local'}
        self.assertTrue(directory.match_computer_device(c,{'name':'pc-01','domain':'EXAMPLE.LOCAL'}))
        self.assertTrue(directory.match_computer_device(c,{'name':'pc-01.example.local','domain':'example.local'}))
        self.assertFalse(directory.match_computer_device(c,{'name':'PC-01','domain':'other.local'}))
        self.assertFalse(directory.match_computer_device(c,{'name':'PC-01','domain':'WORKGROUP'}))
        self.assertFalse(directory.match_computer_device(c,{'name':'PC-02','domain':'example.local'}))


class ComputerApiTests(unittest.TestCase):
    call=fixtures.DirectoryApiTests.call
    login=fixtures.DirectoryApiTests.login
    def setUp(self):
        fixtures.DirectoryApiTests.setUp(self)
        self.conn=mock_directory();add_computers(self.conn)
        self.patcher=patch('directory.open_directory',side_effect=lambda *args:nullcontext(self.conn));self.patcher.start()
        self.cookie,self.csrf=self.login();self.call('ad/settings',CONFIG,self.cookie,self.csrf)
    def tearDown(self):
        self.patcher.stop();self.conn.unbind();fixtures.DirectoryApiTests.tearDown(self)
    def import_record(self,name,domain,user='alice@example.local'):
        r=self.call('import',{'name':name,'domain':domain,'user':user,'apps':[{'name':'Office'}],'ram':16},self.cookie,self.csrf)
        self.assertEqual(r['status'],200,r)
    def test_merge_inventory_without_crossdomain_collision(self):
        self.import_record('PC-01','example.local');self.import_record('PC-02','other.local')
        r=self.call('ad/computers',cookie=self.cookie);self.assertEqual(r['status'],200,r)
        linked={c['name']:c for c in r['body']['computers']}
        self.assertEqual(linked['PC-01']['inventory']['ram'],16)
        self.assertIsNone(linked['PC-02']['inventory']);self.assertIsNone(linked['PC-03']['inventory'])
        self.assertNotIn('apps',linked['PC-01']['inventory'])
        d=self.call('device?name=PC-01',cookie=self.cookie);self.assertEqual(d['body']['apps'],[{'name':'Office','version':''}])
    def test_user_links_latest_snapshot_only_and_not_arbitrary_identity(self):
        self.import_record('PC-01','example.local');self.import_record('PC-02','example.local','LOCAL\\alice')
        route='ad/user-devices?'+urlencode({'dn':'CN=Alice,'+OU})
        r=self.call(route,cookie=self.cookie);self.assertEqual(r['status'],200,r);self.assertEqual([d['name'] for d in r['body']['devices']],['PC-01'])
        self.import_record('PC-01','example.local','example.local\\bob')
        self.assertEqual(self.call(route,cookie=self.cookie)['body']['count'],0)
        self.assertEqual(self.call('ad/user-devices?'+urlencode({'dn':'CN=Alice,DC=outside,DC=local'}),cookie=self.cookie)['status'],403)
    def test_inventory_permission_not_leaked_by_directory(self):
        self.import_record('PC-01','example.local')
        self.call('users',{'email':'dir-only@example.local','password':'test-viewer-password','permissions':['directory.read']},self.cookie,self.csrf)
        vc,vs=self.login('dir-only@example.local','test-viewer-password')
        r=self.call('ad/computers',cookie=vc);self.assertEqual(r['status'],200);self.assertFalse(r['body']['inventory_visible'])
        self.assertTrue(all(x['inventory'] is None for x in r['body']['computers']))
        self.assertEqual(self.call('ad/user-devices?'+urlencode({'dn':'CN=Alice,'+OU}),cookie=vc)['status'],403)
        self.assertEqual(self.call('device?name=PC-01',cookie=vc)['status'],403)
        self.call('users',{'email':'inv-only@example.local','password':'test-viewer-password','permissions':['inventory.read']},self.cookie,self.csrf)
        ic,is_=self.login('inv-only@example.local','test-viewer-password')
        self.assertEqual(self.call('ad/computers',cookie=ic)['status'],403)
        self.assertEqual(self.call('ad/user-devices?'+urlencode({'dn':'CN=Alice,'+OU}),cookie=ic)['status'],403)
