import io
import unittest
import zipfile
import xml.etree.ElementTree as ET
import reporting

class ReportingTest(unittest.TestCase):
    def test_identity_counts_are_unique_and_do_not_guess(self):
        users=[{'sid':'S-1-5-21-1-2-3-101','dn':'CN=One,DC=kmd,DC=com','username':'one','domain':{'dns':'kmd.com','netbios':'KMD0'}}]
        devices=[{'name':'PC1','user':'KMD0\\one','userSid':'S-1-5-21-1-2-3-101'}, {'name':'PC2','user':'KMD0\\one','userSid':'S-1-5-21-1-2-3-101'}, {'name':'PC1','user':'PC1\\local'}, {'name':'PC2','user':'PC2\\local'}, {'name':'PC3','user':'other\\one'}, {'name':'PC4','user':''}]
        r=reporting.user_counts(users,devices)
        self.assertEqual((r['ad_users'],r['local_users'],r['unknown_devices']),(1,2,2))

    def test_styled_workbook_and_untrusted_strings(self):
        devices=[{'name':'PC2','user':'=HYPERLINK("bad")','ram':16,'receivedAt':1,'status':'Recent','memoryModules':[{'capacityGB':8},{'capacityGB':8}]}, {'name':'PC1','ram':2,'receivedAt':1,'status':'Stale'}]
        with zipfile.ZipFile(io.BytesIO(reporting.workbook(devices,'HR & Finance'))) as z:
            for n in z.namelist(): ET.fromstring(z.read(n))
            xml=z.read('xl/worksheets/sheet1.xml').decode()
            self.assertLess(xml.index('PC2'),xml.index('PC1'))
            self.assertIn('HR &amp; Finance',xml)
            self.assertIn('state="frozen"',xml)
            self.assertIn('8 GB + 8 GB',xml)
            self.assertNotIn('<f>',xml)
            self.assertIn('t="inlineStr"',xml)
            self.assertIn('showRowStripes="1"',z.read('xl/tables/table1.xml').decode())
        with zipfile.ZipFile(io.BytesIO(reporting.workbook([]))) as z:
            for n in z.namelist(): ET.fromstring(z.read(n))
            self.assertNotIn('xl/tables/table1.xml',z.namelist())
