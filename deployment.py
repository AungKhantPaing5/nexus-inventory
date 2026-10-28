"""Administrator-only, resumable bulk enrollment bundles for AD/GPO rollout."""
import hashlib
import io
import json
import re
import secrets
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import directory


def prepare(c, db, root, origin, values, actor):
    if not isinstance(values, dict):
        raise directory.DirectoryError('Invalid deployment request.')
    cfg=directory.load_settings(c)
    host=values.get('share_host','').strip()
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host) or len(host)>253:
        raise directory.DirectoryError('Enter the DNS hostname of the Windows server that will host the rollout shares.')
    if not origin.startswith('https://'):
        raise directory.DirectoryError('Automatic rollout requires a configured HTTPS APP_ORIGIN.')
    nested=values.get('nested',True); servers=values.get('include_servers',False)
    if not isinstance(nested,bool) or not isinstance(servers,bool):
        raise directory.DirectoryError('Invalid scope options.')
    ca=values.get('ca_pem','')
    if not isinstance(ca,str) or len(ca)>100000:
        raise directory.DirectoryError('Upload the Nexus gateway root CA as PEM.')
    try:
        certs=x509.load_pem_x509_certificates(ca.encode())
        if len(certs)!=1:raise ValueError()
        cert=certs[0]
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:raise ValueError()
        if cert.issuer!=cert.subject:raise ValueError()
        now=datetime.now(timezone.utc)
        if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc:raise ValueError()
        der=cert.public_bytes(serialization.Encoding.DER)
        ca=cert.public_bytes(serialization.Encoding.PEM).decode()
    except (ValueError,x509.ExtensionNotFound):
        raise directory.DirectoryError('Use the valid self-issued Nexus/Caddy root CA certificate, not a server certificate, AD CA bundle or fingerprint text.') from None
    data=directory.list_computers(cfg,db,values.get('ou',''),'',nested)
    if data['truncated']:
        raise directory.DirectoryError('AD result is incomplete. Select a narrower OU before preparing rollout.')
    if len(data['computers'])>5000:
        raise directory.DirectoryError('Prepare at most 5,000 computers per bundle; select a narrower OU.')
    existing={r['name'].casefold() for r in c.execute('SELECT name FROM agents')}
    included=[];skipped=[];configs={};manifest_names=set()
    for computer in data['computers']:
        name=computer.get('account','').rstrip('$') or computer['name'];sid=computer.get('sid','')
        reason=''
        if computer['enabled'] is not True:reason='Disabled or unknown account state'
        elif not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}',name) or name.upper() in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}:reason='Unsupported Windows computer name'
        elif name.casefold() in existing:reason='Already enrolled or revoked; existing token is unchanged'
        elif name.casefold() in manifest_names:reason='Duplicate computer name'
        elif computer.get('os') and 'windows' not in computer['os'].casefold():reason='Not a Windows computer'
        elif not servers and 'server' in computer.get('os','').casefold():reason='Server excluded by scope option'
        elif not directory.sid_string(sid):reason='Computer SID missing; check AD read access'
        if reason:
            skipped.append({'name':name,'reason':reason});continue
        token=secrets.token_urlsafe(32)
        inserted=c.execute('INSERT INTO agents(name,token) VALUES(?,?) ON CONFLICT(name) DO NOTHING',
                           (name,hashlib.sha256(token.encode()).hexdigest()))
        if not inserted.rowcount:
            skipped.append({'name':name,'reason':'Enrolled concurrently; token unchanged'});continue
        manifest_names.add(name.casefold())
        doc=ET.Element('Nexus');ET.SubElement(doc,'ServerUrl').text=origin
        ET.SubElement(doc,'Token').text=token;ET.SubElement(doc,'ComputerName').text=name
        configs[name]=ET.tostring(doc,encoding='utf-8',xml_declaration=True)
        included.append({'name':name,'sid':sid,'dn':computer['dn']})
    batch=secrets.token_hex(16)
    collector=(root/'collectors/collector-legacy.ps1').read_bytes()
    settings=ET.Element('NexusRollout')
    for k,v in [('ServerUrl',origin),('ConfigShare',f'\\\\{host}\\NexusEnroll$'),
                ('CollectorSHA256',hashlib.sha256(collector).hexdigest()),
                ('RootSHA256',hashlib.sha256(der).hexdigest())]:ET.SubElement(settings,k).text=v
    manifest={'version':1,'batch_id':batch,'generated_at':datetime.now(timezone.utc).isoformat(),
              'share_host':host,'server_url':origin,'scope_dn':data['ou'],'include_nested':nested,
              'computers':included,'skipped':skipped}
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json',json.dumps(manifest,indent=2))
        z.writestr('public/collector.ps1',collector)
        z.writestr('public/nexus-root.crt',ca)
        z.writestr('public/rollout.xml',ET.tostring(settings,encoding='utf-8',xml_declaration=True))
        z.write(root/'deployment/Start-Nexus.ps1','public/Start-Nexus.ps1')
        z.write(root/'deployment/Install-NexusDeployment.ps1','Install-NexusDeployment.ps1')
        z.write(root/'docs/AUTOMATIC_ROLLOUT.md','README.md')
        for name,config in configs.items():z.writestr('private-configs/'+name+'/endpoint.xml',config)
    encrypted=directory.cipher(db,create=True).encrypt(buf.getvalue())
    c.execute('INSERT INTO deployment_batches(id,created,actor,count,payload) VALUES(?,?,?,?,?)',
              (batch,time.time(),actor,len(included),encrypted))
    return {'id':batch,'count':len(included),'skipped_count':len(skipped),'skipped':skipped[:30],
            'message':'Bundle prepared. Download it, stage it on the AD/file server, then configure one computer GPO. Existing tokens were not changed.'}


def download(c,db,batch):
    if not re.fullmatch(r'[a-f0-9]{32}',str(batch)):
        raise directory.DirectoryError('Invalid deployment ID.')
    row=c.execute('SELECT payload FROM deployment_batches WHERE id=?',(batch,)).fetchone()
    if not row:raise directory.DirectoryError('Deployment bundle not found.',404)
    from cryptography.fernet import InvalidToken
    try:return directory.cipher(db).decrypt(row['payload'])
    except InvalidToken:
        raise directory.DirectoryError('Cannot decrypt deployment bundle. Restore the matching AD credential key.',503) from None
