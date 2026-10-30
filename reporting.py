"""Inventory identity summary and dependency-free, styled OOXML report export."""
import io
import math
import re
import zipfile
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape
import directory


def user_counts(users, devices):
    ad, local = set(), set()
    classified = []
    for d in devices:
        matched = next((u for u in users if directory.match_user_device(u, d)), None)
        kind, identity = 'unknown', ''
        if matched:
            kind = 'ad'
            identity = str(matched.get('sid') or matched.get('dn') or matched.get('upn') or '').casefold()
            ad.add(identity)
        else:
            observed = str(d.get('user', '')).strip()
            prefix, sep, name = observed.partition('\\')
            if sep and name and prefix.casefold() in (str(d.get('name','')).casefold(), '.'):
                kind = 'local'
                identity = (str(d.get('name',''))+'\\'+(directory.sid_string(d.get('userSid','')) or name)).casefold()
                local.add(identity)
        # Opaque grouping keys let the UI count distinct users within its current filters.
        key = __import__('hashlib').sha256(identity.encode()).hexdigest() if identity else ''
        classified.append({'name':d['name'],'kind':kind,'user_key':key})
    return {'ad_users':len(ad),'local_users':len(local),
            'unknown_devices':sum(x['kind']=='unknown' for x in classified),
            'classification':classified,
            'basis':'Distinct users in latest inventory snapshots; local accounts are scoped to each PC.'}


def workbook(devices, scope='All user OUs'):
    """Inline-string cells prevent spreadsheet formula injection. No external links/macros."""
    ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    def xml(s):
        return escape(re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(s)))
    def cell(col,row,value,style=4,numeric=False):
        ref=f'{chr(65+col)}{row}'
        if numeric: return f'<c r="{ref}" s="{style}"><v>{float(value)}</v></c>'
        return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{xml(value)}</t></is></c>'
    now=datetime.now(timezone(timedelta(hours=6,minutes=30))).strftime('%d %b %Y, %H:%M MMT')
    recent=sum(d.get('status')=='Recent' for d in devices)
    rows=[f'<row r="1" ht="34" customHeight="1">{cell(0,1,"NSD AD Client Inventory",1)}</row>',
          f'<row r="2" ht="26" customHeight="1">{cell(0,2,"Device inventory report · "+now,2)}</row>',
          f'<row r="3" ht="28" customHeight="1">{cell(0,3,f"{len(devices)} devices | {recent} recent check-ins | User OU: {scope}",2)}</row>']
    headers=['Device name','Status','Assigned user','Processor','Memory (GB)','Storage','Uptime','Operating system','Domain','IP address','Last check-in (MMT)','RAM modules']
    rows.append('<row r="5" ht="30" customHeight="1">'+''.join(cell(i,5,h,3) for i,h in enumerate(headers))+'</row>')
    for row,d in enumerate(devices,6):
        seen=datetime.fromtimestamp(d['receivedAt'],timezone(timedelta(hours=6,minutes=30))).strftime('%Y-%m-%d %H:%M:%S')
        modules=' + '.join(str(m['capacityGB']).removesuffix('.0')+' GB' for m in d.get('memoryModules',[])) or 'Not reported'
        values=[d.get('name',''),d.get('status',''),d.get('user',''),d.get('cpu',''),d.get('ram',0),d.get('storage',''),d.get('uptime',''),d.get('os',''),d.get('domain',''),d.get('ip',''),seen,modules]
        cells=[]
        for i,value in enumerate(values):
            style=7 if i==4 else (5 if value=='Recent' else 6) if i==1 else 4
            cells.append(cell(i,row,value,style,i==4))
        height=min(409,max(42,14*max(math.ceil(len(str(v))/max(8,w-3)) for v,w in zip(values,[24,17,29,48,17,60,22,34,24,27,25,30]))+12))
        rows.append(f'<row r="{row}" ht="{height}" customHeight="1">'+''.join(cells)+'</row>')
    last=max(5,len(devices)+5)
    widths=[24,17,29,48,17,60,22,34,24,27,25,30]
    cols=''.join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i,w in enumerate(widths,1))
    table_parts='<tableParts count="1"><tablePart r:id="rId1"/></tableParts>' if devices else ''
    sheet=f'''<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><dimension ref="A1:L{last}"/><sheetViews><sheetView workbookViewId="0" showGridLines="0"><pane ySplit="5" topLeftCell="A6" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A6" sqref="A6"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="20"/><cols>{cols}</cols><sheetData>{''.join(rows)}</sheetData><autoFilter ref="A5:L{last}"/><mergeCells count="3"><mergeCell ref="A1:L1"/><mergeCell ref="A2:L2"/><mergeCell ref="A3:L3"/></mergeCells><printOptions horizontalCentered="1"/><pageMargins left="0.25" right="0.25" top="0.4" bottom="0.4" header="0.2" footer="0.2"/><pageSetup paperSize="9" orientation="landscape" fitToWidth="1" fitToHeight="0"/>{table_parts}</worksheet>'''
    styles=f'''<?xml version="1.0"?><styleSheet xmlns="{ns}"><fonts count="4"><font><sz val="11"/><name val="Calibri"/><color rgb="FF17212B"/></font><font><b/><sz val="20"/><name val="Calibri"/><color rgb="FFFFFFFF"/></font><font><sz val="11"/><name val="Calibri"/><color rgb="FF475569"/></font><font><b/><sz val="11"/><name val="Calibri"/><color rgb="FFFFFFFF"/></font></fonts><fills count="6"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF123B2A"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF1F5F9"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE1F4E7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left/><right/><top/><bottom style="thin"><color rgb="FFE2E8F0"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="8"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="2" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="center" horizontal="right"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/></styleSheet>'''
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        types=f'''<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>{'<Override PartName="/xl/tables/table1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>' if devices else ''}</Types>'''
        z.writestr('[Content_Types].xml',types)
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml',f'<workbook xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets><sheet name="Device Inventory" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm.Print_Titles" localSheetId="0">\'Device Inventory\'!$1:$5</definedName></definedNames></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr('xl/styles.xml',styles)
        z.writestr('xl/worksheets/sheet1.xml',sheet)
        if devices:
            z.writestr('xl/worksheets/_rels/sheet1.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" Target="../tables/table1.xml"/></Relationships>')
            columns=''.join(f'<tableColumn id="{i}" name="{xml(h)}"/>' for i,h in enumerate(headers,1))
            z.writestr('xl/tables/table1.xml',f'<table xmlns="{ns}" id="1" name="InventoryTable" displayName="InventoryTable" ref="A5:L{last}" totalsRowShown="0"><autoFilter ref="A5:L{last}"/><tableColumns count="12">{columns}</tableColumns><tableStyleInfo name="TableStyleMedium2" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/></table>')
    return out.getvalue()
