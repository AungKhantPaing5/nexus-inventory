#requires -version 2.0
<# Nexus inventory collector. Read-only local WMI + uninstall registry inventory.
Only allowlisted shutdown/restart actions; no remote shell or certificate bypass.
Without ConfigPath writes an offline JSON snapshot. Use 64-bit Windows PowerShell.
#>
param([string]$ConfigPath='', [string]$OutputPath='')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Web.Extensions
$serializer=New-Object System.Web.Script.Serialization.JavaScriptSerializer
$serializer.MaxJsonLength=8388608
function Query-Wmi([string]$ClassName) { Get-WmiObject -Class $ClassName -ErrorAction Stop }
$cs=Query-Wmi 'Win32_ComputerSystem'
$os=Query-Wmi 'Win32_OperatingSystem'
$cpu=@(Query-Wmi 'Win32_Processor')
$memory=@(Query-Wmi 'Win32_PhysicalMemory')
$enclosure=@(Query-Wmi 'Win32_SystemEnclosure')
$bios=Query-Wmi 'Win32_BIOS'
$types=@{20='DDR';21='DDR2';24='DDR3';26='DDR4';34='DDR5'}
$ddr=@($memory | ForEach-Object {
 $t=[int]$_.SMBIOSMemoryType
 if($t -eq 0){$t=[int]$_.MemoryType}
 if($types.ContainsKey($t)){$types[$t]}else{'Unknown'}
} | Select-Object -Unique)
$memoryModules=@($memory | Where-Object { [double]$_.Capacity -gt 0 } | ForEach-Object {
 $t=[int]$_.SMBIOSMemoryType
 if($t -eq 0){$t=[int]$_.MemoryType}
 $kind='Unknown';if($types.ContainsKey($t)){$kind=$types[$t]}
 @{capacityGB=[math]::Round([double]$_.Capacity/1GB,2);slot=[string]$_.DeviceLocator;ddr=$kind;speed=[string]$_.ConfiguredClockSpeed;manufacturer=[string]$_.Manufacturer;partNumber=([string]$_.PartNumber).Trim()}
})
$diskRows=@()
if(Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue){
 try {$diskRows=@(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { '{0} GB {1} - {2}' -f [math]::Round($_.Size/1GB),$_.MediaType,$_.FriendlyName })}catch{}
}
if($diskRows.Count -eq 0){$diskRows=@(Query-Wmi 'Win32_DiskDrive' | ForEach-Object { '{0} GB (HDD/SSD unknown) - {1}' -f [math]::Round($_.Size/1GB),$_.Model })}
$apps=@()
foreach($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')){
 $apps+=@(Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | ForEach-Object { @{name=[string]$_.DisplayName;version=[string]$_.DisplayVersion} })
}
$ip=@(Query-Wmi 'Win32_NetworkAdapterConfiguration' | Where-Object {$_.IPEnabled} | ForEach-Object {$_.IPAddress} | Where-Object {$_ -match '^\d+\.\d+\.\d+\.\d+$'}) -join ', '
$boot=[System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
$uptime=(Get-Date)-$boot
$portable=$false
foreach($e in $enclosure){foreach($t in $e.ChassisTypes){if(@(8,9,10,14,30,31,32) -contains [int]$t){$portable=$true}}}
$deviceType='Desktop'
if($portable){$deviceType='Laptop'}elseif([int]$os.ProductType -ne 1){$deviceType='Server'}
# Resolve the observed user's SID when possible; failure leaves name-based matching.
$userSid=''
if($cs.UserName){
 try {
  $account=New-Object System.Security.Principal.NTAccount -ArgumentList ([string]$cs.UserName)
  $userSid=$account.Translate([System.Security.Principal.SecurityIdentifier]).Value
 }catch{}
}
$record=@{
 memoryModules=$memoryModules;powerAgent=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18")
 name=$env:COMPUTERNAME;type=$deviceType;user=[string]$cs.UserName;userSid=$userSid
 cpu=(@($cpu | ForEach-Object {$_.Name}) -join ' / ');ram=[math]::Round($cs.TotalPhysicalMemory/1GB,1);ddr=($ddr -join ' / ')
 storage=($diskRows -join ' + ');uptime=('{0}d {1}h {2}m' -f $uptime.Days,$uptime.Hours,$uptime.Minutes)
 model=[string]$cs.Model;domain=[string]$cs.Domain;ip=$ip;boot=$boot.ToUniversalTime().ToString('o')
 collectedAt=(Get-Date).ToUniversalTime().ToString('o');os=[string]$os.Caption;serial=[string]$bios.SerialNumber;apps=$apps
}
$json=$serializer.Serialize($record)
if($OutputPath -eq ''){$OutputPath=Join-Path (Get-Location) ($env:COMPUTERNAME+'-inventory.json')}
[IO.File]::WriteAllText($OutputPath,$json,(New-Object Text.UTF8Encoding($false)))
Write-Host ('Inventory saved: '+$OutputPath)
if($ConfigPath -ne ''){
 $xml=New-Object System.Xml.XmlDocument
 $xml.XmlResolver=$null
 $xml.Load($ConfigPath)
 $url=[string]$xml.Nexus.ServerUrl
 $token=[string]$xml.Nexus.Token
 if(-not $url.StartsWith('https://')){throw 'Use HTTPS with a certificate trusted by this computer.'}
 if($token.Length -lt 32){throw 'Missing device enrollment token.'}
 # TLS 1.2 when installed .NET/OS supports it. No certificate validation is disabled.
 try {[Net.ServicePointManager]::SecurityProtocol=[Enum]::Parse([Net.SecurityProtocolType],'Tls12')}catch{throw 'TLS 1.2 unavailable: use offline import or install required OS/.NET updates.'}
 $client=New-Object Net.WebClient
 $client.Headers.Add('Content-Type','application/json; charset=utf-8')
 $client.Headers.Add('Authorization','Bearer '+$token)
 $client.Encoding=[Text.Encoding]::UTF8
 try {
  $response=$serializer.DeserializeObject($client.UploadString($url.TrimEnd('/')+'/api/checkin','POST',$json))
  Write-Host 'Check-in accepted.'
  if($record.powerAgent -and $response.ContainsKey('command')){
   $action=[string]$response['command']['action']
   $switch=''
   if($action -eq 'shutdown'){$switch='/s'}elseif($action -eq 'restart'){$switch='/r'}else{throw 'Unsupported power action'}
   # No /f and zero timeout: do not implicitly force-close unsaved applications.
   & "$env:SystemRoot\System32\shutdown.exe" $switch /t 0 /d p:4:1 /c 'Nexus administrator requested maintenance'
   if($LASTEXITCODE -ne 0){throw 'Windows rejected the power request'}
  }
 }finally{$client.Dispose()}
}
