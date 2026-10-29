#requires -version 3.0
# Run once as administrator on the AD/file server. Keeps device tokens and CA unchanged.
param([string]$PublicPath='C:\Program Files\NexusDeployment\public')
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'collector.ps1'
$settingsPath=Join-Path $PublicPath 'rollout.xml'
$destination=Join-Path $PublicPath 'collector.ps1'
if(-not(Test-Path -LiteralPath $settingsPath)){throw 'Existing rollout.xml not found'}
foreach($path in @($PublicPath,$settingsPath,$destination)){
 if(((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path refused'}
}
$doc=New-Object Xml.XmlDocument
$doc.XmlResolver=$null
$doc.Load($settingsPath)
if(-not $doc.NexusRollout.CollectorSHA256){throw 'Invalid rollout settings'}
$bytes=[IO.File]::ReadAllBytes($source)
$hash=[Security.Cryptography.SHA256]::Create()
try{$pin=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
Copy-Item -LiteralPath $settingsPath -Destination ($settingsPath+'.'+$stamp+'.bak')
Copy-Item -LiteralPath $destination -Destination ($destination+'.'+$stamp+'.bak')
[IO.File]::WriteAllBytes($destination,$bytes)
Unblock-File -LiteralPath $destination
$doc.NexusRollout.CollectorSHA256=$pin
$doc.Save($settingsPath)
Write-Host 'Collector and SHA256 pin updated. Existing tokens and certificate preserved.'
Write-Host 'Endpoints receive the collector at their next Nexus task run.'
