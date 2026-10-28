#requires -version 2.0
<# Run by one computer-side GPO task as SYSTEM. No enrollment/admin secrets here. #>
param([Parameter(Mandatory=$true)][string]$PublicShare)
$ErrorActionPreference='Stop'
$local=Join-Path $env:ProgramFiles 'NexusAgent'
function Read-SafeXml([string]$Path){
 $settings=New-Object System.Xml.XmlReaderSettings
 $settings.ProhibitDtd=$true
 $settings.XmlResolver=$null
 $reader=[System.Xml.XmlReader]::Create($Path,$settings)
 try {$doc=New-Object System.Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader);return $doc}finally{$reader.Close()}
}
function Sha256([byte[]]$Bytes){
 $hash=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
}
function No-Reparse([string]$Path){
 if(Test-Path -LiteralPath $Path){if(((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'A managed path is a reparse point. Administrator review is required.'}}
}
function Lock-Directory([string]$Path){
 No-Reparse $Path
 if(-not(Test-Path -LiteralPath $Path)){[IO.Directory]::CreateDirectory($Path)|Out-Null}
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 $sys=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
 $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
 $acl.SetOwner($sys)
 foreach($sid in @($sys,$admins)){
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 [IO.Directory]::SetAccessControl($Path,$acl)
}
function Lock-File([string]$Path){
 No-Reparse $Path
 $acl=New-Object Security.AccessControl.FileSecurity
 $acl.SetAccessRuleProtection($true,$false)
 $sys=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
 $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
 $acl.SetOwner($sys)
 foreach($sid in @($sys,$admins)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))}
 [IO.File]::SetAccessControl($Path,$acl)
}
try{
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Run this bootstrap through the computer GPO task as SYSTEM.'}
 if($PublicShare -notmatch '^\\\\[A-Za-z0-9.-]+\\NexusAgent\$$'){throw 'Invalid public deployment share.'}
 $settings=Read-SafeXml (Join-Path $PublicShare 'rollout.xml')
 $origin=[string]$settings.NexusRollout.ServerUrl
 $configShare=[string]$settings.NexusRollout.ConfigShare
 if(-not $origin.StartsWith('https://') -or $configShare -notmatch '^\\\\[A-Za-z0-9.-]+\\NexusEnroll\$$'){throw 'Invalid rollout settings.'}
 Lock-Directory $local
 foreach($name in @('collector.ps1','nexus-root.crt','endpoint.xml','inventory.json','run.log')){No-Reparse (Join-Path $local $name)}
 # Source scripts and their hashes are read from an administrator-writable share.
 $collectorBytes=[IO.File]::ReadAllBytes((Join-Path $PublicShare 'collector.ps1'))
 if((Sha256 $collectorBytes) -ne [string]$settings.NexusRollout.CollectorSHA256){throw 'Collector hash does not match the rollout settings.'}
 $caBytes=[IO.File]::ReadAllBytes((Join-Path $PublicShare 'nexus-root.crt'))
 $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$caBytes)
 if((Sha256 $cert.RawData) -ne [string]$settings.NexusRollout.RootSHA256){throw 'Nexus root certificate hash does not match.'}
 [IO.File]::WriteAllBytes((Join-Path $local 'collector.ps1'),$collectorBytes)
 [IO.File]::WriteAllBytes((Join-Path $local 'nexus-root.crt'),$caBytes)
 Lock-File (Join-Path $local 'collector.ps1');Lock-File (Join-Path $local 'nexus-root.crt')
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
 try{$store.Open('ReadWrite');$store.Add($cert)}finally{$store.Close()}
 $endpoint=Join-Path $local 'endpoint.xml'
 $remote=Join-Path (Join-Path $configShare $env:COMPUTERNAME) 'endpoint.xml'
 if(Test-Path -LiteralPath $remote){
  $doc=Read-SafeXml $remote
 }elseif(Test-Path -LiteralPath $endpoint){
  $doc=Read-SafeXml $endpoint
 }else{
  # Preserve an already-enrolled endpoint's old local token without rotation.
  $legacy=Join-Path $env:ProgramData 'Nexus'
  No-Reparse $legacy
  $legacy=Join-Path $legacy 'endpoint.xml';No-Reparse $legacy
  if(-not(Test-Path -LiteralPath $legacy)){throw 'No per-computer config is available yet. Prepare/stage the next domain rollout bundle.'}
  $doc=Read-SafeXml $legacy
 }
 if([string]$doc.Nexus.ServerUrl -ne $origin -or ([string]$doc.Nexus.Token).Length -lt 32){throw 'Endpoint config does not match this Nexus server.'}
 $expected=[string]$doc.Nexus.ComputerName
 if($expected -ne '' -and $expected -ne $env:COMPUTERNAME){throw 'Config is for a different computer.'}
 $doc.Save($endpoint);Lock-File $endpoint
 & (Join-Path $local 'collector.ps1') -ConfigPath $endpoint -OutputPath (Join-Path $local 'inventory.json') | Out-Null
 Lock-File (Join-Path $local 'inventory.json')
 [IO.File]::WriteAllText((Join-Path $local 'run.log'),((Get-Date).ToString('o')+' Check-in accepted.'))
 Lock-File (Join-Path $local 'run.log')
 exit 0
}catch{
 # Never include tokens, XML contents or a credential-bearing command line in logs.
 $reason=$_.Exception.Message
 if(Test-Path -LiteralPath $local){
  try{No-Reparse (Join-Path $local 'run.log');[IO.File]::WriteAllText((Join-Path $local 'run.log'),((Get-Date).ToString('o')+' '+$reason));Lock-File (Join-Path $local 'run.log')}catch{}
 }
 Write-Error $reason
 exit 1
}
