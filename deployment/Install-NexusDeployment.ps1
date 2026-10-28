#requires -version 3.0
<# Run on the AD/file server as an elevated authorized deployment administrator.
Stages public assets and machine-SID protected tokens. Does not edit/link a GPO.
#>
param([string]$PublishPath=(Join-Path $env:ProgramFiles 'NexusDeployment'))
$ErrorActionPreference='Stop'
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module SmbShare -ErrorAction Stop
$bundle=Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest=Get-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Use an elevated administrator PowerShell.'}
$cs=Get-WmiObject Win32_ComputerSystem
$actual=($cs.DNSHostName+'.'+$cs.Domain).ToLowerInvariant()
if($actual -ne ([string]$manifest.share_host).ToLowerInvariant()){throw ('This bundle must be staged on '+$manifest.share_host+', not '+$actual)}
if($PublishPath -notmatch '^[A-Za-z]:\\' -or $PublishPath.Contains('..')){throw 'Choose a dedicated local NTFS directory.'}
$PublishPath=[IO.Path]::GetFullPath($PublishPath).TrimEnd('\')
$sys=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$authenticated=New-Object Security.Principal.SecurityIdentifier('S-1-5-11')
function No-Reparse([string]$Path){
 if(Test-Path -LiteralPath $Path){if(((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse point is not allowed: '+$Path)}}
}
function Secure-Directory([string]$Path,[string]$ReaderSID='', [switch]$TraverseOnly){
 No-Reparse $Path
 if(-not(Test-Path -LiteralPath $Path)){New-Item -ItemType Directory -Path $Path | Out-Null}
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins)
 foreach($sid in @($sys,$admins)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
 if($ReaderSID){
  $sid=New-Object Security.Principal.SecurityIdentifier($ReaderSID)
  if($TraverseOnly){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Traverse','None','None','Allow')}
  else{$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')}
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $Path -AclObject $acl
}
function Secure-File([string]$Path,[string]$ReaderSID=''){
 No-Reparse $Path
 $acl=New-Object Security.AccessControl.FileSecurity
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins)
 foreach($sid in @($sys,$admins)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))}
 if($ReaderSID){$sid=New-Object Security.Principal.SecurityIdentifier($ReaderSID);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'ReadAndExecute','Allow')))}
 Set-Acl -LiteralPath $Path -AclObject $acl
}
# Validate the whole scope before publishing any credentials.
foreach($computer in $manifest.computers){
 if([string]$computer.name -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$'){throw 'Invalid manifest computer name.'}
 $ad=Get-ADComputer -Identity ([string]$computer.name) -Properties SID
 if($ad.SID.Value -ne [string]$computer.sid){throw ('AD account changed for '+$computer.name+'. Prepare a new rollout after administrator review.')}
 $source=Join-Path (Join-Path (Join-Path $bundle 'private-configs') $computer.name) 'endpoint.xml'
 if(-not(Test-Path -LiteralPath $source)){throw ('Config missing for '+$computer.name)}
}
$marker=Join-Path $PublishPath '.nexus-rollout'
No-Reparse $PublishPath;No-Reparse $marker
if((Test-Path -LiteralPath $PublishPath) -and -not(Test-Path -LiteralPath $marker) -and @(Get-ChildItem -LiteralPath $PublishPath -Force).Count){throw 'PublishPath must be empty or a previously managed Nexus deployment folder.'}
if(Test-Path -LiteralPath $marker){
 $old=Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
 if($old.server_url -ne $manifest.server_url -or $old.share_host -ne $manifest.share_host){throw 'Existing deployment belongs to a different host or Nexus origin.'}
}
Secure-Directory $PublishPath $authenticated.Value -TraverseOnly
$public=Join-Path $PublishPath 'public';$private=Join-Path $PublishPath 'private-configs'
Secure-Directory $public $authenticated.Value
Secure-Directory $private $authenticated.Value -TraverseOnly
foreach($file in @('Start-Nexus.ps1','collector.ps1','nexus-root.crt','rollout.xml')){
 $dest=Join-Path $public $file;No-Reparse $dest
 Copy-Item -LiteralPath (Join-Path (Join-Path $bundle 'public') $file) -Destination $dest -Force
 Secure-File $dest $authenticated.Value
}
foreach($computer in $manifest.computers){
 $folder=Join-Path $private $computer.name
 Secure-Directory $folder ([string]$computer.sid)
 $dest=Join-Path $folder 'endpoint.xml';No-Reparse $dest
 Copy-Item -LiteralPath (Join-Path (Join-Path (Join-Path $bundle 'private-configs') $computer.name) 'endpoint.xml') -Destination $dest -Force
 Secure-File $dest ([string]$computer.sid)
}
# Incremental bundles preserve configs previously published for other PCs.
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $marker -Encoding UTF8
Secure-File $marker
$adminName=$admins.Translate([Security.Principal.NTAccount]).Value
$readName=$authenticated.Translate([Security.Principal.NTAccount]).Value
foreach($item in @(@{Name='NexusAgent$';Path=$public},@{Name='NexusEnroll$';Path=$private})){
 $share=Get-SmbShare -Name $item.Name -ErrorAction SilentlyContinue
 if($share){
  if($share.Path.TrimEnd('\') -ne $item.Path.TrimEnd('\')){throw ('Share '+$item.Name+' already points elsewhere. No existing share was changed.')}
  foreach($ace in (Get-SmbShareAccess -Name $item.Name)){
   if($ace.AccessControlType -ne 'Allow' -or ($ace.AccountName -ne $adminName -and -not($ace.AccountName -eq $readName -and $ace.AccessRight -eq 'Read'))){throw ('Review unexpected share permission on '+$item.Name)}
  }
 }else{
  New-SmbShare -Name $item.Name -Path $item.Path -FullAccess $adminName -ReadAccess $readName -FolderEnumerationMode AccessBased -CachingMode None | Out-Null
 }
}
Write-Host ('Staged '+@($manifest.computers).Count+' new computers; previous configs preserved.')
Write-Host 'Create ONE computer GPO scheduled task; details are in README.md.'
Write-Host 'Run as NT AUTHORITY\SYSTEM; repeat every 10 minutes and add an At startup trigger.'
Write-Host 'Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
Write-Host ('Arguments: -NoProfile -NonInteractive -File "\\'+$manifest.share_host+'\NexusAgent$\Start-Nexus.ps1" -PublicShare "\\'+$manifest.share_host+'\NexusAgent$"')
Write-Host 'Review script signing/execution policy. No Bypass policy is used.'
Write-Host 'Keep the downloaded ZIP and extracted private-configs restricted to administrators.'
