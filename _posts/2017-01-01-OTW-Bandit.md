---
layout: post
title: OverTheWire Bandit
date: 2017-01-01
tags: [OverTheWire]
---

# Level 0

```bash
ssh -p 2220 bandit0@bandit.labs.overthewire.org
```

```bash
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

# Level 1

>   The password for the next level is stored in a file called - located in the home directory

```bash
ssh -p 2220 bandit1@bandit.labs.overthewire.org
```

```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat < -
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

# Level 2

>   The password for the next level is stored in a file called spaces in this filename located in the home directory

```bash
ssh -p 2220 bandit2@bandit.labs.overthewire.org
```

```bash
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat < spaces\ in\ this\ filename
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

# Level 3

>   The password for the next level is stored in a hidden file in the inhere directory.

```bash
ssh -p 2220 bandit3@bandit.labs.overthewire.org
```

```bash
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ ls
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 May  7  2020 .
drwxr-xr-x 3 root    root    4096 May  7  2020 ..
-rw-r----- 1 bandit4 bandit3   33 May  7  2020 .hidden
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

# Level 4

>   The password for the next level is stored in the only human-readable file in the inhere directory.

```bash
ssh -p 2220 bandit4@bandit.labs.overthewire.org
```

```bash
bandit4@bandit:~$ ls
inhere
bandit4@bandit:~$ cd inhere/
bandit4@bandit:~/inhere$ ls
-file00  -file02  -file04  -file06  -file08
-file01  -file03  -file05  -file07  -file09
bandit4@bandit:~/inhere$ for x in {0..9}; do file ./-file0$x; done
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

# Level 5

>   The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:
>
>   -   human-readable
>   -   1033 bytes in size
>   -   not executable
>

```bash
ssh -p 2220 bandit5@bandit.labs.overthewire.org
```

```bash
bandit5@bandit:~/inhere$ find -type f -size 1033c ! -executable
./maybehere07/.file2
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

# Level 6

>   The password for the next level is stored somewhere on the server and has all of the following properties:
>
>   -   owned by user bandit7
>   -   owned by group bandit6
>   -   33 bytes in size
>

```bash
ssh -p 2220 bandit6@bandit.labs.overthewire.org
```

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

# Level 7

>   The password for the next level is stored in the file data.txt next to the word millionth

```bash
ssh -p 2220 bandit7@bandit.labs.overthewire.org
```

```bash
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ cat data.txt | grep millionth
millionth	cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

# Level 8

>   The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

```bash
ssh -p 2220 bandit8@bandit.labs.overthewire.org
```

```bash
bandit8@bandit:~$ ls
data.txt
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

# Level 9

>   The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

```bash
ssh -p 2220 bandit9@bandit.labs.overthewire.org
```

```bash
bandit9@bandit:~$ ls
data.txt
bandit9@bandit:~$ cat data.txt | strings | grep ===
========== the*2i"4
========== password
Z)========== is
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```

# Level 10

>   The password for the next level is stored in the file data.txt, which contains base64 encoded data

```bash
ssh -p 2220 bandit10@bandit.labs.overthewire.org
```

```bash
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

# Level 11

>   The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

```bash
ssh -p 2220 bandit11@bandit.labs.overthewire.org
```

```bash
sudo apt-get install hxtools -y
echo "Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh" | rot13
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

# Level 12

>   The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed.

```bash
ssh -p 2220 bandit12@bandit.labs.overthewire.org
```

```bash
bandit12@bandit:/tmp/shiro$ xxd -r data.txt > something
bandit12@bandit:/tmp/shiro$ file something
something: gzip compressed data, was "data2.bin", from Unix
bandit12@bandit:/tmp/shiro$ gunzip something
gzip: something: unknown suffix -- ignored
bandit12@bandit:/tmp/shiro$ mv something something.gz
bandit12@bandit:/tmp/shiro$ gunzip something.gz
bandit12@bandit:/tmp/shiro$ ls
data.txt  something
bandit12@bandit:/tmp/shiro$ file something
something: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/shiro$ bunzip2 something
bunzip2: Can't guess original name for something -- using something.out
bandit12@bandit:/tmp/shiro$ ls
data.txt  something.out
bandit12@bandit:/tmp/shiro$ file something.out
something.out: gzip compressed data, was "data4.bin", from Unix
bandit12@bandit:/tmp/shiro$ mv something.out something.gz
bandit12@bandit:/tmp/shiro$ gunzip something.gz
bandit12@bandit:/tmp/shiro$ ls
data.txt  something
bandit12@bandit:/tmp/shiro$ file something
something: POSIX tar archive (GNU)
bandit12@bandit:/tmp/shiro$ tar x something
tar: Refusing to read archive contents from terminal (missing -f option?)
tar: Error is not recoverable: exiting now
bandit12@bandit:/tmp/shiro$ tar xf something
bandit12@bandit:/tmp/shiro$ ls
data5.bin  data.txt  something
bandit12@bandit:/tmp/shiro$ file data5.bin
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/shiro$ tar xvf data5.bin
data6.bin
bandit12@bandit:/tmp/shiro$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/shiro$ bunzip2 data6.bin
bunzip2: Can't guess original name for data6.bin -- using data6.bin.out
bandit12@bandit:/tmp/shiro$ ls
data5.bin  data6.bin.out  data.txt  something
bandit12@bandit:/tmp/shiro$ file data6.bin.out
data6.bin.out: POSIX tar archive (GNU)
bandit12@bandit:/tmp/shiro$ tar xvf data6.bin.out
data8.bin
bandit12@bandit:/tmp/shiro$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", from Unix
bandit12@bandit:/tmp/shiro$ mv data8.bin data8.gz
bandit12@bandit:/tmp/shiro$ gunzip data8.gz
bandit12@bandit:/tmp/shiro$ ls
data5.bin  data6.bin.out  data8  data.txt  something
bandit12@bandit:/tmp/shiro$ file data8
data8: ASCII text
bandit12@bandit:/tmp/shiro$ cat data8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

# Level 13

>   The password for the next level is stored in `/etc/bandit_pass/bandit14` and can only be read by user `bandit14`. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on

```bash
ssh -p 2220 bandit13@bandit.labs.overthewire.org
```

```bash
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
```

# Level 14

>   The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost. Netcat is for UDP/TCP port connections.
>

```bash
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
bandit14@bandit:~$ nc localhost 30000
testing
Wrong! Please enter the correct current password
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14 | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

# Level 15

>   The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.
>   Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…

```bash
ssh -p 2220 bandit15@bandit.labs.overthewire.org
```

```bash
andit15@bandit:~$ cat /etc/bandit_pass/bandit15 | openssl s_client -ign_eof -connect localhost:30001
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEfftLGTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
...
0z2RuRxgxMVjOvcSIJyvwyjVH4jY4I434fMyldePLxO1POLd1cxoKNTO
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
...
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```

# Level 16

>   The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

```bash
ssh -p 2220 bandit16@bandit.labs.overthewire.org
```

```bash
bandit16@bandit:~$ nmap localhost -p31000-32000

Nmap scan report for localhost (127.0.0.1)
Host is up (0.00032s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
bandit16@bandit:~$ cat /etc/bandit_pass/bandit16 | openssl s_client -ign_eof -connect localhost:31046
bandit16@bandit:~$ cat /etc/bandit_pass/bandit16 | openssl s_client -ign_eof -connect localhost:31518
bandit16@bandit:~$ cat /etc/bandit_pass/bandit16 | openssl s_client -ign_eof -connect localhost:31691
bandit16@bandit:~$ cat /etc/bandit_pass/bandit16 | openssl s_client -ign_eof -connect localhost:31790
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIESK0prjANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
...
JUvpO+seiTk7lj/4byRQXlHcYxMdAflrDl+m9tKeDJlYaAPO5d9P28Iv
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
...
---
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
...
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```

# Level 17

>   There are 2 files in the homedirectory: `passwords.old` and `passwords.new`. The password for the next level is in `passwords.new` and is the only line that has been changed between `passwords.old` and `passwords.new`
>
>   NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19
>

```bash
bandit16@bandit:/tmp/shiro$ mkdir /tmp/shiro2
bandit16@bandit:/tmp/shiro$ cd /tmp/shiro2
bandit16@bandit:/tmp/shiro2$ nano bandit17
Unable to create directory /home/bandit16/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

bandit16@bandit:/tmp/shiro2$ cat bandit17
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
...
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
bandit16@bandit:/tmp/shiro2$ chmod 600 bandit17
bandit16@bandit:/tmp/shiro2$ ssh -i bandit17 bandit17@localhost
bandit17@bandit:~$ ls
passwords.new  passwords.old
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```

# Level 18

>   The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.
>

```bash
$ sshpass -p kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd ssh bandit18@bandit.labs.overthewire.org -p 2220
```

When you try to login, it immediately kicks you out. However, you can run a command after you login.

```bash
$ sshpass -p kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

# Level 19

>   To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

```bash
sshpass -p IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x ssh bandit19@bandit.labs.overthewire.org -p 2220
```

```bash
bandit19@bandit:~$ ls -l
total 8
-rwsr-x--- 1 bandit20 bandit19 7296 May  7  2020 bandit20-do
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

# Level 20

>   There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

```bash
sshpass -p GbKksEFF4yrVs6il55v6gwY5aVje5f0j ssh bandit20@bandit.labs.overthewire.org -p 2220
```

Open another terminal and connect to bandit20. Start netcat and then connect to the netcat from the other terminal. Thereafter, send the bandit20 password from the netcat terminal.

```bash
bandit20@bandit:~$ ./suconnect 8888
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
```

```bash
bandit20@bandit:~$ nc -lvp 8888
listening on [any] 8888 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 55944
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

# Level 21

>   A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

```bash
sshpass -p gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr ssh bandit21@bandit.labs.overthewire.org -p 2220
```

```bash
bandit21@bandit:~$ cd /etc/cron.d
bandit21@bandit:/etc/cron.d$ ls
cronjob_bandit15_root  cronjob_bandit17_root  cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  cronjob_bandit25_root
bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

# Level 22

>   A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
>   NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

```bash
sshpass -p Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI ssh bandit22@bandit.labs.overthewire.org -p 2220
```

```bash
bandit22@bandit:~$ cd /etc/cron.d
bandit22@bandit:/etc/cron.d$ ls
cronjob_bandit15_root  cronjob_bandit17_root  cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  cronjob_bandit25_root
bandit22@bandit:/etc/cron.d$ cat cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:/etc/cron.d$ myname=$(whoami)
bandit22@bandit:/etc/cron.d$ echo myname
myname
bandit22@bandit:/etc/cron.d$ mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
bandit22@bandit:/etc/cron.d$ echo $mytarget
8169b67bd894ddbb4412f91573b38db3
bandit22@bandit:/etc/cron.d$ echo "I am user bandit22" | md5sum | cut -d ' ' -f 1
8169b67bd894ddbb4412f91573b38db3
bandit22@bandit:/etc/cron.d$ echo "I am user bandit23" | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:/etc/cron.d$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

# Level 23

>   A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
>
>   NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!
>
>   NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…
>

```bash
sshpass -p jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n ssh bandit23@bandit.labs.overthewire.org -p 2220
```

```bash
bandit23@bandit:/etc/cron.d$ cat cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit23@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit23@bandit:/etc/cron.d$ myname=bandit24
bandit23@bandit:/etc/cron.d$ cd /var/spool/$myname
bandit23@bandit:/etc/cron.d$ mkdir /tmp/shiro
bandit23@bandit:/etc/cron.d$ chmod 777 /tmp/shiro
bandit23@bandit:/var/spool/bandit24$ nano script.sh
Unable to create directory /home/bandit23/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

bandit23@bandit:/var/spool/bandit24$ cat script.sh
#!/bin/bash

cat /etc/bandit_pass/bandit24 > /tmp/shiro/password.txt
bandit23@bandit:/var/spool/bandit24$ chmod +x script.sh
bandit23@bandit:/var/spool/bandit24$ ls /tmp/shiro
password.txt
bandit23@bandit:/var/spool/bandit24$ cat /tmp/shiro/password.txt
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

# Level 24

>   A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.
>

```bash
sshpass -p UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ ssh bandit24@bandit.labs.overthewire.org -p 2220
```

```bash
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
bandit24@bandit:~$ mkdir /tmp/shiro
bandit24@bandit:~$ cd /tmp/shiro
bandit24@bandit:/tmp/shiro$ nano script.sh
Unable to create directory /home/bandit24/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

bandit24@bandit:/tmp/shiro$ cat script.sh
#!/bin/bash

for i in {0000..9999}
do
echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i" >> combinations.txt
done
bandit24@bandit:/tmp/shiro$ chmod +x script.sh
bandit24@bandit:/tmp/shiro$ ./script.sh
bandit24@bandit:/tmp/shiro$ cat combinations.txt | nc localhost 30002 >> result.txt
bandit24@bandit:/tmp/shiro$ sort result.txt | uniq -u

Correct!
Exiting.
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
```

# Level 25

>   Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.
>

```bash
sshpass -p uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG ssh bandit25@bandit.labs.overthewire.org -p 2220
```

```bash
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ cat bandit26.sshkey
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApis2AuoooEqeYWamtwX2k5z9uU1Afl2F8VyXQqbv/LTrIwdW
...
IZdtF5HXs2S5CADTwniUS5mX1HO9l5gUkk+h0cH5JnPtsMCnAUM+BRY=
-----END RSA PRIVATE KEY-----

bandit25@bandit:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
bandit0:x:11000:11000:bandit level 0:/home/bandit0:/bin/bash
bandit1:x:11001:11001:bandit level 1:/home/bandit1:/bin/bash
...
bandit25:x:11025:11025:bandit level 25:/home/bandit25:/bin/bash
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit27:x:11027:11027:bandit level 27:/home/bandit27:/bin/bash
...
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost
```

In vim editor, type `:e cat /etc/bandit_pass/bandit26`
Password is `5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z`

# Level 26

>   Good job getting a shell! Now hurry and grab the password for bandit27!
>

```bash
sshpass -p 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z ssh bandit26@bandit.labs.overthewire.org -p 2220
```

In vim editor, type `set shell=/bin/bash` and then `:shell`

```bash
bandit26@bandit:~$ ls
bandit27-do  text.txt
bandit26@bandit:~$ ./bandit27-do
Run a command as another user.
  Example: ./bandit27-do id
bandit26@bandit:~$ ./bandit27-do id
uid=11026(bandit26) gid=11026(bandit26) euid=11027(bandit27) groups=11026(bandit26)
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```
