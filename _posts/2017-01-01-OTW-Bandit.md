---
layout: post
title: OverTheWire Bandit
date: 2017-01-01
categories: [OverTheWire, Bandit]
tags: [OverTheWire, Bandit]
---

# Level 0

`ssh -p 2220 bandit0@bandit.labs.overthewire.org`

```
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

# Level 1

The password for the next level is stored in a file called - located in the home directory
`ssh -p 2220 bandit1@bandit.labs.overthewire.org`

```
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat < -
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

# Level 2

The password for the next level is stored in a file called spaces in this filename located in the home directory
`ssh -p 2220 bandit2@bandit.labs.overthewire.org`

```
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat < spaces\ in\ this\ filename
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

# Level 3

The password for the next level is stored in a hidden file in the inhere directory.
`ssh -p 2220 bandit3@bandit.labs.overthewire.org`

```
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

The password for the next level is stored in the only human-readable file in the inhere directory.
`ssh -p 2220 bandit4@bandit.labs.overthewire.org`

```
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

The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

-   human-readable
-   1033 bytes in size
-   not executable

`ssh -p 2220 bandit5@bandit.labs.overthewire.org`

```
bandit5@bandit:~/inhere$ find -type f -size 1033c ! -executable
./maybehere07/.file2
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

# Level 6

The password for the next level is stored somewhere on the server and has all of the following properties:

-   owned by user bandit7
-   owned by group bandit6
-   33 bytes in size

`ssh -p 2220 bandit6@bandit.labs.overthewire.org`

```
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

# Level 7

The password for the next level is stored in the file data.txt next to the word millionth
`ssh -p 2220 bandit7@bandit.labs.overthewire.org`

```
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ cat data.txt | grep millionth
millionth	cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

# Level 8

The password for the next level is stored in the file data.txt and is the only line of text that occurs only once
`ssh -p 2220 bandit8@bandit.labs.overthewire.org`

```
bandit8@bandit:~$ ls
data.txt
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

# Level 9

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.
`ssh -p 2220 bandit9@bandit.labs.overthewire.org`

```
bandit9@bandit:~$ ls
data.txt
bandit9@bandit:~$ cat data.txt | strings | grep ===
========== the*2i"4
========== password
Z)========== is
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```

# Level 10

The password for the next level is stored in the file data.txt, which contains base64 encoded data
`ssh -p 2220 bandit10@bandit.labs.overthewire.org`

```
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

# Level 11

The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions
`ssh -p 2220 bandit11@bandit.labs.overthewire.org`

```
sudo apt-get install hxtools -y
echo "Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh" | rot13
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

# Level 12

The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed.
`ssh -p 2220 bandit12@bandit.labs.overthewire.org`

```
bandit12@bandit:/tmp/shiro$ xxd -r data.txt > something
bandit12@bandit:/tmp/shiro$ file something
something: gzip compressed data, was "data2.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
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
something.out: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
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
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
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

The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on
`ssh -p 2220 bandit13@bandit.labs.overthewire.org`

```
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
```

# Level 14

The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.
Netcat is for UDP/TCP port connections.

```
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

The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.
Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…
`ssh -p 2220 bandit15@bandit.labs.overthewire.org`

```
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
b2NhbGhvc3QwHhcNMjEwNDEzMDgzODA3WhcNMjIwNDEzMDgzODA3WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMLfXBVa
jVKDHlA3U+S0hBMJMJlfue3xKECpmx1Ajp4/khUuWwvPB7+wLjqasBO2WfFYJzcq
z9t7FfAPIlYjgvOTQs5X4vQ1aGzanvnNn+1VknpOnFAJQBSFq6ZD3ipWrhwm9XZq
8CgFhTGp9IPthZp8Y0B7OgobhlMtXD/zLaTbAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAMFH9rsZovwnb5k71/MpyCnXEwGlIhixUu6qfi1kiFvhJ6lJCvaO
weOYxV4oJy1OEB0LSEAQOnSPfzC8dDasijFcdVhuIGGPuQ2GZ05nCiiIZUNnrMRB
0z2RuRxgxMVjOvcSIJyvwyjVH4jY4I434fMyldePLxO1POLd1cxoKNTO
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 75FEF37F9B9BC8B3F4559C58177443B6523477B2ED89D9C7FCFDED8A1F5C1D49
    Session-ID-ctx:
    Master-Key: 49ECAF94E38F0D7A80CC89AABDDC942DE4F4604B8EE4730C3269A525F378C710CCB693EE35B61F2F141439CF6C83A2B3
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - f2 5b 83 7e f0 ca 58 ca-aa f3 8f 83 b9 65 d5 23   .[.~..X......e.#
    0010 - 63 bb 43 cb 0d c6 39 6a-a8 18 2e a9 f9 ea 44 a5   c.C...9j......D.
    0020 - 3f 61 50 ac a4 3c 59 89-1e d3 58 85 d5 d0 76 10   ?aP..<Y...X...v.
    0030 - 9d 66 03 85 49 ca 66 4b-a0 59 7f 59 d1 5a 91 44   .f..I.fK.Y.Y.Z.D
    0040 - fd 44 80 a7 a7 3c 89 f3-1e ab 3a c8 84 e1 53 28   .D...<....:...S(
    0050 - f0 3e 83 f6 b0 fc b4 ad-a5 18 c3 14 d7 c9 4c db   .>............L.
    0060 - d9 c4 85 c5 c9 76 a7 a3-da 61 dd 2a 45 16 93 3d   .....v...a.*E..=
    0070 - 5d 93 f9 13 30 c6 d9 d7-42 a5 d3 8b b3 00 b3 e8   ]...0...B.......
    0080 - 76 15 c0 de 99 c9 68 1b-00 af b3 41 64 bf fb ac   v.....h....Ad...
    0090 - a2 f5 f1 a7 4f b4 a9 19-6d 0d 73 0f c0 96 da ed   ....O...m.s.....

    Start Time: 1624774406
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```

# Level 16

The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.
`ssh -p 2220 bandit16@bandit.labs.overthewire.org`

```
bandit16@bandit:~$ nmap localhost -p31000-32000

Starting Nmap 7.40 ( https://nmap.org ) at 2021-06-27 08:16 CEST
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
b2NhbGhvc3QwHhcNMjEwNjE0MTkzOTAyWhcNMjIwNjE0MTkzOTAyWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL3AJi7+
mhQwXXHZweajk45kDauQ8gItcbmfbmCE8dvjBuzjFho+nN9OZ/5xPHjNy+15d+Kr
iv+p1DPsjtPdDP5LNhShGBJIdj+h1DanaQbZnILW64fmbZPQzsvf1U0q3KUX/Hr5
OlZNV5eryXtPGELBddTVB4QyRo7qEdCIjf83AgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBACDBqqnOEy6516ocDng2iqNRS+mLAiaVKONccL+847NK54W4g4Wo
0PdPF4dVhkNiLGJDcrx3aY4A+u+aFAcZmDYJOFsGJMCBOdle8v9PvQ6V/y8x4TkR
JUvpO+seiTk7lj/4byRQXlHcYxMdAflrDl+m9tKeDJlYaAPO5d9P28Iv
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 5377BF257A34A616028A1B70A9B356C0DDEA8876880E08003B0AD31643F5409F
    Session-ID-ctx:
    Master-Key: ED15CF6168B9EFBBC425C7443BF563F3ABEAA51E3065E3E692D2B09D5C0BB2099233445071A6C9AF8F384E9A4394453C
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 4d 56 29 e9 f1 5c 3e 86-5d 40 4d 5e 38 22 f0 d1   MV)..\>.]@M^8"..
    0010 - c9 e4 cd 6c e8 ff 72 ca-8f 28 d5 78 8a 53 db fa   ...l..r..(.x.S..
    0020 - 69 1a 71 e6 ee 7c e4 a6-a3 81 a0 56 dd 06 2d ce   i.q..|.....V..-.
    0030 - fd f5 6f b5 74 81 24 98-fa 49 95 59 34 61 f9 7d   ..o.t.$..I.Y4a.}
    0040 - 9e 4b 6f ac c3 0b 7a 3b-50 c5 cb b2 60 ed 82 35   .Ko...z;P...`..5
    0050 - e9 f4 4d d3 cd 62 4d 20-73 47 e5 77 7b bf 82 05   ..M..bM sG.w{...
    0060 - 49 ea 8d 76 70 75 31 6b-d8 6d 5b e5 e9 f7 bd 14   I..vpu1k.m[.....
    0070 - 42 d4 57 83 cd 11 f8 0d-b1 0f c4 14 e1 f4 51 10   B.W...........Q.
    0080 - a2 78 fc f1 d1 23 65 cc-ab b6 be 9b c1 42 cb 84   .x...#e......B..
    0090 - 00 05 a1 4b 24 8f b4 9b-a7 f3 54 88 79 37 96 4c   ...K$.....T.y7.L

    Start Time: 1624774779
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```

# Level 17

There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new

NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

```
bandit16@bandit:/tmp/shiro$ mkdir /tmp/shiro2
bandit16@bandit:/tmp/shiro$ cd /tmp/shiro2
bandit16@bandit:/tmp/shiro2$ nano bandit17
Unable to create directory /home/bandit16/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

bandit16@bandit:/tmp/shiro2$ cat bandit17
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
bandit16@bandit:/tmp/shiro2$ chmod 600 bandit17
bandit16@bandit:/tmp/shiro2$ ssh -i bandit17 bandit17@localhost
```

```
bandit17@bandit:~$ ls
passwords.new  passwords.old
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```

# Level 18

The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

```
┌──(root💀shiro)-[/home/shiro/OverTheWire/Bandit]
└─# sshpass -p kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd ssh bandit18@bandit.labs.overthewire.org -p 2220
```

When you try to login, it immediately kicks you out. However, you can run a command after you login.

```
┌──(root💀shiro)-[/home/shiro/OverTheWire/Bandit]
└─# sshpass -p kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

# Level 19

To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.
`sshpass -p IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x ssh bandit19@bandit.labs.overthewire.org -p 2220`

```
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

There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).
`sshpass -p GbKksEFF4yrVs6il55v6gwY5aVje5f0j ssh bandit20@bandit.labs.overthewire.org -p 2220`
Open another terminal and connect to bandit20. Start netcat and then connect to the netcat from the other terminal. Thereafter, send the bandit20 password from the netcat terminal.

```
bandit20@bandit:~$ ./suconnect 8888
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
```

```
bandit20@bandit:~$ nc -lvp 8888
listening on [any] 8888 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 55944
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

# Level 21

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
`sshpass -p gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr ssh bandit21@bandit.labs.overthewire.org -p 2220`

```
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

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.
`sshpass -p Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI ssh bandit22@bandit.labs.overthewire.org -p 2220`

```
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

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

```
sshpass -p jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n ssh bandit23@bandit.labs.overthewire.org -p 2220
```

```
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

A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

```
sshpass -p UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ ssh bandit24@bandit.labs.overthewire.org -p 2220
```

```
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

Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

```
sshpass -p uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG ssh bandit25@bandit.labs.overthewire.org -p 2220
```

```
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ cat bandit26.sshkey
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApis2AuoooEqeYWamtwX2k5z9uU1Afl2F8VyXQqbv/LTrIwdW
pTfaeRHXzr0Y0a5Oe3GB/+W2+PReif+bPZlzTY1XFwpk+DiHk1kmL0moEW8HJuT9
/5XbnpjSzn0eEAfFax2OcopjrzVqdBJQerkj0puv3UXY07AskgkyD5XepwGAlJOG
xZsMq1oZqQ0W29aBtfykuGie2bxroRjuAPrYM4o3MMmtlNE5fC4G9Ihq0eq73MDi
1ze6d2jIGce873qxn308BA2qhRPJNEbnPev5gI+5tU+UxebW8KLbk0EhoXB953Ix
3lgOIrT9Y6skRjsMSFmC6WN/O7ovu8QzGqxdywIDAQABAoIBAAaXoETtVT9GtpHW
qLaKHgYtLEO1tOFOhInWyolyZgL4inuRRva3CIvVEWK6TcnDyIlNL4MfcerehwGi
il4fQFvLR7E6UFcopvhJiSJHIcvPQ9FfNFR3dYcNOQ/IFvE73bEqMwSISPwiel6w
e1DjF3C7jHaS1s9PJfWFN982aublL/yLbJP+ou3ifdljS7QzjWZA8NRiMwmBGPIh
Yq8weR3jIVQl3ndEYxO7Cr/wXXebZwlP6CPZb67rBy0jg+366mxQbDZIwZYEaUME
zY5izFclr/kKj4s7NTRkC76Yx+rTNP5+BX+JT+rgz5aoQq8ghMw43NYwxjXym/MX
c8X8g0ECgYEA1crBUAR1gSkM+5mGjjoFLJKrFP+IhUHFh25qGI4Dcxxh1f3M53le
wF1rkp5SJnHRFm9IW3gM1JoF0PQxI5aXHRGHphwPeKnsQ/xQBRWCeYpqTme9amJV
tD3aDHkpIhYxkNxqol5gDCAt6tdFSxqPaNfdfsfaAOXiKGrQESUjIBcCgYEAxvmI
2ROJsBXaiM4Iyg9hUpjZIn8TW2UlH76pojFG6/KBd1NcnW3fu0ZUU790wAu7QbbU
i7pieeqCqSYcZsmkhnOvbdx54A6NNCR2btc+si6pDOe1jdsGdXISDRHFb9QxjZCj
6xzWMNvb5n1yUb9w9nfN1PZzATfUsOV+Fy8CbG0CgYEAifkTLwfhqZyLk2huTSWm
pzB0ltWfDpj22MNqVzR3h3d+sHLeJVjPzIe9396rF8KGdNsWsGlWpnJMZKDjgZsz
JQBmMc6UMYRARVP1dIKANN4eY0FSHfEebHcqXLho0mXOUTXe37DWfZza5V9Oify3
JquBd8uUptW1Ue41H4t/ErsCgYEArc5FYtF1QXIlfcDz3oUGz16itUZpgzlb71nd
1cbTm8EupCwWR5I1j+IEQU+JTUQyI1nwWcnKwZI+5kBbKNJUu/mLsRyY/UXYxEZh
ibrNklm94373kV1US/0DlZUDcQba7jz9Yp/C3dT/RlwoIw5mP3UxQCizFspNKOSe
euPeaxUCgYEAntklXwBbokgdDup/u/3ms5Lb/bm22zDOCg2HrlWQCqKEkWkAO6R5
/Wwyqhp/wTl8VXjxWo+W+DmewGdPHGQQ5fFdqgpuQpGUq24YZS8m66v5ANBwd76t
IZdtF5HXs2S5CADTwniUS5mX1HO9l5gUkk+h0cH5JnPtsMCnAUM+BRY=
-----END RSA PRIVATE KEY-----
bandit25@bandit:~$ cat /etc/passwd
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
messagebus:x:101:104::/var/run/dbus:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
identd:x:103:65534::/var/run/identd:/bin/false
ntp:x:104:107::/home/ntp:/bin/false
bandit0:x:11000:11000:bandit level 0:/home/bandit0:/bin/bash
bandit1:x:11001:11001:bandit level 1:/home/bandit1:/bin/bash
bandit10:x:11010:11010:bandit level 10:/home/bandit10:/bin/bash
bandit11:x:11011:11011:bandit level 11:/home/bandit11:/bin/bash
bandit12:x:11012:11012:bandit level 12:/home/bandit12:/bin/bash
bandit13:x:11013:11013:bandit level 13:/home/bandit13:/bin/bash
bandit14:x:11014:11014:bandit level 14:/home/bandit14:/bin/bash
bandit15:x:11015:11015:bandit level 15:/home/bandit15:/bin/bash
bandit16:x:11016:11016:bandit level 16:/home/bandit16:/bin/bash
bandit17:x:11017:11017:bandit level 17:/home/bandit17:/bin/bash
bandit18:x:11018:11018:bandit level 18:/home/bandit18:/bin/bash
bandit19:x:11019:11019:bandit level 19:/home/bandit19:/bin/bash
bandit2:x:11002:11002:bandit level 2:/home/bandit2:/bin/bash
bandit20:x:11020:11020:bandit level 20:/home/bandit20:/bin/bash
bandit21:x:11021:11021:bandit level 21:/home/bandit21:/bin/bash
bandit22:x:11022:11022:bandit level 22:/home/bandit22:/bin/bash
bandit23:x:11023:11023:bandit level 23:/home/bandit23:/bin/bash
bandit24:x:11024:11024:bandit level 24:/home/bandit24:/bin/bash
bandit25:x:11025:11025:bandit level 25:/home/bandit25:/bin/bash
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit27:x:11027:11027:bandit level 27:/home/bandit27:/bin/bash
bandit28:x:11028:11028:bandit level 28:/home/bandit28:/bin/bash
bandit29:x:11029:11029:bandit level 29:/home/bandit29:/bin/bash
bandit3:x:11003:11003:bandit level 3:/home/bandit3:/bin/bash
bandit30:x:11030:11030:bandit level 30:/home/bandit30:/bin/bash
bandit31:x:11031:11031:bandit level 31:/home/bandit31:/bin/bash
bandit32:x:11032:11032:bandit level 32:/home/bandit32:/home/bandit32/uppershell
bandit33:x:11033:11033:bandit level 33:/home/bandit33:/bin/bash
bandit4:x:11004:11004:bandit level 4:/home/bandit4:/bin/bash
bandit5:x:11005:11005:bandit level 5:/home/bandit5:/bin/bash
bandit6:x:11006:11006:bandit level 6:/home/bandit6:/bin/bash
bandit7:x:11007:11007:bandit level 7:/home/bandit7:/bin/bash
bandit8:x:11008:11008:bandit level 8:/home/bandit8:/bin/bash
bandit9:x:11009:11009:bandit level 9:/home/bandit9:/bin/bash
bandit27-git:x:11527:11527::/home/bandit27-git:/usr/bin/git-shell
bandit28-git:x:11528:11528::/home/bandit28-git:/usr/bin/git-shell
bandit29-git:x:11529:11529::/home/bandit29-git:/usr/bin/git-shell
bandit30-git:x:11530:11530::/home/bandit30-git:/usr/bin/git-shell
bandit31-git:x:11531:11531::/home/bandit31-git:/usr/bin/git-shell
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

Good job getting a shell! Now hurry and grab the password for bandit27!

```
sshpass -p 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z ssh bandit26@bandit.labs.overthewire.org -p 2220
```

In vim editor, type `set shell=/bin/bash` and then `:shell`

```
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
