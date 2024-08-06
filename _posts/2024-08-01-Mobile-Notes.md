---
layout: post
title: Mobile Notes
date: 2024-08-01
tags: [Mobile, Cheatsheet]
---

# Mobile
## iOS
### Jailbreaking iOS device
```bash
# https://canijailbreak.com/

# checkra1n Jailbreak (https://aupsham98.medium.com/practical-ios-penetration-testing-a-step-by-step-guide-8214d35aaf3c)
$ wget https://assets.checkra.in/downloads/linux/cli/x86_64/dac9968939ea6e6bfbdedeb41d7e2579c4711dc2c5083f91dced66ca397dc51d/checkra1n -O checkra1n
$ chmod +x checkra1n
$ sudo checkra1n
checkra1n> Click Start to put iOS device in recovery mode
checkra1n> Click Next
checkra1n> Click Next
checkra1n> Click Start
checkra1n> Wait for device to restart after Jailbreak completes
ios device> open checkra1n app
checkra1n app> install Cydia
```

### Installing Tools on iOS device
```bash
# Add Akemi and Frida repo to Cydia
Cydia > Manage > Sources > Edit > Add Sources https://cydia.akemi.ai/ and https://build.frida.re

$ iproxy 2222 22
$ ssh root@localhost 2222

# MOBSF
$ docker pull opensecurity/mobile-security-framework-mobsf:latest
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Frida
$ pip install frida-tools

# Objection
$ pip3 install objection

# MOBSF
$ docker pull opensecurity/mobile-security-framework-mobsf:latest
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Frida
$ pip install frida-tools
```

### SSH Into iOS Device
```bash
! Make sure that your iOS device is in the same network as your computer !
! Make sure that your iOS device has openSSH installed !
iOS> go to WiFi settings and look for the ip address
computer> ssh root@192.168.1.XXX
```

##### Copying files to iOS Device using SSH
```bash
ssh$ scp file root@192.168.1.XXX:/var/tmp/
```

### Setting Up Burp Proxy
```bash
BurpSuite> Proxy > Options > Proxy Listeners > select "Bind to address: All interfaces"
iOS device> Settings > Wi-Fi > Wi-Fi network connected > Configure Proxy >  Manual > Server = IP address of laptop > Port 8080 
iOS device> open Safari browser > go to http://burp > download certificate and click Allow
iOS device> Settings > General > Profile > Portswigger CA > Install
iOS device> Settings > General > About > Certificate Trust Settings > Enable
```

### Installing and Obtaining IPA files on jailbroken iOS device
```bash
# Installing IPA file
$ idevicename
$ ideviceinstaller -i file.ipa

# Obtaining installed IPA file
$ find /var/ -name "*.app"'
$ cd /tmp
$ mkdir Payload
$ cp -r /location/of/AppName.app Payload/
$ zip -r AppName.app Payload/ 

# Dump IPA file
$ git clone https://github.com/AloneMonkey/frida-ios-dump
$ cd frida-ios-dump
$ sudo pip install -r requirements.txt --upgrade
$ frida-ps -Ua
$ iproxy 2222 22
$ ./dump.py APP_NAME -u root -P password
```

### Static Testing of iOS Application

>   -   IPA files are actually zip packages, so you can change the file extension to `.zip` and decompress them. 
>   -   A fully packaged app that is ready to be installed is called a Bundle.
>   -   After decompressing the file, there should be a file called `AppName.app`, which is a `.zip` archive.

##### MobSF

```bash
MobSF> Drag and drop IPA file into interface and run static analysis

Once static analysis is complete, review results for any misconfigurations or vulnerabilities such as:
. Insecure URL schemes
. Insecure permissions and ATS misconfiguration
. Insecure binary options
. Presence of hardcoded sensitive information such as Firebase database or email addresses
. Other interesting files that may contain security issues or vulnerabilities.
```

##### Manual Testing

```bash
ssh$ find /var/ -name "*.plist" | grep "DVIA"

# system apps can be found in /Applications/ directory 
# user-installed apps are found in /private/var/containers/

# When enabled, the app loads into a random memory address every-time it launches
ssh$ otool -hv <app-binary> | grep PIE # It should include the PIE flag 

# A ‘canary’ value is placed on the stack before calling a function for validation purposes
ssh$ otool -I -v <app-binary> | grep stack_chk # It should include the symbols: stack-chk_guard and stack_chk_fail

# ARC prevents common memory corruption flaws
ssh$ otool -I -v <app-binary> | grep objc_release # It should include the _objc_release symbol

# The binary should be encrypted
ssh$ otool -arch all -Vl <app-binary> | grep -A5 LC_ENCRYPT # The cryptid should be 1

# Weak Hashing Algorithms
ssh$ otool -I -v <app-binary> | grep -w "_CC_MD5"
ssh$ otool -I -v <app-binary> | grep -w "_CC_SHA1"

# Insecure Random Functions
ssh$ otool -I -v <app-binary> | grep -w "_random"
ssh$ otool -I -v <app-binary> | grep -w "_srand"
ssh$ otool -I -v <app-binary> | grep -w "_rand"

# Insecure ‘Malloc’ Function
ssh$ otool -I -v <app-binary> | grep -w "_malloc"

# Insecure and Vulnerable Functions
ssh$ otool -I -v <app-binary> | grep -w "_gets"
ssh$ otool -I -v <app-binary> | grep -w "_memcpy"
ssh$ otool -I -v <app-binary> | grep -w "_strncpy"
ssh$ otool -I -v <app-binary> | grep -w "_strlen"
ssh$ otool -I -v <app-binary> | grep -w "_vsnprintf"
ssh$ otool -I -v <app-binary> | grep -w "_sscanf"
ssh$ otool -I -v <app-binary> | grep -w "_strtok"
ssh$ otool -I -v <app-binary> | grep -w "_alloca"
ssh$ otool -I -v <app-binary> | grep -w "_sprintf"
ssh$ otool -I -v <app-binary> | grep -w "_printf"
ssh$ otool -I -v <app-binary> | grep -w "_vsprintf"

# Check Info.plist (this file contains some app specific configurations)
# Using Linux to convert file to XML
$ plistutil -i Info.plist -o Infoxml.plist
# Using Objection to hook into app
$ objection -g "AppName" explore
objection> ios plist cat Info.plist
# Look for BundleIdentifier, BundleVersion, SupportedDeviceTypes, RequiredPermissions, URLSchemes, NSAppTransportSecurity
```

### Dynamic Testing of iOS Application

```bash
# List all apps currently installed on iOS
$ frida-ps -Uai
$ objection -g "AppName" explore
# View environment variables for app
objection> env
Name					Path
__________________		__________
DocumentsDirectory		/var/mobile/Containers/Data/Application/ABCD-EFGH-IJKL/
...						...
# Check for Sensitive Information saved by the app in the filesystem
# Sensitive Data in Plist
objection> cd /var/mobile/Containers/Data/Application/ABCD-EFGH-IJKL/
objection> ls
...
objection> cd Documents
objection> ios plist cat userInfo.plist
# Sensitive data in UserDefaults
objection> cd Preferences
objection> cd ios plist cat com.abc.xyz.plist
# Sensitive data in Keychain
objection> ios keychain dump_raw # gives some hexadecimal value (decode using hex to ascii converter)
# Sensitive data in database

# Sensitive data in cookies







```



