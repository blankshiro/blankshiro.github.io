---
layout: post
title: Mobile Notes
date: 2024-07-01
tags: [Cheatsheet]
---

# Mobile
## iOS
### Jailbreaking iOS device
```shell
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
```shell
# Add Akemi and Frida repo to Cydia
Cydia > Manage > Sources > Edit > Add Sources https://cydia.akemi.ai/ and https://build.frida.re

# MOBSF
$ docker pull opensecurity/mobile-security-framework-mobsf:latest
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Frida
$ pip install frida-tools

# MOBSF
$ docker pull opensecurity/mobile-security-framework-mobsf:latest
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Frida
$ pip install frida-tools
```

### Installing and Obtaining IPA files on jailbroken iOS device
```shell
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
