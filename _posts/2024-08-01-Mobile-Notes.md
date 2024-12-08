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
MOBSF> credentials are mobsf:mobsf

# Frida
$ pip install frida-tools # install frida-tools on computer
iOS> add source https://build.frida.re
$ wget https://github.com/frida/frida/releases/frida_16.1.8_iphoneos-arm64.deb
$ scp frida_16.1.8_iphoneos-arm64.deb root@192.168.1.XXX:/var/tmp/
ssh$ dpkg -i frida_16.1.8_iphoneos-arm64.deb
ssh$ ps aux | grep frida # check if frida is running
ssh$ /usr/sbin/frida-server -l 0.0.0.0 &
$ frida-ps -H 192.168.1.XXX # check if frida commands can run

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
computer> ssh root@192.168.X.Y
```

##### Copying files to iOS Device using SSH
```bash
ssh$ scp file root@192.168.X.Y:/var/tmp/
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
$ find /var/ -name "*.app"
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

### Static Analysis

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

# Decompiling main.jsbundle file (https://github.com/numandev1/react-native-decompiler)
$ npx react-native-decompiler -i ./main.jsbundle -o ./output
```

### Dynamic Analysis

```bash
# List all apps currently installed on iOS
$ frida-ps -Uai
$ objection -g <AppName> explore
# or 
$ objection -g <pid> explore
# or
$ objection -g <pid> explore -s "ios sslpinning disable"

# View environment variables for app
objection> env
Name					Path
__________________		__________
DocumentsDirectory		/var/mobile/Containers/Data/Application/ABCD-EFGH-IJKL/
...						...
# Check for Sensitive Information saved by the app in the filesystem
# Sensitive Data in Plist
objection> ios plist cat userInfo.plist

# Sensitive data in UserDefaults
objection> ios nsuserdefaults get

# Sensitive data in Keychain
objection> ios keychain dump_raw # gives some hexadecimal value (decode using hex to ascii converter)

# Sensitive data in NSURLCredentialStorage
objection> ios nsurlcredentialstorage dump

# Sensitive data in cookies
objection> ios cookies get

# Try to bypass Jailbreak detection
objection> ios jailbreak disable

# Disable SSL Pinning
obection> ios sslpinning disable --quiet

# Search for classes
objection> ios hooking search classes "string"
objection> ios hooking list class_methods <class>

# Set return value (boolean) to class
objection> ios hooking set return_value "+[<class> <method>]" 0

# check all classes available
frida$ ObjC.enumerateLoadedClassesSync()
#  list all the methods this class has excluding inherited methods
frida$ ObjC.classes.<interestingclass>.$ownMethods
$ cat jailbreakbypass.js
//for <method> very important to copy exactly from the $ownMethods string.
var jailbreakMethod = ObjC.classes.<jailbreakclass>["<method>"];
Interceptor.attach(jailbreakMethod.implementation,{
    onEnter: function(){}, //do nothing
    onLeave: function(retVal) //need to parse in any variable for it to return
{
    console.log("Disabling jailbreak detection");
    retVal.replace(0);//false
}
});

//for <method> very important to copy exactly from the $ownMethods string.
var methodToCheat = ObjC.classes.<class needed to cheat>["<method>"];
Interceptor.attach(methodToCheat.implementation,{
    onEnter: function(args){
        //args is an array and we know it has 2 values
        console.log("first arg is:" + args[0]);
        console.log("second arg is:" + args[1]);
    },
    onLeave: function(retVal) //need to parse in any variable for it to return
    {
        console.log("current return val is:" + returnVal);
        console.log("changing it to 10");
        retVal.replace(10);
    }
});
# run frida with js script
$ frida -l jailbreakbypass.js -f <bundle identifier>
```

## Android
### Setting Up `adb`
```bash
# kill any adb process running
cmd> taskkill /f /t /im adb.exe
# start a server on host
cmd> adb.exe -a nodaemon server
# check your IP for Wireless LAN adapter Wi-Fi IP
cmd> ipconfig
# check if AVD is detectable on kali
$ .\adb.exe -H <ip> -P 5037 devices
# access AVD shell
$ .\adb.exe -H <ip> -P 5037 shell

# Debugging Purposes
cmd> .\emulator.exe -list-avds
cmd> .\emulator.exe -avd Pixel_6_API_30 -writable-system -no-snapshot-load
cmd> .\adb.exe -H <ip> root
cmd> .\adb.exe -H <ip> shell avbctl disable-verification
cmd> .\adb.exe -H <ip> reboot
cmd> .\adb.exe -H <ip> root
cmd> .\adb.exe -H <ip> remount

# Create Burp Certificate
cmd> openssl x509 -inform DER -in cacert.der -out cacert.pem
cmd> openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
cmd> mv cacert.pem <hash>.0 (in my case the hash is 9a5ba575)
cmd> .\adb.exe push 9a5ba575.0 /sdcard/
adb> mv /sdcard/9a5ba575.0 /system/etc/security/cacerts
adb> chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

##### Common `adb` commands
```bash
# list all connected Android devices
$ adb devices

# install/uninstall apk
$ adb install/uninstall [path to APK]

# copies file from Android to local computer or vice versa
$ adb pull/push [remote file path] [local file path]

# display Android system log in real-time (c is clear, d is display)
$ adb logcat [-c / -d] 

# list all installed packages
$ adb shell pm list packages | grep sampleapp

# stop package activity 
$ adb shell am force-stop <package>

# dump the package information
$ adb shell pm dump <package>

# get the full path of apk file
$ adb shell pm path <package>

# kill all background processes
$ adb am kill-all

# start activity with intent
$ adb shell am start -W -a android.intent.action.VIEW -d "https://attacker.com"

# query contents
$ adb shell content query --uri "content://org.abc.appname/user/1"
```

### Static Analysis

#### Reverse Engineering
> 2 methods: `DEX` to `JAR` to `JAVA` or `APK` to `JAVA`.

##### Dex2Jar + JD-GUI
```bash
# https://sourceforge.net/projects/dex2jar/
# Step 1: convert .apk file to .zip file and then extract zip file

# Step 2: use dex2jar to convert .dex to JAR files
cmd> d2j-dex2jar.bat C:\path\to\classes.dex

# Step 3: use jd-gui to open classes-dex2jar.jar file
```
##### JADX
```bash
# Just open the apk file with JADX!
```

#### Decompiling, Recompiling, and Signing
```bash
# https://apktool.org/
# Step 1: Decompile the apk file with apktool
cmd> set path = "C:\Program Files\Java\jdk-xx\bin"
cmd> apktool d app.apk

# Step 2: Modify whatever you want on the source code

# Step 3: Recompile the apk folder
cmd> apktool d <folder>
# Step 4: Sign the APK
kali$ keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
kali$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore <app_modified.apk>
# or
kali$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore <app_modified.apk> alias_name

# Step 5: Install on Android device
kali$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore appWithSSL.apk alias_name
```

### Manifest File Analysis
Find vulnerabilities from the `Manifest.xml`:
- `debuggable="true"`
- `android:allowBackup="false"`
- `android:networkSecurityConfig="@xml/network_security_config"` in `res/xml/`
- Exported Activities and Services
- Content Providers and FileProviders
- Broadcast Receivers and URL Schemes
- `minSdkVersion`, `targetSDKVersion`, and `maxSdkVersion`

### Dynamic Analysis
```bash
$ apktool d test.apk
$ grep -Rnw ./* -e "interestingFunctionName"
$ apktool b testFolder -o testModified.apk
cmd> java -jar uber-apk-signer-1.3.0.jar --apks testModified.apk

$ su
$ netstat -tunlp
$ kill -9 <pid_of_frida>

$ adb push -H $IP file /data/local/tmp/
$ adb shell chmod 755 /data/local/tmp/frida-server
$ adb shell "/data/local/tmp/frida-server &"
kali$ adb -H $IP forward tcp:27042 tcp:27042
kali$ adb -H $IP forward tcp:27043 tcp:27043
$ frida-ps -H $IP -ai

# Frida scripting
$ cat letsGetPassword.js # requires user interaction
function letsGetPassword()
{
var whatevername = Java.use("<package>.<classname>");
whatevername.<function>.implementation = function()
{
var password = this.<function>(); // this function is actual function in app!
console.log(password);
return this.<function>(); // return as per normal
}
}
Java.perform(letsGetPassword);
$ cat letsGetPassword.js # don't need user interaction
Java.perform(function () {
        var vaultClass = Java.use("<package>.<classname>");
        var vaultInstance = vaultClass.$new();
        console.log(vaultInstance.<functionName>());
        // send(vaultInstance.<functionName>());
});
frida$ %load letsGetPassword.js

# Objection
$ objection -N -h "192.168.X.Y" -g <app_package> explore -s "android root disable"
objection$ android hooking search classes <class you are interested in> 
objection$ android hooking watch class_method <package>.<class>.<password function> --dump-return
```
