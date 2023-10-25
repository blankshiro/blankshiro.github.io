---
layout: post
title: TryHackMe Registry Persistence Detection
date: 2023-01-01
categories: [TryHackMe, Methodology]
tags: [TryHackMe, Methodology]
---
>   Source: [Registry Persistence Detection](https://tryhackme.com/room/registrypersistencedetection)

# I. Malware Persistence Mechanisms

There are multiple ways malware can gain persistence. In Windows, the most common and easiest-to-implement technique is the abuse of Windows Registry Run keys.

The Windows Registry is a database of low-level operating systems and application settings. The Run keys are specific keys within the Registry that contain a path that runs every time a user logs on, and they are listed below:

-   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` - Run path when the current user logs in
-   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` - Run path when *any* user logs in
-   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` - Run path when the current user logs in, then delete
-   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce` - Run path when *any* user logs in, then delete



# II. AutoRuns

A widely-used tool from Microsoft called [AutoRuns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) checks all possible locations where a program can automatically run on start-up or when a user logs in. There is also a [AutoRuns PowerShell module](https://github.com/p0w3rsh3ll/AutoRuns).

AutoRuns PowerShell has a function called `Get-PSAutorun` that will list all possible auto-start mechanisms available on the machine. It makes this list by looking at categories like the Registry, Windows services, WMI entries, DLL hijacking, and more. Piping the result of the command above to the [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-7.2) cmdlet can make the output more readable.

```powershell
PS C:\> Get-PSAutorun | Out-GridView
```

