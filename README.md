# Invoke-PowerExtract

This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) oder additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (currently limited to NT-Hashes) of the LSASS process.

Important: The script holds no functionality to create dump files - it will just read them.


Currently supported Windows Versions (64bit only):

Clients:

Windows 10
Windows 8.1
windows 8
Windows 7

Server:

Windows Server 2019
Windows Server 2016
Windows Server 2012R2
Windows Server 2012
Windows Server 2008R2 (implemented - tests ongoing)
Windows Server 2008

Currently open:

Windows 11
Windows Server 2022

# Usage 

The is quite simple:
```powershell
 Invoke-PowerExtract -PathToDMP C:\temp\lsass.dmp
```

# Future Plans

 Mid-term I will add additional authentication packages (e.g. Kerberos).
 