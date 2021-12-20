# Invoke-PowerExtract

This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) oder additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (currently limited to NT-Hashes) of the LSASS process.

Important: The script holds no functionality to create dump files - it will just read them.


# Usage 

The is quite simple:
```powershell
 Invoke-PowerExtract -PathToDMP C:\temp\lsass.dmp
```

# Future Plans

Currently the functions for reading the dump file itself are quite completed. My next short term goals are increasing the compatibility for extracting secrets for the different Windows Versions (currently Windows 7, Windows 10,  Windows Server 2019 and Windows Server 2016 are supported). Windows Server 2008, Windows Server 2008R2 should work but i am still in ongoing tests. Windows 8 and 8.1 are implemented but need to be tested. Mid-term I will add additional authentication packages (e.g. Kerberos).
 