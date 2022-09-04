<#
    .SYNOPSIS
        Get the kernel system call ID for Nt/Zw functions in ntdll.
    .DESCRIPTION
        The `syscall` instruction, which is typically found in the Nt/Zw functions and differs for each OS
        version, is how user mode operations switch into kernel mode. Direct syscalls can be made to evade
        userland hooks placed by EDR without having to remove them first.
    .EXAMPLE
        Get the syscall ID for all Nt functions.

        PS> Get-SyscallID
    .EXAMPLE
        Get the syscall ID for a specific function.

        PS> Get-SyscallID -Function NtCreateProcess
    .NOTES
        https://github.com/0x00Check
#>
function Get-SyscallID {
    [CmdletBinding()]
    param(
        # Path to ntdll.dll file
        [Parameter(Mandatory = $False)]
        [ValidateScript({
                if (-not ($_ | Test-Path)) {
                    throw "Path does not exist"
                }
                if (-not ($_ | Test-Path -PathType Leaf)) {
                    throw "Path should point to a file"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $Path = "C:\Windows\System32\ntdll.dll",

        # Get the syscall ID for specific function(s)
        [Parameter(Mandatory = $False)]
        [ValidatePattern('^(Nt|Zw)')]
        [string[]]
        $Functions
    )
    begin {
        Write-Verbose "Begin $($MyInvocation.MyCommand)"
        $ErrorActionPreference = "Stop"

        # PInvoke necessary Win32 APIs
        Add-Type -MemberDefinition @"
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DOS_HEADER {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public char[] e_magic;    // Magic number
    public UInt16 e_cblp;     // Bytes on last page of file
    public UInt16 e_cp;       // Pages in file
    public UInt16 e_crlc;     // Relocations
    public UInt16 e_cparhdr;  // Size of header in paragraphs
    public UInt16 e_minalloc; // Minimum extra paragraphs needed
    public UInt16 e_maxalloc; // Maximum extra paragraphs needed
    public UInt16 e_ss;       // Initial (relative) SS value
    public UInt16 e_sp;       // Initial SP value
    public UInt16 e_csum;     // Checksum
    public UInt16 e_ip;       // Initial IP value
    public UInt16 e_cs;       // Initial (relative) CS value
    public UInt16 e_lfarlc;   // File address of relocation table
    public UInt16 e_ovno;     // Overlay number

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public UInt16[] e_res1;   // Reserved words
    public UInt16 e_oemid;    // OEM identifier (for e_oeminfo)
    public UInt16 e_oeminfo;  // OEM information; e_oemid specific

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public UInt16[] e_res2;   // Reserved words
    public Int32 e_lfanew;    // File address of new exe header

    private string _e_magic {
        get {
            return new string(e_magic);
        }
    }

    public bool isValid {
        get {
            return _e_magic == "MZ";
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS32 {
    [FieldOffset(0)]
    public UInt32 Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

    private string _Signature {
        get {
            return Signature.ToString();
        }
    }

    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS64 {
    [FieldOffset(0)]
    public UInt32 Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

    private string _Signature {
        get {
            return Signature.ToString();
        }
    }

    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_FILE_HEADER {
    public UInt16 Machine;
    public UInt16 NumberOfSections;
    public UInt32 TimeDateStamp;
    public UInt32 PointerToSymbolTable;
    public UInt32 NumberOfSymbols;
    public UInt16 SizeOfOptionalHeader;
    public UInt16 Characteristics;
}

public enum MachineType : ushort {
    Unknown = 0x0000,
    I386 = 0x014c,
    R3000 = 0x0162,
    R4000 = 0x0166,
    R10000 = 0x0168,
    WCEMIPSV2 = 0x0169,
    Alpha = 0x0184,
    SH3 = 0x01a2,
    SH3DSP = 0x01a3,
    SH4 = 0x01a6,
    SH5 = 0x01a8,
    ARM = 0x01c0,
    Thumb = 0x01c2,
    ARMNT = 0x01c4,
    AM33 = 0x01d3,
    PowerPC = 0x01f0,
    PowerPCFP = 0x01f1,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    M68K = 0x0268,
    Alpha64 = 0x0284,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    EBC = 0x0ebc,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    AMD64 = 0x8664,
    ARM64 = 0xaa64,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041
}

public enum MagicType : ushort {
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
}

public enum SubSystemType : ushort {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14
}

public enum DllCharacteristicsType : ushort {
    RES_0 = 0x0001,
    RES_1 = 0x0002,
    RES_2 = 0x0004,
    RES_3 = 0x0008,
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    RES_4 = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
}

public enum DataSectionFlags : uint {
    TypeReg = 0x00000000,
    TypeDsect = 0x00000001,
    TypeNoLoad = 0x00000002,
    TypeGroup = 0x00000004,
    TypeNoPadded = 0x00000008,
    TypeCopy = 0x00000010,
    ContentCode = 0x00000020,
    ContentInitializedData = 0x00000040,
    ContentUninitializedData = 0x00000080,
    LinkOther = 0x00000100,
    LinkInfo = 0x00000200,
    TypeOver = 0x00000400,
    LinkRemove = 0x00000800,
    LinkComDat = 0x00001000,
    NoDeferSpecExceptions = 0x00004000,
    RelativeGP = 0x00008000,
    MemPurgeable = 0x00020000,
    Memory16Bit = 0x00020000,
    MemoryLocked = 0x00040000,
    MemoryPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    LinkExtendedRelocationOverflow = 0x01000000,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER32 {
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    // PE32 contains this additional field
    [FieldOffset(24)]
    public uint BaseOfData;

    [FieldOffset(28)]
    public uint ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public uint SizeOfStackReserve;

    [FieldOffset(76)]
    public uint SizeOfStackCommit;

    [FieldOffset(80)]
    public uint SizeOfHeapReserve;

    [FieldOffset(84)]
    public uint SizeOfHeapCommit;

    [FieldOffset(88)]
    public uint LoaderFlags;

    [FieldOffset(92)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(96)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(104)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY Reserved;
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER64 {
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    [FieldOffset(24)]
    public ulong ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public ulong SizeOfStackReserve;

    [FieldOffset(80)]
    public ulong SizeOfStackCommit;

    [FieldOffset(88)]
    public ulong SizeOfHeapReserve;

    [FieldOffset(96)]
    public ulong SizeOfHeapCommit;

    [FieldOffset(104)]
    public uint LoaderFlags;

    [FieldOffset(108)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(224)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(232)]
    public IMAGE_DATA_DIRECTORY Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DATA_DIRECTORY {
    public UInt32 VirtualAddress;
    public UInt32 Size;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY {
    public UInt32 Characteristics;
    public UInt32 TimeDateStamp;
    public UInt16 MajorVersion;
    public UInt16 MinorVersion;
    public UInt32 Name;
    public UInt32 Base;
    public UInt32 NumberOfFunctions;
    public UInt32 NumberOfNames;
    public UInt32 AddressOfFunctions;    // RVA from base of image
    public UInt32 AddressOfNames;        // RVA from base of image
    public UInt32 AddressOfNameOrdinals; // RVA from base of image
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_SECTION_HEADER {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
    public string Name;
    public UInt32 VirtualSize;
    public UInt32 VirtualAddress;
    public UInt32 SizeOfRawData;
    public UInt32 PointerToRawData;
    public UInt32 PointerToRelocations;
    public UInt32 PointerToLinenumbers;
    public UInt16 NumberOfRelocations;
    public UInt16 NumberOfLinenumbers;
    public DataSectionFlags Characteristics;
}
"@ -Name "Kernel32" -Namespace "Win32" -PassThru | Out-Null
    }
    process {
        Write-Host "[+] Reading all bytes from '$Path'.."
        try {
            $NtdllBytes = [IO.File]::ReadAllBytes($Path)
        } catch {
            throw "Failed to read bytes from '$($Nt.Name)' : $($_)"
        }

        Write-Host "[+] Allocating and copying buffer to unmanaged memory.."
        try {
            $AddressOfNtdll = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($NtdllBytes.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($NtdllBytes, 0, $AddressOfNtdll, $NtdllBytes.Length)
        } catch {
            throw "Failed to allocate and copy buffer : $($_)"
        }

        Write-Host "[+] Getting DOS and NT headers.."
        try {
            $DOSHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfNtdll, [type][Win32.Kernel32+IMAGE_DOS_HEADER])
            if ($null -eq $DOSHeader) {
                throw "Failed to get DOS header"
            }
            $DOSHeader | Format-Table | Out-String | Write-Verbose

            $AddressOfNTHeaders = [System.IntPtr]::Add($AddressOfNtdll, $DOSHeader.e_lfanew)
            $NTHeaders = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfNTHeaders, [type][Win32.Kernel32+IMAGE_NT_HEADERS64])
            if ($null -eq $NTHeaders) {
                throw "Failed to get NT headers"
            }
            $NTHeaders | Format-Table | Out-String | Write-Verbose
            $NTHeaders.FileHeader | Format-Table | Out-String | Write-Verbose
            $NTHeaders.OptionalHeader | Format-Table | Out-String | Write-Verbose
        } catch {
            throw $_
        }

        $SizeOfNTHeaders = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32.Kernel32+IMAGE_NT_HEADERS64])
        $SizeOfImageSectionHeaders = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32.Kernel32+IMAGE_SECTION_HEADER])

        Write-Host "[+] Getting all section headers.."
        try {
            $SectionHeaders = New-Object PSObject[]($NTHeaders.FileHeader.NumberOfSections)
            $AddressOfFirstSection = [System.IntPtr]::Add($AddressOfNTHeaders, $SizeOfNTHeaders)
            foreach ($i in 0..($NTHeaders.FileHeader.NumberOfSections - 1)) {
                $SectionHeaders[$i] = [System.Runtime.InteropServices.Marshal]::PtrToStructure(([IntPtr]::Add($AddressOfFirstSection, ($i * $SizeOfImageSectionHeaders))), [type][Win32.Kernel32+IMAGE_SECTION_HEADER])
            }
            $SectionHeaders | Format-Table | Out-String | Write-Verbose
        } catch {
            throw "Failed to get section header : $($_)"
        }

        Write-Host "[+] Locating the export address table.."
        try {
            $ExportDirectoryRVA = [System.IntPtr]::New($NTHeaders.OptionalHeader.ExportTable.VirtualAddress)
            $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $ExportDirectoryRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $ExportDirectoryRVA.ToInt64() }
            $ExportDirectoryOffset = $ExportDirectoryRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $ImageExportDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStructure([System.IntPtr]::Add($AddressOfNtdll, $ExportDirectoryOffset), [type][Win32.Kernel32+IMAGE_EXPORT_DIRECTORY])
            if ($null -eq $ImageExportDirectory) {
                throw "Failed to get ImageExportDirectory structure"
            }
            $ImageExportDirectory | Format-Table | Out-String | Write-Verbose
        } catch {
            # If the $Path is a EXE the script should crash here. Could do '($NTHeaders.FileHeader.Characteristics -band 0x2000)' above to validiate it's a DLL.
            throw "Failed to locate the image export directory : $($_)"
        }

        Write-Host "[+] Calculating offsets to exported functions.."
        try {
            $AddressOfFunctionsRVA = [System.IntPtr]::new($ImageExportDirectory.AddressOfFunctions)
            $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $AddressOfFunctionsRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $AddressOfFunctionsRVA.ToInt64() }
            $AddressOfFunctionsOffset = $AddressOfFunctionsRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $AddressOfFunctions = [System.IntPtr]::Add($AddressOfNtdll, $AddressOfFunctionsOffset)

            $AddressOfNamesRVA = [System.IntPtr]::new($ImageExportDirectory.AddressOfNames)
            $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $AddressOfNamesRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $AddressOfNamesRVA.ToInt64() }
            $AddressOfNamesOffset = $AddressOfNamesRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $AddressOfNames = [System.IntPtr]::Add($AddressOfNtdll, $AddressOfNamesOffset)

            $AddressOfNameOrdinalsRVA = [System.IntPtr]::new($ImageExportDirectory.AddressOfNameOrdinals)
            $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $AddressOfNameOrdinalsRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $AddressOfNameOrdinalsRVA.ToInt64() }
            $AddressOfNameOrdinalsOffset = $AddressOfNameOrdinalsRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $AddressOfNameOrdinals = [System.IntPtr]::Add($AddressOfNtdll, $AddressOfNameOrdinalsOffset)
            [PSCustomObject]@{
                AddressOfFunctions    = "{0:X16}" -f [long]$AddressOfFunctions
                AddressOfNames        = "{0:X16}" -f [long]$AddressOfNames
                AddressOfNameOrdinals = "{0:X16}" -f [long]$AddressOfNameOrdinals
            } | Format-Table | Out-String | Write-Verbose
        } catch {
            throw "Failed to calculate offsets : $($_)"
        }

        $SyscallResults = @()
        # Ternary operator introduced in PS7 :(
        Write-Host "[+] Getting the syscall ID for $(if ($Functions) { $Functions.Count } else { "all" }) functions.."
        try {
            for ($i = 0; $i -lt $ImageExportDirectory.NumberOfNames; $i++) {
                Write-Progress -Activity "Iterating through the exported functions.." -Status "$i/$($ImageExportDirectory.NumberOfNames) Completed" -PercentComplete (($i / $ImageExportDirectory.NumberOfNames) * 100)
                $FunctionNameRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($AddressOfNames, 4 * $i))
                $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $FunctionNameRVA -and ($_.VirtualAddress + $_.VirtualSize) -gt $FunctionNameRVA }
                $FunctionNameOffset = $FunctionNameRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
                $FunctionNameAddr = [System.IntPtr]::Add($AddressOfNtdll, $FunctionNameOffset)
                $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNameAddr)

                if ($FunctionName -notmatch '^(Nt|Zw)') {
                    continue
                }

                $NameOrdinalRVA = [System.Runtime.InteropServices.Marshal]::ReadInt16([System.IntPtr]::Add($AddressOfNameOrdinals, 2 * $i))

                $FunctionAddressRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($AddressOfFunctions, $NameOrdinalRVA * 4))
                $RVAInSection = $SectionHeaders | Where-Object { $_.VirtualAddress -le $FunctionAddressRVA -and ($_.VirtualAddress + $_.VirtualSize) -gt $FunctionAddressRVA }
                $FunctionAddressOffset = $FunctionAddressRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
                $FunctionAddress = [System.IntPtr]::Add($AddressOfNtdll, $FunctionAddressOffset)

                # The syscall ID is 2 bytes
                $FirstByte = "0x{0:X2}" -f [long]([System.Runtime.InteropServices.Marshal]::ReadByte([System.IntPtr]::Add($FunctionAddress, 4)))
                $SecondByte = "0x{0:X2}" -f [long]([System.Runtime.InteropServices.Marshal]::ReadByte([System.IntPtr]::Add($FunctionAddress, 5)))

                $FunctionSyscallID = "0x{0:X2}" -f [System.BitConverter]::ToUInt16(($FirstByte, $SecondByte), 0)

                $SyscallResults += [PSCustomObject]@{
                    Function  = $FunctionName
                    SyscallID = $FunctionSyscallID
                }
            }
        } catch {
            throw "Failed to grab function SyscallIDs : $($_)"
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AddressOfNtdll)

        if ($Functions) {
            $SyscallResults | Where-Object Function -in $Functions
        } else {
            $SyscallResults
        }
    }
    end {
        Write-Verbose "End $($MyInvocation.MyCommand)"
    }
}