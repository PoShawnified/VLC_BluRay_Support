#Requires -Version 5.0

<#
  .Synopsis
    Blu-ray for VLC
  .DESCRIPTION
    Long description
  .EXAMPLE
    .\install.ps1
  .EXAMPLE
    @Params = @{
    VLCPath                    = "C:\Apps\VLC\" 
    BDPlusTablesArchive        = '.\2022-01-01_bdplus_tables.7z',
    BDPlusTablesUpdateArchives = (Get-Childitem C:\Tables_update\*.7z).Name
    Language                   = 'spa'
    PerUser                    = $true
    Verbose                    = $true
    }
    .\install.ps1
  .NOTES
    Usage: 

      The script will download the keydb_xxx.zip file at run time, but you may also specify a keydb zip as a param. 

      Prep:
        - Create directory
        - Place 'install.ps1' into directory
        - Place 7z.exe and 7z.dll into directory
        - Place '*libaacs*.7z' and '*bdplus_tables*.7z' archives into directory
        - Place vm0.zip archive into directory
        - Modify parameters with correct file names (or pass updated file names as params at the command-line)
    
      Execute:
        - *AS ADMINISTRATOR*, run PowerShell.exe (or PowerShell_ise.exe)
        - CD into directory
        - Execute: .\install.ps1 <params>

    ----------------------------

    Manual Instructions:

      How To (Windows):
          Put the 32-bit or 64-bit libaacs/libbdplus DLLs (all 4) in the corresponding VLC directory:
          Put the BD+ vm files in the %APPDATA%\bdplus\vm0 directory
          Put the cached BD+ tables (1.5GB) in the %APPDATA%\bdplus\convtab directory
              updated tables 2020-07-05 (36MB)
              updated tables 2021-01-06 (31MB)
          Put the FindVUK KEYDB.cfg in the %APPDATA%\aacs directory
          Edit the KEDYB.cfg and put the keys and certs from this post (https://forum.doom9.org/showthread.php?p=1883655#post1883655) on top

      Directory locations:
          VLC DLLs:
              dll 32-bit: C:\Program Files (x86)\VideoLAN\VLC
              dll 64-bit: C:\Program Files\VideoLAN\VLC

          If System:
              aacs (system wide): %ProgramData%\aacs
              bdplus (system wide): %ProgramData%\bdplus
        
          If User: 
              aacs (per user): %APPDATA%\aacs
              bdplus (per user): %APPDATA%\bdplus
#>

[cmdletbinding()]
param (

  [string]$SevenZexePath = "$PSScriptRoot\7zip\7z.exe",

  [String]$LibAacsArchive = "$PSScriptRoot\2020-07-26_libaacs_libbdplus.7z",

  [string]$BDPlusVM0Archive = "$PSScriptRoot\vm0.zip",

  [string]$BDPlusTablesArchive = "$PSScriptRoot\2019-09-29_bdplus_tables.7z",

  [string[]]$BDPlusTablesUpdateArchives = ("$PSScriptRoot\2020-07-05_bdplus_tables_update.7z", "$PSScriptRoot\2021-01-06_bdplus_tables_update.7z"),

  [ValidateScript({$_ -match "^[a-zA-Z]{3}$"})]
  [string]$Language = (Get-Culture).ThreeLetterISOLanguageName,

  [switch]$PerUser

)

#region - Functions
  function Get-VLCInfo {

    [cmdletbinding()]
    param()

    Write-Verbose -Message "Get-VLCInfo: Begin"

    if ($vlcPath = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VLC media player').InstallLocation){

      $vlcBitness = 64

      Write-Verbose "Checking for 64-bit VLC"

    }
    elseif ($vlcPath = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VLC media player').InstallLocation){

      $vlcBitness = 32

      Write-Verbose "Checking for 64-bit VLC"

    }
    else {
    
      Write-Error "Could not locate VLC."
    
    }

    Write-Verbose "Found VLC at: $vlcPath. Setting bitness to $vlcBitness"

    [pscustomobject]@{
      Path    = $vlcPath
      Bitness = $vlcBitness
    }

    Write-Verbose -Message "Get-VLCInfo: Complete"

  }

  function Install-LibAACS {
  
    [cmdletbinding()]
    param (
    
      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).extension -eq '.7z'})]
      [string]$LibAacsArchive,

      [parameter(mandatory=$true)]
      [string]$VLCPath,

      [parameter(mandatory=$true)]
      [validateset(32,64)]
      [int]$VLCArchitecture,

      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).Name -eq '7z.exe'})]
      [string]$SevenZexePath
    
    )
    
    Write-Verbose -Message "Install-LibAACS: Begin"

    # Get full archive file details
    Write-Verbose -Message "Collecting file details"
    $LibAacsArchiveObj = Get-Item $LibAacsArchive

    # Create container 
    try { 
      
      $libAacsUnpackDir = New-Item -Path $env:TEMP -Name ([guid]::NewGuid().Guid) -ItemType Directory 
      
      Write-Verbose -Message "Created temp dir: $($libAacsUnpackDir.FullName)"

    }
    catch { Write-Error "Failed to create temporary unpack directory: : $($_.Nessage)" }

    # unpack
    $procArgs = @{
      FilePath               = $SevenZexePath 
      ArgumentList           = "x -aoa -o""$($libAacsUnpackDir.FullName)"" ""$($LibAacsArchiveObj.FullName)""" 
      PassThru               = $true
      NoNewWindow            = $true
      Wait                   = $true
      RedirectStandardOutput = "$libAacsUnpackDir\7z.log" 
      RedirectStandardError  = "$libAacsUnpackDir\7zErr.logs"
    }
    Write-Verbose -Message "Starting unpack: $($LibAacsArchiveObj.Name)" 
    $7zRetCode = Start-Process @procArgs

    if ($7zRetCode.ExitCode -ne 0){

      Write-Error "7z.exe failed to unpack files (Return code: $($7zRetCode.ExitCode)). 7z logs are located in: $libAacsUnpackDir"

    }

    # Locate correct files for our architecture
    Write-Verbose -Message "Searching unpacked archive for correct files." 
    $libSource = (Get-childItem -Recurse -Directory $libAacsUnpackDir | ? Name -eq "win$($VLCArchitecture)").FullName

    # Copy to VLC
    try { 
      
      Write-Verbose -Message "Copying: $libSource  -->  $VLCPath" 
      $null = Copy-Item -Path "$libSource\*" -Destination $VLCPath -Recurse -Force
      
    }
    catch { Write-Error "Failed to copy files to VLC directory: $($_.Nessage)" }

    # Cleanup temp files
    try { 
      
      Write-Verbose -Message "Cleaning up temp dir: $libAacsUnpackDir"
      Remove-Item -LiteralPath $libAacsUnpackDir -Recurse -Force 
      
    }
    catch {Write-Warning "Failed to remove temporary files located in: $libAacsUnpackDir : $($_.Nessage)"}

    Write-Verbose -Message "Install-LibAACS: Complete"

  }

  function Install-BDPlusTables {
  
    [cmdletbinding()]
    param (
    
      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).extension -eq '.7z'})]
      [string]$BDPlusTablesArchive,

      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).Name -eq '7z.exe'})]
      [string]$SevenZexePath,

      [switch]$PerUser
    
    )

    Write-Verbose -Message "Install-BDPlusTables: Begin"

    # Get full archive file details
    Write-Verbose -Message "Collecting file details"
    $BDPlusTablesArchiveObj = Get-Item $BDPlusTablesArchive

    # Set base dir
    if ($PerUser){ $BasePath = $env:APPDATA }
    else { $BasePath = $env:ProgramData }

    # Create dir
    try {
  
      if (!(Get-ChildItem $BasePath -Name 'bdplus' -Directory -ErrorAction SilentlyContinue)){

        Write-Verbose -Message "Creating bdplus directory."
        $null = New-Item -Path $BasePath -Name bdplus -ItemType Directory

      }
  
    }
    catch { Write-Error "Could not create bdplus directory: $($_.Nessage)" }

    # unpack
    $ProcArgs = @{
      FilePath               = $SevenZexePath
      ArgumentList           = "x -aoa -o""$BasePath\bdplus"" $($BDPlusTablesArchiveObj.FullName)" 
      PassThru               = $true 
      NoNewWindow            = $true 
      Wait                   = $true 
      RedirectStandardOutput = "$env:temp\7z-bdplus.log" 
      RedirectStandardError  = "$env:temp\7z-bdplusErr.log"
    }
    Write-Verbose -Message "Starting direct to destination unpack for: $($BDPlusTablesArchiveObj.Name)" 
    $7zRetCode = Start-Process @ProcArgs

    if ($7zRetCode.ExitCode -ne 0){

      Write-Error "7z.exe failed to unpack bdplus files (Return code: $($7zRetCode.ExitCode)). 7z logs are located in: $env:temp"

    }

    Write-Verbose -Message "Install-BDPlusTables: Complete"
  
  }

  function Update-BDPlusTables {
  
    [cmdletbinding()]
    param (
    
      [parameter(mandatory=$true)]
      [ValidateScript({
        $_ | ForEach-Object {(Get-Item $_).extension -eq '.7z'}
      })]
      [string[]]$BDPlusTablesUpdateArchives,

      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).Name -eq '7z.exe'})]
      [string]$SevenZexePath,

      [switch]$PerUser
    
    )

    Write-Verbose -Message "Update-BDPlusTables: Begin"

    # Set base dir
    if ($PerUser){ $BasePath = $env:APPDATA }
    else { $BasePath = $env:ProgramData }

    # Get full archive file details
    Write-Verbose -Message "Collecting file details"
    $BDPlusTablesUpdateArchivesObj = $BDPlusTablesUpdateArchives | Get-Item

    # Create dir
    try {
  
      if (!(Get-ChildItem $BasePath -Name 'bdplus' -Directory -ErrorAction SilentlyContinue)){
        
        Write-Verbose -Message "Creating bdplus directory."
        $null = New-Item -Path $BasePath -Name bdplus -ItemType Directory

      }
  
    }
    catch { Write-Error "Could not bdplus directory: $($_.Nessage)" }

    $BDPlusTablesUpdateArchivesObj | Sort-Object BaseName | ForEach-Object { 

      # unpack
      $ProcArgs = @{
        FilePath               = $SevenZexePath
        ArgumentList           = "x -aoa -o""$BasePath\bdplus"" $($_.FullName)" 
        PassThru               = $true 
        NoNewWindow            = $true 
        Wait                   = $true 
        RedirectStandardOutput = "$env:temp\7z-$($_.BaseName).log" 
        RedirectStandardError  = "$env:temp\7z-$($_.BaseName)Err.log"
      }
      Write-Verbose -Message "Starting direct to destination unpack for: $($_.Name)" 
      $7zRetCode = Start-Process @ProcArgs

      if ($7zRetCode.ExitCode -ne 0){

        Write-Error "7z.exe failed to unpack bdplus files (Return code: $($7zRetCode.ExitCode)). 7z logs are located in: $env:temp"

      }

    }

    Write-Verbose -Message "Update-BDPlusTables: Complete"
  
  }

  function Install-BDPlusVM0 {
  
    [cmdletbinding()]
    param (
    
      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).extension -eq '.zip'})]
      [string]$BDPlusVM0Archive,

      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).Name -eq '7z.exe'})]
      [string]$SevenZexePath,

      [switch]$PerUser
    
    )

    Write-Verbose -Message "Install-BDPlusVM0: Begin"

    # Get full archive file details
    $BDPlusVM0ArchiveObj = Get-Item $BDPlusVM0Archive

    # Set base dir
    if ($PerUser){ $BasePath = $env:APPDATA }
    else { $BasePath = $env:ProgramData }

    $BasePath = "$BasePath\bdplus"

    # Create dir
    try {
  
      if (!(Get-ChildItem $BasePath -Name 'vm0' -Directory -ErrorAction SilentlyContinue)){
        
        Write-Verbose -Message "Creating vm0 directory."
        $null = New-Item -Path $BasePath -Name vm0 -ItemType Directory -Force

      }
  
    }
    catch { Write-Error "Could not create vm0 directory: $($_.Nessage)" }

    # unpack
    $ProcArgs = @{
      FilePath               = $SevenZexePath
      ArgumentList           = "x -aoa -o""$BasePath\vm0"" $($BDPlusVM0ArchiveObj.FullName)" 
      PassThru               = $true 
      NoNewWindow            = $true 
      Wait                   = $true 
      RedirectStandardOutput = "$env:temp\7z-vm0.log" 
      RedirectStandardError  = "$env:temp\7z-vm0Err.log"
    }
    Write-Verbose -Message "Starting direct to destination unpack for: $($BDPlusVM0ArchiveObj.Name)" 
    $7zRetCode = Start-Process @ProcArgs

    if ($7zRetCode.ExitCode -ne 0){

      Write-Error "7z.exe failed to unpack vm0 files (Return code: $($7zRetCode.ExitCode)). 7z logs are located in: $env:temp"

    }

    Write-Verbose -Message "Install-BDPlusVM0: Complete"
  
  }

  function Install-KeyDB { 

    [cmdletbinding()]
    param (
    
      [ValidateScript({[regex]::match($_, "^[a-zA-z]{3}$").Success})]
      [string]$Language = 'eng',

      [ValidateScript({(Get-Item $_).Name -match '^keydb_[a-zA-Z]{3}.zip$'})]
      [string]$KeyDBZipArchive,

      [parameter(mandatory=$true)]
      [ValidateScript({(Get-Item $_).Name -eq '7z.exe'})]
      [string]$SevenZexePath,

      [switch]$PerUser,

      [switch]$SuppressProgress
    
    )

    Write-Verbose -Message "Install-KeyDB: Begin"
    
    # Set base dir
    if ($PerUser){ $BasePath = $env:APPDATA }
    else { $BasePath = $env:ProgramData }

    # Progress bar
    if ($SuppressProgress){ 
    
      Write-Verbose -Message "Suppressing progress bar"  
      $ProgressPreference = "SilentlyContinue" 
      
    }

    # Create container 
    try { 
      
      # Create temp dir declare zip file path/name
      $keyDBTempDir = New-Item -Path $env:TEMP -Name ([guid]::NewGuid().Guid) -ItemType Directory 
      $keyDBZip = "$keyDBTempDir\keydb.zip"
      
      Write-Verbose -Message "Created temp dir: $($keyDBTempDir.FullName)"
      
    }
    catch { Write-Error "Failed to create temporary unpack directory: $($_.Nessage)" }

    # If we're using a provided keydb.zip, copy it to temp and rename. Otherwise, download the zip.
    if ($KeyDBZipArchive){
      
      try { 
      
        $KeyDBZipArchiveObj = Get-Item $KeyDBZipArchive
        Copy-Item -LiteralPath $KeyDBZipArchiveObj.FullName -Destination $keyDBZip -Force
        
      }
      catch { Write-Error "Failed to copy provided Key DB zip file for unpacking: $($_.Nessage)" }

    }
    else{

      try {
  
        Write-Warning -Message "Attempting to download Key DB zip file. Be paatient, this might take a few min..."

        Invoke-WebRequest "http://fvonline-db.bplaced.net/fv_download.php?lang=$Language" -OutFile $keyDBZip -ContentType "application/octet-stream"
     
       }
       catch{ Write-Error "Failed to download Key DB zip file: $($_.Nessage)"}

    }

    # Unpack
    try { 

      $ProcArgs = @{
        FilePath               = $SevenZexePath 
        ArgumentList           = "x -aoa -o""$($keyDBTempDir.FullName)"" $keyDBZip" 
        PassThru               = $true
        NoNewWindow            = $true 
        Wait                   = $true 
        RedirectStandardOutput = "$keyDBTempDir\7z.log" 
        RedirectStandardError  = "$keyDBTempDir\7zErr.logs"
      }
      Write-Verbose -Message "Starting unpack: $keyDBZip" 
      $7zRetCode = Start-Process @ProcArgs

      if ($7zRetCode.ExitCode -ne 0){

        Write-Error "7z.exe failed to unpack files (Return code: $($7zRetCode.ExitCode)). 7z logs are located in: $keyDBTempDir"

      }

    }
    catch {

      Write-Error "Could not download KeyDB zip file: $($_.Nessage)"

    }

    # IF DL/unpack success: copy to location
    try {
  
      if (!(Get-ChildItem $BasePath -Name 'aacs' -Directory -ErrorAction SilentlyContinue)){

        Write-Verbose -Message 'Creating aacs directory'
        $null = New-Item -Path $BasePath -Name aacs -ItemType Directory

      }

      Write-Verbose -Message "Copying $($keyDBTempDir.FullName)\keydb.cfg  -->  $BasePath\aacs"
      Copy-Item -LiteralPath "$($keyDBTempDir.FullName)\keydb.cfg" -Destination "$BasePath\aacs" -Force
  
    }
    catch { Write-Error "Failed to copy keydb.cfg: $($_.Nessage)" }
    
    # Cleanup temp files
    try { 
    
      Write-Verbose -Message "Cleaning up temp dir: $keyDBTempDir" 
      Remove-Item -LiteralPath $keyDBTempDir -Recurse -Force 
      
    }
    catch {Write-Warning "Failed to remove temporary files located in: $($keyDBTempDir.FullName): $($_.Nessage)"}

    Write-Verbose -Message "Install-KeyDB: Complete"

  }

  function isAdmin {
    <#
    .SYNOPSIS
        Checks if the user invoking the PowrShell process/script/ISE/IDE is an administrator on the local system
    .DESCRIPTION
        Returns True if the caller has administrative privileges. Returns False if they don't.
    #>
    [OutputType([System.Boolean])]
    param ()
    
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $principal.IsInRole($admin)
  }
#endregion - Functions


#region - Setup / Checks

  # Set error action to stop
  $ErrorActionPreference = 'Stop'

  # Check for admin rights
  if (!(isAdmin)){ Write-Error "Not running as an admistrator/elevated. Exiting..." }

  # Verify Archive exists
  try { $null = Get-ChildItem -LiteralPath $LibAacsArchive }
  catch {  Write-Error "Could not locate archive for: libaacs_libaacsplus: $($_.Nessage)" }

  # Verify Archive exists
  try { $null = Get-ChildItem -LiteralPath $BDPlusVM0Archive }
  catch {  Write-Error "Could not locate archive for: libaacs_libaacsplus: $($_.Nessage)" }

  # Verify Archive exists
  try { $null = Get-ChildItem -LiteralPath $BDPlusTablesArchive }
  catch { Write-Error "Could not locate archive for: BD+ Tables: $($_.Nessage)" }

  # Verify Archives exist
  try { $null = $BDPlusTablesUpdateArchives | Get-Item }
  catch { Write-Error "Could not locate archive for: BD+ Tables update: $($_.Nessage)" }

  # Verify VLC path exists
  if (!($VLCInfoObj = Get-VLCInfo)){
  
    Write-Error "Could not locate VLC install info: $($_.Nessage)"
    break

  }

$deviceKeyBlob = @'
; KEYDB.cfg

; Contents:
; - Device Keys: 15
; - Processing Keys: 29
; - Host Certificates: 10

; Device Keys
| DK | DEVICE_KEY 0xAA856A1BA814AB99FFDEBA6AEFBE1C04 | DEVICE_NODE 0x0018 | KEY_UV 0x00000001 | KEY_U_MASK_SHIFT 0x17 ; MKBv01
| DK | DEVICE_KEY 0x810827A76E5B2CC1685E3217A23E2186 | DEVICE_NODE 0x0100 | KEY_UV 0x00000100 | KEY_U_MASK_SHIFT 0x17 ; MKBv01-MKBv12
| DK | DEVICE_KEY 0x44145A846F19D096F2C84A2E50C5C4F5 | DEVICE_NODE 0x0200 | KEY_UV 0x00000280 | KEY_U_MASK_SHIFT 0x09 ; MKBv14-MKBv16
| DK | DEVICE_KEY 0xEB55A475080FBCF18534EFA0839A7373 | DEVICE_NODE 0x0340 | KEY_UV 0x00000340 | KEY_U_MASK_SHIFT 0x08 ; MKBv17-MKBv19
| DK | DEVICE_KEY 0xFB4AC39009E82113D45ECF4B7EAEA467 | DEVICE_NODE 0x0388 | KEY_UV 0x00000384 | KEY_U_MASK_SHIFT 0x07 ; MKBv20-MKBv21
| DK | DEVICE_KEY 0x8BF4FBD91A7FB7DB8576D1E5A15A8544 | DEVICE_NODE 0x0388 | KEY_UV 0x00000384 | KEY_U_MASK_SHIFT 0x05 ; MKBv22-MKBv30
| DK | DEVICE_KEY 0xA088BC72424478EACAF237A9E258351E | DEVICE_NODE 0x0400 | KEY_UV 0x00000200 | KEY_U_MASK_SHIFT 0x17 ; MKBv01-MKBv23
| DK | DEVICE_KEY 0x5FB86EF127C19C171E799F61C27BDC2A | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17 ; MKBv01-MKBv48
| DK | DEVICE_KEY 0x6C02A9C4DF6DE9314F6F4BB44677BD67 | DEVICE_NODE 0x0600 | KEY_UV 0x00000500 | KEY_U_MASK_SHIFT 0x0A ; MKBv24-MKBv35
| DK | DEVICE_KEY 0x4D84E4D6D434A08D6EF0B523B6D891B2 | DEVICE_NODE 0x0700 | KEY_UV 0x00000680 | KEY_U_MASK_SHIFT 0x09 ; MKBv36-MKBv43
| DK | DEVICE_KEY 0xF2F56575C0C5448042298FA9B316AB9A | DEVICE_NODE 0x0710 | KEY_UV 0x00000714 | KEY_U_MASK_SHIFT 0x04 ; MKBv44-MKBv51
| DK | DEVICE_KEY 0x31A194B61D3119D2B09DC0D8B9A73A00 | DEVICE_NODE 0x0880 | KEY_UV 0x00000840 | KEY_U_MASK_SHIFT 0x0B ; MKBv49-MKBv52
| DK | DEVICE_KEY 0x25F9782764D026413C3D4868F891E81E | DEVICE_NODE 0x0884 | KEY_UV 0x000008A0 | KEY_U_MASK_SHIFT 0x07 ; MKBv53-MKBv54
| DK | DEVICE_KEY 0xFDAD855E9A89E5335288AF2805DC0497 | DEVICE_NODE 0x08F0 | KEY_UV 0x000008FC | KEY_U_MASK_SHIFT 0x04 ; MKBv55-MKBv57
| DK | DEVICE_KEY 0x7FD1F7966AD2B0E4F4901205E32A69BA | DEVICE_NODE 0x0A00 | KEY_UV 0x00000900 | KEY_U_MASK_SHIFT 0x0B ; MKBv49-MKBv62

; Processing Keys
| PK | 0x09F911029D74E35BD84156C5635688C0 ; MKBv01
| PK | 0x455FE10422CA29C4933F95052B792AB2 ; MKBv03
| PK | 0x973940BB180E83266231EE596CEF65B2 ; MKBv03-MKBv12
| PK | 0xF190A1E8178D80643494394F8031D9C8 ; MKBv04
| PK | 0x7A5F8A09F833F7221BD41FA64C9C7933 ; MKBv06-MKBv08
| PK | 0xC87294CE84F9CCEB5984B547EEC18D66 ; MKBv09
| PK | 0x452F6E403CDF10714E41DFAA257D313F ; MKBv10
| PK | 0x58EBDADF88DCC93304CBBEDB9EE095F6 ; MKBv14-MKBv16
| PK | 0xCC72242D4CC8156B960502805987DED0 ; MKBv14-MKBv23
| PK | 0x465FA8BE828509014D05D2FCCEFF35D2 ; MKBv17
| PK | 0xAD5E546C46D72DC083AEB5686924E1B3 ; MKBv18-MKBv19
| PK | 0x53FCE78ECD352DA50D526B5EE3D3D96B ; MKBv20-MKBv21
| PK | 0xC32238976FF44A51E2D33553CFE85772 ; MKBv22-MKBv30
| PK | 0x3ADE0AB7C9E4270055506C449E8EE6CF ; MKBv24-MKBv48
| PK | 0xD11E3DBA323D37DE3DE0D6A0DC5EC807 ; MKBv24-MKBv25
| PK | 0xAAAF8A16F829DA16A124D837F64EE2D8 ; MKBv26-MKBv28
| PK | 0xC0F535929D59CD071BEE9CB53F0C21C2 ; MKBv30-MKBv35
| PK | 0x99AB6AE0A7E13504CE284B7CA401B26A ; MKBv31-MKBv36
| PK | 0x19DF7DA3A1FB75AC4DC34CCB6AF6A5C7 ; MKBv36-MKBv38
| PK | 0x3FB9D3314AAC7F76581190A624A5C578 ; MKBv39-MKBv43
| PK | 0x186D1BBA19487F6450C1FD5ADA9407E6 ; MKBv44-MKBv51
| PK | 0xF2C416A45D806D964F567B5D7FED209D ; MKBv49-MKBv52
| PK | 0x7A8BAB1B0C66C39D1A2EEE6883E4DD3C ; MKBv53-MKBv54
| PK | 0x1F70D403A6D39B20A3F7131750ACAA22 ; MKBv53-MKBv54
| PK | 0x8FBDD8452146552EF76136B0A348590B ; MKBv55-MKBv57
| PK | 0x0EB5F81CF17405CAFDB97832F5EA11B4 ; MKBv55-MKBv62
| PK | 0x76DDD7093216D28C15049A6B9C5C18B9 ; MKBv63
| PK | 0x3B323C7A9AFC0921831D247239823DE6 ; MKBv64-MKBv65
| PK | 0x7A4F40D8696B7B159BE8176CC9EDB85C ; MKBv66-MKBv68

; Host Certificates
| HC | HOST_PRIV_KEY 0x909250D0C7FC2EE0F0383409D896993B723FA965 | HOST_CERT 0x0203005CFFFF800001C100003A5907E685E4CBA2A8CD5616665DFAA74421A14F6020D4CFC9847C23107697C39F9D109C8B2D5B93280499661AAE588AD3BF887C48DE144D48226ABC2C7ADAD0030893D1F3F1832B61B8D82D1FAFFF81 ; Revoked in MKBv72
| HC | HOST_PRIV_KEY 0x5924778E74CC2B18B95BAE7D93A09505B1BF08CE | HOST_CERT 0x0201005CFFFF800001B100005F1407EDBF9D1CD38F33A625209B5ED10D48F71E2AB2A1C53CCF9E25D6AEB4BEE968FBBD10DC44064841C358106731589A2C12DD5B4D86FE840D2C6525594E72A19C2EDBC3DD6A28F75E9A9C00D684BB ; Revoked in MKBv70
| HC | HOST_PRIV_KEY 0x5F291AE7CF68D67F58689A4CBFE2953064539FAA | HOST_CERT 0x0203005CFFFF8000018900003E7C4B0931C0045DFB017F24B1557F5BD0AF5B961FBC1B43519F9023A1E84A3E8C06967B76469CC86527AA3807258C58E00F73971F9BC8353165476454911E3A9D07D742980598BFF9B3DF5EA18E0C7F ; Revoked in MKBv63
| HC | HOST_PRIV_KEY 0x27263F402E2D6DB56B1FB7BB4524C6CD5C9F2EF4 | HOST_CERT 0x0201005CFFFF800001460000952D611B06911B0EAEE577D3715D1FA0E405914068752559DFBD845CB80F4FEE04A40B8FED842ACB78F9F898AEC395409E929C55A20A7EE853509BB84D8FB0DC99E5CAC5F239F0CD79B38C0678702B1C ; Revoked in MKBv58
| HC | HOST_PRIV_KEY 0x0F7B481182425FC4C32CDDE612DD05B1BD7863D6 | HOST_CERT 0x0203005CFFFF800000AD00005F27B91F047E60C251F4262DE74EC061F9261DCE3254EB737EDED53AD84E12805BBEEDB12C285A61627A529129BD98F8590634CF35A9820CD213D5AF786BDE489EC37A75D4D444B8AB40923E317169E9 ; Revoked in MKBv51
| HC | HOST_PRIV_KEY 0x88B245EA25315F46E6E99D9D521EB1194454A82D | HOST_CERT 0x0201005CFFFF800000C400005BF6843ED1AA9C9DEEFEAD8174479C72AB5457691EEB75669105BB195D4B9133069A18FD5357797116CEC22D7FE8F366C2A092E1D00DB770E9E01DB687456B6FBFA28C962D88F05DD43F584ECC821AF7 ; Revoked in MKBv46
| HC | HOST_PRIV_KEY 0x668C9A75EEFC8DA4261938E271285061BB09F0DD | HOST_CERT 0x0201005CFFFF80000039000065EAC9878B85EFF4D77A62B1D600024ACE68DD3366880E4F844F34B77A050135A20E73B626DAEA5157B32EB84BC6E87B0DEE4D833CEADA86120151002C3C66D5256F71CFA68B7E55BA1B351F3403434E ; Revoked in MKBv32
| HC | HOST_PRIV_KEY 0x567A6A8EFFFD8967651CF1BB8D15EDB6D2463555 | HOST_CERT 0x0200005CFFFF0000006400006440BE797538E4FC369FC50BBE9F95CC694338210CDFACE0D2C878BAB96BB72BA5A29D0F7D2E9B836B4CE06781D933544E6258F1F38668B4733F24638CCB6F5B71220A2220217367F833635E97784D9E ; Revoked in MKBv22
| HC | HOST_PRIV_KEY 0x8C8647FE2A70EF0388EA9E43F432CC441C6B108C | HOST_CERT 0x0200005CFFFF000000AE00004142A5411F1E63F185581C876B939FB40B523BF69C004CA69E047606EE5183C0ABEF1E7D04CB6E65260677E7B0573D08E60957935503ED78F7E27B190B4A7CAFCBAFF4A2836453ECF72E49668DAF1DB9 ; Revoked in MKBv17
| HC | HOST_PRIV_KEY 0x4737676058D7029452514F0AB186DC4CCA8C578F | HOST_CERT 0x0200005CFFFF0000000C00006E3DEB679B9A16ADFAA8E30878767BA6EB2A9B415385AD1181B4446C31E9A5DD2AB808B364FF15885BAC490964318C9BF8029FCF76F688A54FBDA03F6D9332EF04E5A61312DA85880A4D9CBB79D8602E ; Revoked in MKBv03

; Insert Disc Keys Here

'@
#endregion - Setup / Checks


#region - Process
  # Put the 32-bit or 64-bit libaacs/libbdplus DLLs (all 4) in the corresponding VLC directory:
  Install-LibAACS -LibAacsArchive $LibAacsArchive -VLCPath $VLCInfoObj.Path -VLCArchitecture $VLCInfoObj.Bitness -SevenZexePath $SevenZexePath


  # BD+ VM - Put the BD+ vm files in the bdplus\vm0 directory
  Install-BDPlusVM0 -BDPlusVM0Archive $BDPlusVM0Archive -PerUser:$PerUser -SevenZexePath $SevenZexePath


  # BD+ Tables
  Install-BDPlusTables -BDPlusTablesArchive $BDPlusTablesArchive -PerUser:$PerUser -SevenZexePath $SevenZexePath


  # BD+ Tables Updates
  Update-BDPlusTables -BDPlusTablesUpdateArchives $BDPlusTablesUpdateArchives -PerUser:$PerUser -SevenZexePath $SevenZexePath


  # Put the FindVUK KEYDB.cfg in the %APPDATA%\aacs directory
  Install-KeyDB -Language $Language -PerUser:$PerUser -SevenZexePath $SevenZexePath


  #KeyDB Manual Steps - Edit the KEDYB.cfg and put the keys and certs
  # Set base dir
  if ($PerUser){ $BasePath = $env:APPDATA }
  else { $BasePath = $env:ProgramData }

  # Get file content
  $keyDBFile = "$BasePath\aacs\keydb.cfg"

  # Combine Data
  Write-Verbose -Message 'Concatenating Device Key Blob + KeyDB data'
  $keyDBFileContent = $deviceKeyBlob + (Get-content $keyDBFile -Raw)

  # Write file
  Write-Verbose -Message "Writing: $keyDBFile"
  $keyDBFileContent | Out-File $keyDBFile -Encoding utf8 -Force
#endregion - Process
