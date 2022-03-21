# VLC_BluRay_Support

## Info / Notes
### The install.ps1 script attempts a partial automation of [candela's documented steps](https://forum.doom9.org/showthread.php?p=1886086#post1886086)

The script will download the keydb_xxx.zip file at run time, but a previously downloaded zip can be passed as a param instead. 

## Prep
1. Clone repo
2. Place 7z.exe and 7z.dll into repo directory
3. Place all .7z and .zip archives (`\*libaacs\*.7z`, `\*bdplus_tables\*.7z`, `vm0.zip`) archives into repo directory
4. Modify parameters with correct file names (or pass updated file names as params at the command-line)

## Execute
1. *AS ADMINISTRATOR*, run PowerShell.exe (or PowerShell_ise.exe)
2. CD into directory
3. Execute: `.\install.ps1 <params>`

## Parameters

All parameters are optional... If the parameter defaults in the script are correct then no parameters are required and install.ps1 can be run bare. 

*`-Verbose` is, however, recommended.*

  - `-VLCPath` =  String, folder VLC is installed in

  - `-LibAacsArchive` = String, libaacs 7z archive

  - `-BDPlusVM0Archive` = String, vm0 zip file

  - `-BDPlusTablesArchive` = String, bdplus tables 7z file (~1.5Gb)

  - `-BDPlusTablesUpdateArchives` = String Array, one or more bdplus tables archives passed as an array. Script will sort these by name so, if necessary (not usually) rename ascending to alter processing order.

  - `-Language` = String, three-letter language code

  - `-PerUser` = Switch, changes output targets to User locations. Default is system locations

## Credits / Info
### Partial automation of manual steps provided here: https://forum.doom9.org/showthread.php?p=1886086#post1886086 (credit to [candela](https://forum.doom9.org/member.php?u=78000))

#### Manual Instructions:
- How To (Windows): 
    - Put the 32-bit or 64-bit libaacs/libbdplus DLLs (all 4) in the corresponding VLC directory
    - Put the BD+ vm files in the %APPDATA%\bdplus\vm0 directory
    - Put the cached BD+ tables (1.5GB) in the %APPDATA%\bdplus\convtab directory
        - updated tables 2020-07-05 (36MB)
        - updated tables 2021-01-06 (31MB)
    - Put the FindVUK KEYDB.cfg in the %APPDATA%\aacs directory
    - Edit the KEDYB.cfg and put the keys and certs from this post (https://forum.doom9.org/showthread.php?p=1883655#post1883655) on top

- Directory locations:
    - VLC DLLs:
        - dll 32-bit: C:\Program Files (x86)\VideoLAN\VLC
        - dll 64-bit: C:\Program Files\VideoLAN\VLC

    - If System:
        - aacs (system wide): %ProgramData%\aacs
        - bdplus (system wide): %ProgramData%\bdplus

    - If User: 
        - acs (per user): %APPDATA%\aacs
        - bdplus (per user): %APPDATA%\bdplus