extern crate chrono;            // DateTime manipulation
extern crate regex;
extern crate bstr;

use regex::Regex;
use std::{collections::HashSet, hash::Hash};
use crate::{data_defs::*, file_op::*, time::*};
use std::{io::Result, str};
use bstr::ByteSlice;

/* 
        use \x20 for matching spaces when using "x" directive that doesn't allow spaces in regex
        regex crate does not support look-(behind|ahead|etc.)
        fancy-regex crate does support these, but doesn't support captures_iter
            https://docs.rs/fancy-regex/0.4.0/fancy_regex/
            (?:$|\s|[/:@#&\(\]|=\\\}'\"><])
*/

pub fn report_finds(pdt: &str, re: &Regex, file: &str, text: &str, flag: &str) -> std::io::Result<(bool)> {
    let mut found = false;
    for c in re.captures_iter(text) {
        found = true;
        let line = &c[0];
        let mut tags: HashSet<String> = HashSet::new();
        tags.insert(flag.to_owned());
        TxFileContent::new(pdt.to_string(), 
            "FileContent".to_string(), 
            get_now()?, file.to_string(), line.to_string(), 
            "".to_string(), sort_hashset(tags)).report_log();
        sleep();
    }
    Ok(found)
}

pub fn found_base64(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref BASE64: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:[a-z0-9+\/]{4}){16,}(?:[a-z0-9+\/]{4}|[a-z0-9+\/]{3}=|[a-z0-9+\/]{2}={2})
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &BASE64, file, text, flag)?)
}

pub fn found_email(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref EMAIL: Regex = Regex::new(r#"(?mix)
            (:?.*   
                [a-z0-9._%+-]+@[a-z0-9._-]+\.[a-z0-9-]{2,13}
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &EMAIL, file, text, flag)?)
}


pub fn found_encoding(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref ENCODING: Regex = Regex::new(r#"(?mix)
            (:?.*
                [a-z0-9=/+&]{300}
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &ENCODING, file, text, flag)?)
}

pub fn found_hex(bytes: &Vec<u8>, find_this: &Vec<u8>) -> Result<bool> 
{
    if find_this != &[255] && bytes.find(find_this).is_some() {
        return Ok(true)
	}
    Ok(false)
}


pub fn found_ipv4(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref IPV4: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:^|\s|[&/:<>\#({\[|'"=@]|[[:^alnum:]]\\)
                    (?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[1-9])                                          
                    (?:\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])){3}
                (?:$|\s|[&/:<>\#)}\]|'"\\=@])
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &IPV4, file, text, flag)?)
}

// Should not match :: as an ipv6 addr
pub fn found_ipv6(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref IPV6: Regex = Regex::new(r#"(?mix)
        (?:.*                                                          # IPv6 https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
            (?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|                # 1:2:3:4:5:6:7:8
            (?:[0-9a-fA-F]{1,4}:){1,7}:|                               # 1::                              1:2:3:4:5:6:7::
            (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|               # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
            (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|      # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
            (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|      # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
            (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|      # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
            (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|      # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
            [0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|           # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8  
            :(?:(?::[0-9a-fA-F]{1,4}){1,7})|                           # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       :: - not matched     
            fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|           # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
            ::(?:ffff(?::0{1,4}){0,1}:){0,1}
            (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
            (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|              # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
            (?:[0-9a-fA-F]{1,4}:){1,4}:
            (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
            (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])               # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
        .*)
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &IPV6, file, text, flag)?)
}

pub fn found_obfuscation(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref OBFUSCATION: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:echo|printf) .+(?:\\|\s*base64\s+-d|xxd\s+-r\s+-p\s*)?\|\s*bash
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &OBFUSCATION, file, text, flag)?)
}

// Custom regex hunt specified on command line
pub fn found_regex(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{   
    if ARGS.flag_regex != "$^" {
        return Ok(report_finds(pdt, &CUSTOM_REGEX, file, text, flag)?)
    }
    Ok(false)
}

pub fn found_righttoleft(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref RL: Regex = Regex::new(r#"(?mix)
            (:?.*
                \u{202E}
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &RL, file, text, flag)?)
}

pub fn found_shell(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref SHELL: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:[|\s'"><&\\]|^)(?:(?:b?a|t?c|fi|[ak])?sh)(?:[|\s'"><&]|$)
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &SHELL, file, text, flag)?)
}



pub fn found_shellcode(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref SHELL_CODE: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:(?:[0\\]?x|\x20)?[a-f0-9]{2}[,\x20;:\\]){100}
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &SHELL_CODE, file, text, flag)?)
}



/*
    TODO: add aliases
*/
pub fn found_suspicious(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref SUSPICIOUS: Regex = Regex::new(r#"(?mix)
            (:?.*
                (FromBase64String|ToBase64String|System\.Text\.Encoding|
                System\.Convert|securestringtoglobalallocunicode|
                [string]::join|\.GetString|.invoke|

                /t(?:icket|arget)|
                ACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAk|                       # Empire RAT
                \x20-bxor|
                -(?:
                    e(?:c|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?
                    ComputerName|
                    CriticalProcess|
                    HttpStatus|
                    Keystrokes|
                    MasterBootRecord|
                    MicrophoneAudio|
                    Minidump|
                    Persistence|
                    Portscan|
                    processid|
                    ReverseDnsLookup|
                    SecurityPackages|
                    VolumeShadowCopy
                )|
                AVSignature|
                Add-(?:
                    Exfiltration|
                    Persistence|
                    RegBackdoor|
                    ScrnSaveBackdoor
                )|
                AdjustTokenPrivileges|
                Check-VM|
                CompressDLL|
                Control_RunDLL|
                CredentialInjection|
                dll(?:import|injection)|
                download(?:file|data|string)|
                OpenRead|
                WEBReQuEst|
                \.Download|
                Do-Exfiltration|
                ElevatedPersistenceOption|
                Enabled-DuplicateToken|
                EncodeCommand|
                EncryptedScript|
                Exploit-Jboss|
                Find-(?:
                    Fruit|
                    GPOLocation|
                    TrustedDocuments
                )|
                GPP(?:Autologon|Password)|
                Get-(?:
                    ApplicationHost|
                    ChromeDump|
                    ClipboardContents|
                    Content|
                    FoxDump|
                    GPPPassword|
                    IndexedItem|
                    Keystrokes|
                    LSASecret|
                    PassHashes|
                    RegAlwaysInstallElevated|
                    RegAutoLogon|
                    RickAstley|
                    Screenshot|
                    SecurityPackages|
                    ServiceFilePermission|
                    ServicePermission|
                    ServiceUnquoted|
                    SiteListPassword|
                    System|
                    TimedScreenshot|
                    UnattendedInstallFile|
                    Unconstrained|
                    VaultCredential|
                    VulnAutoRun|
                    VulnSchTask|
                    WebConfig
                )|
                Gupt-Backdoor|
                HTTP-Login|
                IMAGE_NT_OPTIONAL_HDR64_MAGIC|
                Install-(?:
                    SSP|
                    ServiceBinary
                )|
                Invoke-(?:
                    ACLScanner|
                    ADSBackdoor|
                    ARPScan|
                    BackdoorLNK|
                    Bloodhound|
                    BypassUAC|
                    Command|
                    CredentialInjection|
                    DCSync|
                    DllInjection|
                    DowngradeAccount|
                    EgressCheck|
                    Expression|iex|
                    Inveigh|
                    InveighRelay|
                    Mimikatz|
                    Mimikittenz|
                    NetRipper|
                    NinjaCopy|
                    PSInject|
                    Paranoia|
                    PortScan|
                    PoshRatHttp|
                    PostExfil|
                    PowerDump|
                    PowerShellTCP|
                    PowerShellWMI|
                    PsExec|
                    PsUaCme|
                    ReflectivePEInjection|
                    RestMethod|
                    ReverseDNSLookup|
                    RunAs|
                    SMBScanner|
                    SSHCommand|
                    ServiceAbuse|
                    ShellCode|
                    Tater|
                    ThunderStruck|
                    TokenManipulation|
                    UserHunter|
                    VoiceTroll|
                    WScriptBypassUAC|
                    WinEnum|
                    WmiCommand|
                    WmiMethod
                )|
                kerberos:|
                LSA_UNICODE_STRING|
                lsadump|
                MailRaider|
                Metasploit|
                Microsoft.Win32.UnsafeNativeMethods|
                Mimikatz|
                MiniDumpWriteDump|
                New-(?:
                    HoneyHash|
                    Object
                )|
                net\.webclient|
                NinjaCopy|
                Out-Minidump|
                PAGE_EXECUTE_READ|
                Port-Scan|
                Power(?:
                    Breach|
                    Up|
                    View
                )|
                procdump|
                ReadProcessMemory.Invoke|
                ReflectivePEInjection|
                Remove-Update|
                runtime\.interopservices\.marshal|
                SECURITY_DELEGATION|
                SE_PRIVILEGE_ENABLED|
                sekurlsa|
                Set-(?:
                    Alias|
                    MacAttribute|
                    Wallpaper
                )|
                ShellCode|
                Show-TargetScreen|
                Start-(?:
                    CaptureServer|
                    Process
                )|
                TOKEN_(?:
                    ADJUST_PRIVILEGES|
                    ALL_ACCESS|
                    ASSIGN_PRIMARY|
                    DUPLICATE|
                    ELEVATION|
                    IMPERSONATE|
                    INFORMATION_CLASS|
                    PRIVILEGES|
                    QUERY
                )|
                TimedScreenshot|
                TokenManipulation|
                UserPersistenceOption|
                VaultCredential|
                VolumeShadowCopyTools|
                WmiCommand|
                \(WCHAR\)|
                IncludeLiveDump="
            )(?:[|\s'"><&]|$)
            ).*
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &SUSPICIOUS, file, text, flag)?)
}


pub fn found_unc(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref UNC: Regex = Regex::new(r#"(?mix)
            (:?.*
                \\\\[a-z0-9_.$-]+\\[a-z0-9_.$-]+
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &UNC, file, text, flag)?)
}


pub fn found_url(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref URL: Regex = Regex::new(r#"(?mix)
            (:?.*
                (?:https?|ftp|smb|cifs)://
            .*)                                                                  
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &URL, file, text, flag)?)
}

pub fn found_webshell(pdt: &str, file: &str, text: &str, flag: &str) -> Result<bool> 
{
    lazy_static! {
        static ref WEBSHELL: Regex = Regex::new(r#"(?mix)
            (?:.*
                # PHP / Perl / JSP possible web shells often used functions
                (?:[|\s'"><&\\;()\[\]]|^)(?:(?:eval|passthru|base64_decode|system|p(?:roc_)?open|                        
                preg_replace|show_source|parse_ini_file|assert|gzdeflate|
                str_rot13|StreamConnector|start|parse_ini_file|show_source)\(|exec(?:\(|\.)|

                # ASP possible web shells often used functions
                creatobject|\.run\()
            .*)                                                               
        "#).expect("Invalid Regex");
    }
    Ok(report_finds(pdt, &WEBSHELL, file, text, flag)?)
}