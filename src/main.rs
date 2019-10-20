/*
    Author: Brian Kellogg
    Description: Pull operational forensics triage from Linux hosts.

    Build command: cargo build --release
    Post build: Run "strip" on compiled binary to drastically reduce its size.
        e.g. "strip lin_fh"

    GOAL: 
      - cover all persistence mechanisms that can be here: https://attack.mitre.org/matrices/enterprise/linux/
      - also gather any other information that is useful in triaging an event
*/

extern crate walkdir;           // traverse directory trees
extern crate md5;
extern crate serde;             // needed for json serialization
extern crate serde_derive;      // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate file;
extern crate chrono;            // DateTime manipulation
extern crate tree_magic;        // needed to find MIME type of files
extern crate path_abs;          // needed to create absolute file paths from relative
extern crate regex;
#[macro_use] extern crate lazy_static;

use walkdir::WalkDir;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::io;
use std::io::Read;
use std::thread;
use std::fs::{self};
use serde_derive::{Serialize};
use chrono::offset::Utc;
use chrono::DateTime;
use path_abs::{PathAbs, PathInfo};
use regex::Regex;

const MAX_DIR_DEPTH: usize = 5;     // Max number of sub directories to traverse
// file paths we want to watch all files in
const WATCH_PATHS: [&str; 16] = [
    "/etc/init.d",
    "/etc/modules",
    "/etc/rc.local",
    "/etc/initramfs-tools/modules",
    "/home",
    "/etc/passwd",
    "/etc/group",
    "/lib/modules",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/var/spool/cron/crontabs",
    "/tmp",
    "/proc/",
    "/root"
    ];
// files whose content we want to look at for interesting strings
const WATCH_FILES: [&str; 11] = [
    "/etc/passwd",
    "/etc/group",
    "/etc/rc.local",
    "/etc/rc.d/",
    "/etc/crontab",
    "/etc/cron.d/",
    "/var/spool/cron/crontabs/",
    "/usr/lib/systemd/system/",
    "/.bash_profile",
    "/.bashrc",
    "/root/"
    ];

// holds file metadata info
#[derive(Serialize)]
struct TxFile {
    parent_data_type: String,
    data_type: String,
    timestamp: String,
    path: String, 
    md5: String, 
    mime_type: String,
    last_access_time: String, 
    last_write_time: String,
    creation_time: String,
    size: u64,
    hidden: bool
}
impl TxFile {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            md5: String, 
            mime_type: String,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            size: u64,
            hidden: bool) -> TxFile {
        TxFile {
            parent_data_type,
            data_type,
            timestamp,
            path,
            md5,
            mime_type,
            last_access_time,
            last_write_time,
            creation_time,
            size,
            hidden
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// holds interesting content found in files
#[derive(Serialize)]
struct TxFileContent {
    parent_data_type: String,
    #[serde(default = "FileContent")]
    data_type: String,
    timestamp: String,
    path: String,
    line: String,
    bytes: String
}
impl TxFileContent {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            line: String,
            bytes: String) -> TxFileContent {
        TxFileContent {
            parent_data_type,
            data_type,
            timestamp,
            path,
            line,
            bytes
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// holds symlink metdata
#[derive(Serialize)]
struct TxLink {
    parent_data_type: String,
    #[serde(default = "ShellLink")]
    data_type: String,
    timestamp: String,
    path: String,
    target_path: String,
    last_access_time: String,
    last_write_time: String,
    creation_time: String,
    size: u64,
    hidden: bool
}
impl TxLink {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            target_path: String,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            size: u64,
            hidden: bool) -> TxLink {
        TxLink {
            parent_data_type,
            data_type,
            timestamp,
            path,
            target_path,
            last_access_time,
            last_write_time,
            creation_time,
            size,
            hidden
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold process metadata info from procfs
#[derive(Serialize)]
struct TxProcess {
    parent_data_type: String,
    #[serde(default = "Process")]
    data_type: String,
    timestamp: String,
    path: String,
    command_line: String,
    pid: i32,
    ppid: i32,
    env: String,
    root_directory: String,
    current_working_directory: String
}
impl TxProcess {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            command_line: String,
            pid: i32, 
            ppid: i32,
            env: String,
            root_directory: String,
            current_working_directory: String) -> TxProcess {
        TxProcess {
            parent_data_type,
            data_type,
            timestamp,
            path,
            command_line,
            pid,
            ppid,
            env,
            root_directory,
            current_working_directory
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold local user metadata
#[derive(Serialize)]
struct TxLocalUser {
    parent_data_type: String,
    #[serde(default = "LocalUser")]
    data_type: String,
    timestamp: String,
    account_name: String,
    uid: String,
    gid: String,
    description: String,
    home_directory: String,
    shell: String
}
impl TxLocalUser {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            account_name: String, 
            uid: String,
            gid: String, 
            description: String,
            home_directory: String,
            shell: String) -> TxLocalUser {
        TxLocalUser {
            parent_data_type,
            data_type,
            timestamp,
            account_name,
            uid,
            gid,
            description,
            home_directory,
            shell
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold group metadata
#[derive(Serialize)]
struct TxLocalGroup {
    parent_data_type: String,
    #[serde(default = "LocalGroup")]
    data_type: String,
    timestamp: String,
    group_name: String,
    gid: String,
    members: String
}
impl TxLocalGroup {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            group_name: String, 
            gid: String,
            members: String) -> TxLocalGroup {
        TxLocalGroup {
            parent_data_type,
            data_type,
            timestamp,
            group_name,
            gid,
            members
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold loaded kernel modules metadata
#[derive(Serialize)]
struct TxLoadedModule {
    parent_data_type: String,
    #[serde(default = "KernelModule")]
    data_type: String,
    timestamp: String,
    name: String,
    size: i64,                  // module size in memory
    loaded: i8,                 // how many times the module is loaded
    dependencies: String,       // other modules this module is dependant on
    state: String,              // state is: Live, Loading, or Unloading
    memory_offset: String       // location in kernel memory of module
}
impl TxLoadedModule {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String,
            size: i64,
            loaded: i8,
            dependencies: String,
            state: String,
            memory_offset: String) -> TxLoadedModule {
        TxLoadedModule {
            parent_data_type,
            data_type,
            timestamp,
            name,
            size,
            loaded,
            dependencies,
            state,
            memory_offset
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold mount point metadata
#[derive(Serialize)]
struct TxMountPoint {
    parent_data_type: String,
    #[serde(default = "KernelModule")]
    data_type: String,
    timestamp: String,
    name: String,
    mount_point: String,
    file_system_type: String,
    mount_options: String
}
impl TxMountPoint {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String,
            mount_point: String,
            file_system_type: String,
            mount_options: String) -> TxMountPoint {
        TxMountPoint {
            parent_data_type,
            data_type,
            timestamp,
            name,
            mount_point,
            file_system_type,
            mount_options
        }
    }

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// tracks path of file and the parent data_type that caused us to look at the file
struct FileParent {
    parent_data_type: String,
    path: std::path::PathBuf
}

// holds info on metadata for file content
struct FileContentMetaData {
    md5: String,
    mime_type: String
}

// return file mime type string
fn get_filetype(buffer: &mut Vec<u8>) -> String {
    tree_magic::from_u8(buffer)
}

// true if path exists, false otherwise
fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

// get date into the format we need
fn format_date(time: DateTime<Utc>) -> Result<String, std::io::Error>  {
    Ok(time.format("%Y-%m-%d %H:%M:%S.%3f").to_string())
}

// get the current date time
fn get_now() -> Result<String, std::io::Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
fn get_epoch_start() -> String  {
    "1970-01-01 00:00:00.000".to_string()
}

// is a file or directory hidden
fn is_hidden(file_path: &std::path::PathBuf) -> bool {
    let path = match file_path.file_name() {
            Some(o) => o,
            None => return false
            };
    if file_path.is_file() {  // simple check for hidden files and directories
        path.to_string_lossy().starts_with(".")
    } else if file_path.is_dir() {
        path.to_string_lossy().contains("/.")
    } else {
        false
    }
}

// get handle to a file
fn open_file(file_path: &std::path::Path) -> std::io::Result<(std::fs::File)> {
    match File::open(&file_path) {
        Ok(f) => return Ok(f),
        Err(e) => return Err(e)
    }
}

// read all file content for examination for interesting strings
fn read_file_string(file: &std::path::Path) -> std::io::Result<(String)> {
    match fs::read_to_string(file) {
        Ok(f) => Ok(f.replace('\u{0000}', " ").trim().to_string()),  // Unicode nulls are replaced with spaces (look for better solution)
        Err(_e) => Ok("".to_string())
    }
}

// read in file as byte vector
fn read_file_bytes(mut file: &std::fs::File) -> std::io::Result<(Vec<u8>)> {
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(f) => f,
        Err(_e) => return Ok(vec![])
    };
    Ok(buffer)
}

// return the path that a symlink points to
fn resolve_link(link_path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let parent_dir = get_parent_dir(link_path);
    match std::env::set_current_dir(parent_dir) {
        Ok(f) => f,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let result = match fs::read_link(link_path) {
        Ok(r) => r,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let abs = PathAbs::new(&result)?;
    Ok(abs.into())
}

// find the parent directory of a given dir or file
fn get_parent_dir(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(d) => return d,
        None => return path
    };
}

// convert a string to a Rust file path
fn push_file_path(path: &str, suffix: &str) -> std::path::PathBuf {
    let mut p = path.to_owned();
    p.push_str(suffix);
    let r = std::path::Path::new(&p);
    return r.to_owned()
}

// get metadata for the file's content (md5, mime_type)
fn get_file_content_info(file: &std::fs::File) -> std::io::Result<(FileContentMetaData)> {
    let mut fc = FileContentMetaData {md5: "".to_string(), mime_type: "".to_string()};
    let mut buffer = read_file_bytes(file)?;
    fc.md5 = format!("{:x}", md5::compute(&buffer)).to_lowercase();
    fc.mime_type = get_filetype(&mut buffer);
    drop(buffer);
    Ok(fc)
}

/*
    regex's to find interesting strings in files
    capture and report the line that the interesting string is found in
*/
fn find_interesting(file: &str, text: &str) -> std::io::Result<()> {
    lazy_static! {
        // use \x20 for matching spaces when using "x" directive that doesn't allow spaces in regex
        static ref RE: Regex = Regex::new(r#"(?mix)
            (?:^.*(?:
                (?:(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])){3})|        # IPv4 address
                (?:                                                                                                 # IPv6 https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
                    (?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|                                                     # 1:2:3:4:5:6:7:8
                    (?:[0-9a-fA-F]{1,4}:){1,7}:|                                                                    # 1::                              1:2:3:4:5:6:7::
                    (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|                                                    # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
                    (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|                                           # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
                    (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|                                           # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
                    (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|                                           # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
                    (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|                                           # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
                    [0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|                                                # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8  
                    :(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|                                                              # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::     
                    fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|                                                # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
                    ::(?:ffff(?::0{1,4}){0,1}:){0,1}
                    (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                    (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|                                                   # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
                    (?:[0-9a-fA-F]{1,4}:){1,4}:
                    (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                    (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])                                                    # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
                )|
                (?:https?|ftp|smb|cifs)://|                                                                         # URL
                \\\\\w+.+\\\w+|                                                                                     # UNC
                (?:^|[\x20"':=!|])(?:/[\w.-]+)+|                                                                    # file path
                (?:[a-z0-9+/]{4}){8,}(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)?|                                           # base64
                [a-z0-9]{300}|                                                                                      # basic encoding
                (?:(?:[0\\]?x|\x20)?[a-f0-9]{2}[,\x20;:\\]){10}                                                     # shell code                      
            ).*$)                                                                    
        "#).expect("bad regex");
    }

    for c in RE.captures_iter(text) {
        let line = &c[0];
        TxFileContent::new("".to_string(), "FileContent".to_string(), 
                        get_now()?, file.to_string(), line.into(), 
                        "".to_string()).report_log();
    }
    Ok(())
}

/*
    identify files being referenced in the file content 
    this is so we can harvest the metadata on these files as well
*/
fn find_paths(text: &str, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"(?mix)(?:^|[\x20"':=!|])((?:/[\w.-]+)+)"#)
                                        .expect("Invalid Regex");
    }
    for c in RE.captures_iter(text) {
        let path = std::path::Path::new(&c[1]);
        process_file("FileContent", path, already_seen)?;
    }
    Ok(())
}

/*
    check if a given file is one we want to inspect the contents of 
    for interesting strings and references to other files
*/
fn watch_file(file_path: &std::path::Path, path: &str, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    if WATCH_FILES.iter().any(|f| path.contains(f)) {
        let data = read_file_string(file_path)?;
        if !data.is_empty() {
            find_paths(&data, already_seen)?;
            find_interesting(path, &data)?;
            drop(data);
        }
    }
    Ok(())
}

// gather metadata for symbolic links
fn process_link(pdt: &str, link: std::fs::Metadata, link_path: String, file_path: String, hidden: bool) -> std::io::Result<()> {
    let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
    if link.created().is_ok() {
        ctime = format_date(link.created()?.into())?;
    }
    let atime = format_date(link.accessed()?.into())?;
    let wtime = format_date(link.modified()?.into())?;
    let size = link.len();

    TxLink::new(pdt.to_string(), "ShellLink".to_string(), get_now()?, 
                link_path, file_path, atime, wtime, 
                ctime, size, hidden).report_log();
    Ok(())
}

/*
    determine if a file is a symlink or not
    return parent data_type and path to file
    never return the path to a symnlink
*/
fn get_link_info(pdt: &str, link_path: &std::path::Path) -> std::io::Result<FileParent> {
    let mut fp = FileParent {
        parent_data_type: pdt.to_string(), 
        path: PathAbs::new(&link_path)?.clone().into() 
        };
    let sl = fs::symlink_metadata(&link_path)?;
    if sl.file_type().is_symlink() {
        fp.path = resolve_link(link_path)?;
        fp.parent_data_type = "ShellLink".to_string();
        process_link(pdt, sl, 
                    link_path.to_string_lossy().into(), 
                    fp.path.to_string_lossy().into(), 
                    is_hidden(&fp.path))?;
    }
    Ok(fp)
}

// harvest a file's metadata
fn process_file(pdt: &str, file_path: &std::path::Path, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let p: String = file_path.to_string_lossy().into();
    if file_path.is_file() && !already_seen.contains(&p.clone()) {
        already_seen.push(p);    // track files we've processed so we don't process them more than once
        let fp = get_link_info(&pdt, file_path)?;   // is this file a symlink? TRUE: get sysmlink info and path to linked file
        
        let file = open_file(file_path)?;
        let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
        if file.metadata()?.created().is_ok() { 
            ctime = format_date(file.metadata()?.created()?.into())?; 
        }
        let atime = format_date(file.metadata()?.accessed()?.into())?;
        let wtime = format_date(file.metadata()?.modified()?.into())?;
        let size = file.metadata()?.len();
        let path = match fp.path.to_str() {
            Some(s) => s,
            None => ""
            };
        let fc = get_file_content_info(&file)?;
        drop(file); // close file handle immediately after not needed to avoid too many files open error
        TxFile::new(fp.parent_data_type, "File".to_string(), get_now()?, 
                    path.into(), fc.md5, fc.mime_type, atime, wtime, 
                    ctime, size, is_hidden(&fp.path)).report_log();

        watch_file(&fp.path, path, already_seen)?;
    }
    Ok(())
}

// split string on string and return vec
fn split_to_vec(source: &str, split_by: &str) -> Vec<String> {
    source.split(split_by).map(|s| s.to_string()).collect()
}

// convert string to i128 or return 0 if fails
fn to_int128(num: &str) -> i128 {
    let n = match num.parse::<i128>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i64 or return 0 if fails
fn to_int64(num: &str) -> i64 {
    let n = match num.parse::<i64>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i32 or return 0 if fails
fn to_int32(num: &str) -> i32 {
    let n = match num.parse::<i32>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i8 or return 0 if fails
fn to_int8(num: &str) -> i8 {
    let n = match num.parse::<i8>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// gather and report process information via procfs
fn process_process(root_path: &str, bin: std::path::PathBuf) -> std::io::Result<()> {
    let path = resolve_link(&bin)?.to_string_lossy().into();
    let cmd = read_file_string(&push_file_path(root_path, "/cmdline"))?;
    let cwd = resolve_link(&push_file_path(root_path, "/cwd"))?;
    let env = read_file_string(&push_file_path(root_path, "/environ"))?;
    let root = resolve_link(&push_file_path(root_path, "/root"))?;
    let subs = split_to_vec(root_path, "/");
    let sub = match subs.iter().next_back() {
        Some(s) => s,
        None => ""
    };
    let pid = to_int32(sub);
    let stat = split_to_vec(&read_file_string(&push_file_path(root_path, "/stat"))?, " ");
    let ppid = to_int32(&stat[3]);

    TxProcess::new("".to_string(), "Process".to_string(), get_now()?, 
                path, cmd, pid, ppid, env, root.to_string_lossy().into(),
                cwd.to_string_lossy().into()).report_log();
    Ok(())
}

// parse modules in /proc/modules
fn parse_modules(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(" ").collect();
        let name = values[0].to_string();
        let size = to_int64(values[1]);
        let loaded = to_int8(values[2]);
        let mut dependencies = values[3].replace(",", ", ").trim().to_string();
        if dependencies.ends_with(",") { dependencies.pop(); }
        let state = values[4].to_string();
        let offset = values[5].to_string();
        TxLoadedModule::new(pdt.to_string(), "KernelModule".to_string(), get_now()?, 
                        name, size, loaded, dependencies, state, offset).report_log();
    }
    Ok(())
}

// parse mount points in /proc/mounts
fn parse_mounts(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(" ").collect();
        let name = values[0].to_string();
        let mount_point = values[1].to_string();
        let file_system_type = values[2].to_string();
        let mount_options = values[3].replace(",", ", ").trim().to_string();
        TxMountPoint::new(pdt.to_string(), "MountPoint".to_string(), get_now()?, 
                        name, mount_point, file_system_type, mount_options).report_log();
    }
    Ok(())
}

// start processing procfs to gather process metadata
fn examine_procs(pdt: &str, path: &str, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    lazy_static! { 
        static ref PID: Regex = Regex::new(r#"(?mix)^/proc/\d{1,5}$"#)
                                        .expect("Invalid Regex");
    }
    for entry in WalkDir::new(path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok()) {
        let p: &str = &*(entry.path().to_string_lossy().to_string());
        match p {
            "/proc/modules" => parse_modules(pdt, &p)?,
            "/proc/mounts" => parse_mounts(pdt, &p)?,
            _ => {
                if !PID.is_match(&p) { continue };
                let bin = push_file_path(p, "/exe");
                match process_file(&pdt, &bin, already_seen) {
                    Ok(f) => f,
                    Err(e) => println!("{}", e)};
                process_process(&p, bin)?;
            }
        };
        thread::sleep(std::time::Duration::from_millis(1));  // sleep so we aren't chewing up too much cpu
    }
    Ok(())
}

// read file's lines into a string vec for parsing
fn file_to_vec(filename: &str) -> io::Result<Vec<String>> {
    let file_in = fs::File::open(filename)?;
    let file_reader = BufReader::new(file_in);
    Ok(file_reader.lines().filter_map(io::Result::ok).collect())
}

// parse local users
fn parse_users(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(":").collect();
        let account_name = values[0].to_string();
        let uid = values[2].to_string();
        let gid = values[3].to_string();
        let description = values[4].to_string();
        let home_directory = values[5].to_string();
        let shell = values[6].to_string();
        TxLocalUser::new(pdt.to_string(), "LocalUser".to_string(), get_now()?, 
                        account_name, uid, gid, description, home_directory, 
                        shell).report_log();
    }
    Ok(())
}

// parse local groups
fn parse_groups(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(":").collect();
        let group_name = values[0].to_string();
        let gid = values[2].to_string();
        let members = values[3].to_string();
        TxLocalGroup::new(pdt.to_string(), "LocalGroup".to_string(), get_now()?, 
                        group_name, gid, members).report_log();
    }
    Ok(())
}

// process files and specific files explicitely
fn process_files(pdt: &str, path: &str, mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    match path {
        "/etc/passwd" => parse_users(pdt, path)?,
        "/etc/group" => parse_groups(pdt, path)?,
        _ => {}
    };
    process_file(&pdt, std::path::Path::new(path), &mut already_seen)?;
    Ok(())
}

// process directories and sub dirs we are interested in
fn process_directory(pdt: &str, path: &str, mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    match path {
        ref p if p.starts_with("/proc") => examine_procs(&pdt, &path, &mut already_seen)?,
        _ => for entry in WalkDir::new(path)
                    .max_depth(MAX_DIR_DEPTH)
                    .into_iter()
                    .filter_map(|e| e.ok()) {
                process_file(&pdt, entry.path(), &mut already_seen)?;
                thread::sleep(std::time::Duration::from_millis(1));  // sleep so we aren't chewing up too much cpu
            },
    }
    Ok(())
}

// let's start this thing
fn main() -> std::io::Result<()> {
    let mut already_seen = vec![];  // cache directories and files already examined to avoid multiple touches and possible infinite loops

    for path in WATCH_PATHS.iter() {
        if !path_exists(path) { continue }
        let pdt = "".to_string();
        let md = fs::metadata(path)?;
        if md.is_dir() {  // if this is a directory we have more to do
            match process_directory(&pdt, path, &mut already_seen) {
                Ok(f) => f,
                Err(e) => println!("{}", e),};
        } else {
            match process_files(&pdt, path, &mut already_seen) {
                Ok(f) => f,
                Err(e) => println!("{}", e),};
        }
    }
    Ok(())
}