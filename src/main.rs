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
const WATCH_PATHS: [&str; 15] = [
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
    "/proc/"
    ];
// files whose content we want to look at for interesting strings
const WATCH_FILES: [&str; 8] = [
    "/etc/rc.local",
    "/etc/passwd",
    "/etc/crontab",
    "/etc/cron.d/",
    "/var/spool/cron/crontabs/",
    "/usr/lib/systemd/system/",
    "/.bash_profile",
    "/.bashrc"
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
    #[serde(default = "".to_string())]
    parent_data_type: String,
    #[serde(default = "FileContent")]
    data_type: String,
    timestamp: String,
    path: String,
    line: String,
    number: i32,
    total: i32,
    bytes: String
}
impl TxFileContent {
    fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            line: String,
            number: i32,
            total: i32,
            bytes: String) -> TxFileContent {
        TxFileContent {
            parent_data_type,
            data_type,
            timestamp,
            path,
            line,
            number,
            total,
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
    #[serde(default = "".to_string())]
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
    #[serde(default = "".to_string())]
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
fn push_file_path(path: String, suffix: &str) -> std::path::PathBuf {
    let mut p = path.clone();
    if !suffix.is_empty() {
        p = path + suffix;
    }
    let r = std::path::Path::new(&p);
    return r.clone().to_owned()
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
                (?:(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])){3})         # ipv4 address
                |(?:https?|ftp|smb|cifs)://                                                                         # URL
                |\\\\\w+.+\\\w+                                                                                     # UNC
                |(?:^|[\x20"':=!|])(?:/[\w.-]+)+                                                                    # file path
                |(?:[a-z0-9+/]{4}){8,}(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)?                                           # base64
                |[a-z0-9]{300}                                                                                      # basic encoding
                |(?:(?:[0\\]?x|\x20)?[a-f0-9]{2}[,\x20;:\\]){10}                                                    # shell code
            ).*$)                                                                    
        "#).expect("bad regex");
    }

    for c in RE.captures_iter(text) {
        let line = &c[0];
        TxFileContent::new("".to_string(), "FileContent".to_string(), 
                        get_now()?, file.to_string(), line.into(), 
                        0, 0, "".to_string()).report_log();
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
    if !WATCH_FILES.iter().any(|f| path.contains(f)) { return Ok(()) }
    let data = read_file_string(file_path)?;
    if !data.is_empty() {
        find_paths(&data, already_seen)?;
        find_interesting(path, &data)?;
        drop(data);
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

// convert string to i32 or return 0 if fails
fn to_int32(num: &str) -> i32 {
    let n = match num.parse::<i32>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// gather and report process information via procfs
fn process_process(root_path: &str, bin: std::path::PathBuf) -> std::io::Result<()> {
    let path = resolve_link(&bin)?.to_string_lossy().into();
    let cmd = read_file_string(&push_file_path(root_path.to_string(), "/cmdline"))?;
    let cwd = resolve_link(&push_file_path(root_path.to_string(), "/cwd"))?;
    let env = read_file_string(&push_file_path(root_path.to_string(), "/environ"))?;
    let root = resolve_link(&push_file_path(root_path.to_string(), "/root"))?;
    let subs = split_to_vec(root_path, "/");
    let sub = match subs.iter().next_back() {
        Some(s) => s,
        None => ""
    };
    let pid = to_int32(sub);
    let stat = split_to_vec(&read_file_string(&push_file_path(root_path.to_string(), "/stat"))?, " ");
    let ppid = to_int32(&stat[3]);

    TxProcess::new("".to_string(), "Process".to_string(), get_now()?, 
                path, cmd, pid, ppid, env, root.to_string_lossy().into(),
                cwd.to_string_lossy().into()).report_log();
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
        let p = entry.path().to_string_lossy().to_string();
        if !PID.is_match(&p) { continue }
        let bin = push_file_path(p.clone(), "/exe");
        match process_file(&pdt, &bin, already_seen) {
            Ok(f) => f,
            Err(e) => println!("{}", e)};
        process_process(&p, bin)?;
        thread::sleep(std::time::Duration::from_millis(1));  // sleep so we aren't chewing up too much cpu
    }
    Ok(())
}

// parse local users
fn parse_users() {

}

// parse local groups
fn parse_groups() {

}

// process files and specific files explicitely
fn process_files(pdt: &str, path: &str, mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    match path {
        "/etc/passwd" => parse_users(),
        "/etc/group" => parse_groups(),
        _ => process_file(&pdt, std::path::Path::new(path), &mut already_seen)?
    }
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
    let mut already_seen = vec![];  // cache directories / files already examined to avoid multiple touches and possible infinite loops

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