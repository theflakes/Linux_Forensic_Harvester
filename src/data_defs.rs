extern crate serde;             // needed for json serialization
extern crate serde_derive;      // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate docopt;
extern crate nix;
extern crate chrono;

use crate::mutate::hex_to_bytes;

use chrono::*;
use serde::Serialize;
use serde_derive::Deserialize;
use std::{io::prelude::Write, collections::HashSet, env, process::Command};
use docopt::Docopt;
use std::thread;
use regex::Regex;
use hostname::*;

lazy_static! {
    pub static ref DEVICE_NAME: String = hostname::get().unwrap_or_default()
                                        .to_string_lossy().to_owned().to_string();
    pub static ref DEVICE_IP: String = get_ip();
}

fn get_ip() -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg("ip route get 1.1.1.1 | grep -oP 'src \\K\\S+'")
        .output()
        .expect("");

    std::str::from_utf8(&output.stdout).unwrap().trim().to_string()
}

pub const USAGE: &'static str = "
Linux Forensic Harvester
    Author: Brian Kellogg
    License: MIT
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

Must be run as root.

Usage:
    lin_fh [options]
    lin_fh -fksl
    lin_fh [--ip <ip> --port <port>] [--depth <depth>]
    lin_fh [--ip <ip> --port <port>] [--limit]
    lin_fh [--i <ip> -p <port>] [--suidsgid] [--limit]
    lin_fh (-s, --suidsgid) [--limit]
    lin_fh (-r <regex> | --regex <regex>) [-ls] [-d <depth>]
    lin_fh --max <bytes> [--limit] [-d <depth>]
    lin_fh (-l | --limit)
    lin_fh --start <start_time> [-d <depth>]
    lin_fh --end <start_time> [-d <depth>] [-ls]
    lin_fh --start <start_time> --end <end_time>
    lin_fh -s [-d <depth>]
    lin_fh [-sl] (-x <hex> | --hex <hex>)
    lin_fh (-h | --help)

Options:
    -d, --depth <depth>     Max directory depth to traverse [default: 5]
    -f, --forensics         Gather general forensic info
    -h, --help              Print help
    -l, --limit             Limit CPU use
    -k, --rootkit           Run rootkit hunts
    -m, --max <bytes>       Max size of a text file in bytes to inspect the content
                            of for interesting strings [default: 100000]
                            - Text files will always be searched for references
                              to other files.
  Remote logging:
    -i, --ip <ip>           IP address to send output to [default: NONE]
    -p, --port <port>       Destination port to send output to [default: 80]
  Time window:
    This option will compare the specified date window to the file's 
    ctime, atime, or mtime and only output logs where one of the dates falls 
    within that window. Window start is inclusive, window end is exclusive.
    --start <UTC_start_time>    Start of time window: [default: 0000-01-01T00:00:00]
                                - format: YYYY-MM-DDTHH:MM:SS
    --end <UTC_end_time>        End of time window: [default: 9999-12-31T23:59:59]
                                - format: YYYY-MM-DDTHH:MM:SS
  Custom hunts:
    -r, --regex <regex>     Custom regex [default: $^]
                            - Search file content using custom regex
                            - Does not support look aheads/behinds/...
                            - Uses Rust regex crate (case insensitive and multiline)
                            - Tag: RegexHunt
    -s, --suidsgid          Search for suid and sgid files
                            - This will search the entire '/' including subdirectories
                            - Can take a long time
                            - /dev/, /mnt/, /proc/, /sys/ directories are ignored
    -x, --hex <hex>         Hex search string [default: FF]
                            - Hex string length must be a multiple of two
                            - format: 0a1b2c3d4e5f
                            - Tag: HexHunt

Note:
  Must be run as root.

  A log with data_type of 'Rootkit' will be generated if the size of file read into
  memory is less that the size on disk. This is a simple possible root kit identification
  method.
  - See: https://github.com/sandflysecurity/sandfly-file-decloak
  
  To capture network output, start a netcat listener on your port of choice.
  Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

  Files larger than 256MB will not be hashed.

  Files larger than '--max' will not be inspected for interesting strings.
";

#[derive(Debug, Deserialize)]
pub struct Args {
    flag_ip: String,
    flag_port: u16,
    flag_limit: bool,
    pub flag_depth: usize,
    pub flag_forensics: bool,
    pub flag_rootkit: bool,
    pub flag_max: u64,
    pub flag_regex: String,
    pub flag_hex: String,
    pub flag_suidsgid: bool,

    // time window
    pub flag_start: String,
    pub flag_end: String,
}

lazy_static! { 
    pub static ref ARGS: Args = Docopt::new(USAGE)
                    .and_then(|d| d.deserialize())
                    .unwrap_or_else(|e| e.exit());
                
    pub static ref CUSTOM_REGEX: Regex = Regex::new(&format!(r"{}{}", "(?mi)".to_string(), ARGS.flag_regex)).expect("Invalid Regex");
    pub static ref TIME_START: DateTime<Utc> = Utc.datetime_from_str(&ARGS.flag_start, "%Y-%m-%dT%H:%M:%S").expect("Invalid start time!!!");
    pub static ref TIME_END: DateTime<Utc> = Utc.datetime_from_str(&ARGS.flag_end, "%Y-%m-%dT%H:%M:%S").expect("Invalid end time!!!");
    pub static ref FIND_HEX: Vec<u8> = hex_to_bytes(&ARGS.flag_hex).expect("Invalid hex string!!!");
}

pub fn sleep() {
    if ARGS.flag_limit {
        thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub fn sort_hashset(mut tags: HashSet<String>) -> Vec<String> {
    tags.remove("");
    let mut vec: Vec<String> = tags.into_iter().collect();
    vec.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    return vec
}

/*
    Help provided by Yandros on using traits: 
        https://users.rust-lang.org/t/refactor-struct-fn-with-macro/40093
*/
type Str = ::std::borrow::Cow<'static, str>;
trait Loggable : Serialize {
    /// convert struct to json
    fn to_log (self: &'_ Self) -> Str
    {
        ::serde_json::to_string(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    
    /// convert struct to json and report it out
    fn write_log (self: &'_ Self)
    {
        if !ARGS.flag_ip.eq("NONE") {
            let socket = format!("{}:{}", ARGS.flag_ip, ARGS.flag_port);
            let mut stream = ::std::net::TcpStream::connect(socket)
                .expect("Could not connect to server");
            writeln!(stream, "{}", self.to_log())
                .expect("Failed to write to server");
        } else {
            println!("{}", self.to_log());
        }
    }
}
impl<T : ?Sized + Serialize> Loggable for T {}

#[derive(Serialize)]
pub struct TxGeneral {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    pub data_type: String,
    pub timestamp: String,
    pub info: String,
    pub tags: Vec<String>
}
impl TxGeneral {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            info: String,
            tags: Vec<String>) -> TxGeneral {
        TxGeneral {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            info,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

#[derive(Serialize)]
pub struct TxCharDevice {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub class: String,
    pub pattern: String,
    pub major: u64,
    pub permissions: String,
    pub uid: u32,
    pub gid: u32,
    pub inode: u64,
    pub last_access_time: String, 
    pub last_write_time: String,
    pub creation_time: String,
    pub tags: Vec<String>
}
impl TxCharDevice {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            class: String,
            pattern: String,
            major: u64,
            permissions: String,
            uid: u32,
            gid: u32,
            inode: u64,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            tags: Vec<String>) -> TxCharDevice {
        TxCharDevice {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            class,
            pattern,
            major,
            permissions,
            uid,
            gid,
            inode,
            last_access_time, 
            last_write_time,
            creation_time,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// holds file metadata info
#[derive(Serialize)]
pub struct TxFile {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    pub data_type: String,
    pub timestamp: String,
    pub path: String, 
    pub md5: String, 
    pub mime_type: String,
    pub last_access_time: String, 
    pub last_write_time: String,
    pub creation_time: String,
    pub size: u64,
    pub hidden: bool,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64, // number of hard links to file
    pub inode: u64,
    pub permissions: String,
    pub tags: Vec<String>,
}
impl TxFile {
    pub fn new(
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
            hidden: bool,
            uid: u32,
            gid: u32,
            nlink: u64,
            inode: u64,
            permissions: String,
            tags: Vec<String>,) -> TxFile {
        TxFile {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
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
            hidden,
            uid,
            gid,
            nlink,
            inode,
            permissions,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// holds interesting content found in files
#[derive(Serialize)]
pub struct TxFileContent {
    device_name: String,
    src_ip: String,
    #[serde(default = "File")]
    pub parent_data_type: String,
    #[serde(default = "FileContent")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub line: String,
    pub bytes: String,
    pub tags: Vec<String>
}
impl TxFileContent {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            line: String,
            bytes: String,
            tags: Vec<String>,) -> TxFileContent {
        TxFileContent {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            line,
            bytes,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// used when a file is possibly holding hidden data (rootkit)
#[derive(Serialize)]
pub struct TxHiddenData {
    device_name: String,
    src_ip: String,
    #[serde(default = "File")]
    pub parent_data_type: String,
    #[serde(default = "DataHidden")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub size: u64,
    pub std_size_read: u64,
    pub mmap_size_read: u64,
    pub hidden_data_string: String,
    pub hidden_data_hex: String,
    pub tags: Vec<String>
}
impl TxHiddenData {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            size: u64,
            std_size_read: u64,
            mmap_size_read: u64,
            hidden_data_string: String,
            hidden_data_hex: String,
            tags: Vec<String>) -> TxHiddenData {
        TxHiddenData {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            size,
            std_size_read,
            mmap_size_read,
            hidden_data_string,
            hidden_data_hex,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// used when a file is possibly holding hidden data (rootkit)
#[derive(Serialize)]
pub struct TxKernelTaint {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "KernelTaint")]
    pub data_type: String,
    pub timestamp: String,
    is_tainted: bool,
    pub taint_value: u32,
    pub info: String,
    pub tags: Vec<String>
}
impl TxKernelTaint {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            is_tainted: bool,
            taint_value: u32,
            info: String,
            tags: Vec<String>) -> TxKernelTaint {
        TxKernelTaint {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            is_tainted,
            taint_value,
            info,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// holds symlink metdata
#[derive(Serialize)]
pub struct TxLink {
    device_name: String,
    src_ip: String,
    #[serde(default = "File")]
    pub parent_data_type: String,
    #[serde(default = "ShellLink")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub target_path: String,
    pub last_access_time: String,
    pub last_write_time: String,
    pub creation_time: String,
    pub size: u64,
    pub hidden: bool,
    pub target_exists: bool,
    pub tags: Vec<String>
}
impl TxLink {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            target_path: String,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            size: u64,
            hidden: bool,
            target_exists: bool,
            tags: Vec<String>) -> TxLink {
        TxLink {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            target_path,
            last_access_time,
            last_write_time,
            creation_time,
            size,
            hidden,
            target_exists,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold process metadata info from procfs
#[derive(Serialize)]
pub struct TxProcess {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "Process")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub exists: bool,
    pub comm: String,
    pub command_line: String,
    pub pid: i32,
    pub ppid: i32,
    pub env: String,
    pub root_directory: String,
    pub current_working_directory: String,
    pub tags: Vec<String>
}
impl TxProcess {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            exists: bool,
            comm: String,
            command_line: String,
            pid: i32, 
            ppid: i32,
            env: String,
            root_directory: String,
            current_working_directory: String,
            tags: Vec<String>) -> TxProcess {
        TxProcess {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            exists,
            comm,
            command_line,
            pid,
            ppid,
            env,
            root_directory,
            current_working_directory,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold process metadata info from procfs
#[derive(Serialize)]
pub struct TxProcessFile {
    device_name: String,
    src_ip: String,
    #[serde(default = "Process")]
    pub parent_data_type: String,
    #[serde(default = "ProcessOpenFile")]
    pub data_type: String,
    pub timestamp: String,
    pub pid: i32,
    pub link: String,
    pub path: String,
    pub exists: bool,
    pub tags: Vec<String>
}
impl TxProcessFile {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            pid: i32,
            link: String,
            path: String,
            exists: bool,
            tags: Vec<String>) -> TxProcessFile {
        TxProcessFile {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            pid,
            link,
            path,
            exists,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold process maps info from procfs
#[derive(Serialize)]
pub struct TxProcessMaps {
    device_name: String,
    src_ip: String,
    #[serde(default = "Process")]
    pub parent_data_type: String,
    #[serde(default = "ProcessMaps")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub pid: i32,
    pub address_range: String,
    pub permissions: String,
    pub offset: String,
    pub device: String,
    pub inode: u128,
    pub tags: Vec<String>
}
impl TxProcessMaps {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            pid: i32, 
            address_range: String,
            permissions: String,
            offset: String,
            device: String,
            inode: u128,
            tags: Vec<String>) -> TxProcessMaps {
        TxProcessMaps {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            pid,
            address_range,
            permissions,
            device,
            offset,
            inode,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold local user metadata
#[derive(Serialize)]
pub struct TxLocalUser {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "LocalUser")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub uid: i32,
    pub gid: i32,
    pub description: String,
    pub home_directory: String,
    pub shell: String,
    pub tags: Vec<String>
}
impl TxLocalUser {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String, 
            uid: i32,
            gid: i32, 
            description: String,
            home_directory: String,
            shell: String,
            tags: Vec<String>) -> TxLocalUser {
        TxLocalUser {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            name,
            uid,
            gid,
            description,
            home_directory,
            shell,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold group metadata
#[derive(Serialize)]
pub struct TxLocalGroup {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "LocalGroup")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub gid: u32,
    pub members: String,
    pub tags: Vec<String>
}
impl TxLocalGroup {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String, 
            gid: u32,
            members: String,
            tags: Vec<String>) -> TxLocalGroup {
        TxLocalGroup {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            name,
            gid,
            members,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold loaded kernel modules metadata
#[derive(Serialize)]
pub struct TxLoadedModule {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "KernelModule")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub size: i64,                  // module size in memory
    pub loaded: i8,                 // how many times the module is loaded
    pub dependencies: String,       // other modules this module is dependant on
    pub state: String,              // state is: Live, Loading, or Unloading
    pub memory_offset: String,      // location in kernel memory of module
    pub tags: Vec<String>
}
impl TxLoadedModule {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String,
            size: i64,
            loaded: i8,
            dependencies: String,
            state: String,
            memory_offset: String,
            tags: Vec<String>) -> TxLoadedModule {
        TxLoadedModule {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            name,
            size,
            loaded,
            dependencies,
            state,
            memory_offset,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold mount point metadata
#[derive(Serialize)]
pub struct TxMountPoint {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "MountPoint")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub mount_point: String,
    pub file_system_type: String,
    pub mount_options: String,
    pub tags: Vec<String>
}
impl TxMountPoint {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            name: String,
            mount_point: String,
            file_system_type: String,
            mount_options: String,
            tags: Vec<String>) -> TxMountPoint {
        TxMountPoint {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            name,
            mount_point,
            file_system_type,
            mount_options,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold network connection metadata
#[derive(Serialize)]
pub struct TxNetConn {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "NetConn")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub pid: i32,
    pub uid: i32,
    pub l_ip: String,   // local ip
    pub l_port: u16,    // local port
    pub r_ip: String,   // remote ip
    pub r_port: u16,    // remote port
    pub status: String,
    pub inode: u128,
    pub tags: Vec<String>
}
impl TxNetConn {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            pid: i32,
            uid: i32,
            l_ip: String,
            l_port: u16,
            r_ip: String,
            r_port: u16,
            status: String,
            inode: u128,
            tags: Vec<String>) -> TxNetConn {
        TxNetConn {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            pid,
            uid,
            l_ip,
            l_port,
            r_ip,
            r_port,
            status,
            inode,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold network connection metadata
#[derive(Serialize)]
pub struct TxCron {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    #[serde(default = "Cron")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub minute: String,
    pub hour: String,
    pub day_of_month: String, 
    pub month: String,
    pub day_of_week: String, 
    pub name: String, 
    pub command_line: String,
    pub tags: Vec<String>
}
impl TxCron {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            minute: String,
            hour: String,
            day_of_month: String, 
            month: String,
            day_of_week: String,
            name: String, 
            command_line: String,
            tags: Vec<String>) -> TxCron {
        TxCron {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            minute,
            hour,
            day_of_month,
            month,
            day_of_week,
            name,
            command_line,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

#[derive(Serialize)]
pub struct TxDirContentCounts {
    device_name: String,
    src_ip: String,
    pub parent_data_type: String,
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub hard_link_count: i128,
    pub visible_count: i128,
    pub hidden_count: i128,
    pub tags: Vec<String>
}
impl TxDirContentCounts {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            hard_link_count: i128,
            visible_count: i128,
            hidden_count: i128,
            tags: Vec<String>) -> TxDirContentCounts {
        TxDirContentCounts {
            device_name: DEVICE_NAME.to_string(),
            src_ip: DEVICE_IP.to_string(),
            parent_data_type,
            data_type,
            timestamp,
            path,
            hard_link_count,
            visible_count,
            hidden_count,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}