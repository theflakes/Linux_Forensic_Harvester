extern crate serde;             // needed for json serialization
extern crate serde_derive;      // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate docopt;

use serde::Serialize;
use serde_derive::{Deserialize};
use std::io::prelude::{Write};
use docopt::Docopt;
use std::thread;

pub const USAGE: &'static str = "
Linux Forensic Harvester
    Author: Brian Kellogg
    License: MIT
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

If not run as root, not all telemetry can be harvested.

Usage:
  lin_fh [--ip <ip> --port <port>]
  lin_fh [--ip <ip> --port <port>] [--limit]
  lin_fh --suidsgid [--limit]
  lin_fh --limit
  lin_fh --help

Options:
  -h, --help            Print help
  -i, --ip <ip>         IP address to send output to [default: NONE]
  -p, --port <port>     Destination port to send output to [default: 80]
  -l, --limit           Limit CPU use
  -s, --suidsgid        Search for suid and sgid files

Note:
  If not run as root some telemetry cannot be harvested.
  
  To capture network output, start a netcat listener on your port of choice.
  Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

  Files larger than 256MB will not be hashed.
";

#[derive(Debug, Deserialize)]
pub struct Args {
    flag_ip: String,
    flag_port: u16,
    flag_limit: bool,
    pub flag_suidsgid: bool
}


lazy_static! { 
    pub static ref ARGS: Args = Docopt::new(USAGE)
                    .and_then(|d| d.deserialize())
                    .unwrap_or_else(|e| e.exit());
}

pub fn sleep() {
    if ARGS.flag_limit {
        thread::sleep(std::time::Duration::from_millis(1));
    }
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

// holds file metadata info
#[derive(Serialize)]
pub struct TxFile {
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
    pub suid: bool,
    pub sgid: bool
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
            suid: bool,
            sgid: bool) -> TxFile {
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
            hidden,
            uid,
            gid,
            nlink,
            inode,
            permissions,
            suid,
            sgid
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
    pub parent_data_type: String,
    #[serde(default = "FileContent")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub line: String,
    pub bytes: String
}
impl TxFileContent {
    pub fn new(
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// holds symlink metdata
#[derive(Serialize)]
pub struct TxLink {
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
    pub hidden: bool
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold process metadata info from procfs
#[derive(Serialize)]
pub struct TxProcess {
    pub parent_data_type: String,
    #[serde(default = "Process")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub exists: bool,
    pub command_line: String,
    pub pid: i32,
    pub ppid: i32,
    pub env: String,
    pub root_directory: String,
    pub current_working_directory: String
}
impl TxProcess {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            exists: bool,
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
            exists,
            command_line,
            pid,
            ppid,
            env,
            root_directory,
            current_working_directory
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
    #[serde(default = "Process")]
    pub parent_data_type: String,
    #[serde(default = "ProcessOpenFile")]
    pub data_type: String,
    pub timestamp: String,
    pub pid: i32,
    pub link: String,
    pub path: String,
    pub exists: bool
}
impl TxProcessFile {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            pid: i32,
            link: String,
            path: String,
            exists: bool) -> TxProcessFile {
        TxProcessFile {
            parent_data_type,
            data_type,
            timestamp,
            pid,
            link,
            path,
            exists
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
    pub parent_data_type: String,
    #[serde(default = "LocalUser")]
    pub data_type: String,
    pub timestamp: String,
    pub account_name: String,
    pub uid: i32,
    pub gid: i32,
    pub description: String,
    pub home_directory: String,
    pub shell: String
}
impl TxLocalUser {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            account_name: String, 
            uid: i32,
            gid: i32, 
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold group metadata
#[derive(Serialize)]
pub struct TxLocalGroup {
    pub parent_data_type: String,
    #[serde(default = "LocalGroup")]
    pub data_type: String,
    pub timestamp: String,
    pub group_name: String,
    pub gid: String,
    pub members: String
}
impl TxLocalGroup {
    pub fn new(
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold loaded kernel modules metadata
#[derive(Serialize)]
pub struct TxLoadedModule {
    pub parent_data_type: String,
    #[serde(default = "KernelModule")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub size: i64,                  // module size in memory
    pub loaded: i8,                 // how many times the module is loaded
    pub dependencies: String,       // other modules this module is dependant on
    pub state: String,              // state is: Live, Loading, or Unloading
    pub memory_offset: String       // location in kernel memory of module
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold mount point metadata
#[derive(Serialize)]
pub struct TxMountPoint {
    pub parent_data_type: String,
    #[serde(default = "MountPoint")]
    pub data_type: String,
    pub timestamp: String,
    pub name: String,
    pub mount_point: String,
    pub file_system_type: String,
    pub mount_options: String
}
impl TxMountPoint {
    pub fn new(
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

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// hold network connection metadata
#[derive(Serialize)]
pub struct TxNetConn {
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
    pub inode: i128
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
            inode: i128) -> TxNetConn {
        TxNetConn {
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
            inode
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
    pub account_name: String, 
    pub command_line: String
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
            account_name: String, 
            command_line: String) -> TxCron {
        TxCron {
            parent_data_type,
            data_type,
            timestamp,
            path,
            minute,
            hour,
            day_of_month,
            month,
            day_of_week,
            account_name,
            command_line
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}