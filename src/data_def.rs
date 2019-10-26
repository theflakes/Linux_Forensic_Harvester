extern crate serde;             // needed for json serialization
extern crate serde_derive;      // needed for json serialization
extern crate serde_json;        // needed for json serialization

use serde_derive::{Serialize};

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
    pub nlink: u64,
    pub inode: u64
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
            nlink: u64, // number of hard links to file
            inode: u64) -> TxFile {
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
            inode
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
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// hold mount point metadata
#[derive(Serialize)]
pub struct TxMountPoint {
    pub parent_data_type: String,
    #[serde(default = "KernelModule")]
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
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

    // convert struct to json
    fn to_log(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(l) => return l,
            _ => return "".into()
        };
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        println!("{}", self.to_log());
    }
}

// tracks path of file and the parent data_type that caused us to look at the file
pub struct FileParent {
    pub parent_data_type: String,
    pub path: std::path::PathBuf
}

// holds info on metadata for file content
pub struct FileContentMetaData {
    pub md5: String,
    pub mime_type: String
}

// holds ip socket
pub struct Socket {
    pub ip: String,
    pub port: u16
}