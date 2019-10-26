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
extern crate regex;

#[macro_use] extern crate lazy_static;

mod data_def;
mod file_op;
mod mutate;
mod time;

use walkdir::WalkDir;
use std::thread;
use std::fs::{self};
use regex::Regex;
use {data_def::*, file_op::*, mutate::*, time::*};
use std::os::unix::fs::MetadataExt;

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
const WATCH_FILES: [&str; 15] = [
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
    "/.bash_history",
    "/.bash_logout",
    "/.lesshst",
    "/.viminfo",
    "/root/"
    ];


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
        let uid = file.metadata()?.uid();
        let gid = file.metadata()?.gid();
        let nlink = file.metadata()?.nlink();
        let inode = file.metadata()?.ino();
        let path = match fp.path.to_str() {
            Some(s) => s,
            None => ""
            };
        let perms = parse_permissions(file.metadata()?.mode());
        let fc = get_file_content_info(&file)?;
        drop(file); // close file handle immediately after not needed to avoid too many files open error
        TxFile::new(fp.parent_data_type, "File".to_string(), get_now()?, 
                                path.into(), fc.md5, fc.mime_type, atime, wtime, 
                                ctime, size, is_hidden(&fp.path), uid, gid, 
                                nlink, inode, perms).report_log();

        watch_file(&fp.path, path, already_seen)?;
    }
    Ok(())
}

/*
    report on network connections for each process
*/
fn process_open_file(path: &str, pid: i32) -> std::io::Result<()> {
    
    Ok(())
}

// take IPv4 socket and translate it
fn get_ipv4_port(socket: &str) -> std::io::Result<Socket> {
    let mut s = Socket {ip: "".to_string(), port: 0};
    let (ip, port) =
        match socket
                .split(':')
                .map(|s| {
                    u32::from_str_radix(s, 0x10)
                        .expect("hex number")
                })
                .collect::<::arrayvec::ArrayVec<[_; 2]>>()
                [..]
        {
            | [ip, port] => (ip, port),
            | _          => panic!("Invalid input!"),
        };
    s.ip = std::net::Ipv4Addr::from(u32::from_be(ip)).to_string();
    s.port = port as u16;
    return Ok(s);
}

// take IPv6 socket and translate it
fn get_ipv6_port(socket: &str) -> std::io::Result<Socket> {
    let mut s = Socket {ip: "".to_string(), port: 0};
    let (ip, port) =
        match socket
                .split(':')
                .map(|s| {
                    u128::from_str_radix(s, 0x10)
                        .expect("hex number")
                })
                .collect::<::arrayvec::ArrayVec<[_; 2]>>()
                [..]
        {
            | [ip, port] => (ip, port),
            | _          => panic!("Invalid input!"),
        };
    s.ip = u128_swap_u32s_then_to_ipv6(u128::from(ip))?.to_string();
    s.port = port as u16;
    return Ok(s);
}

// is the IP an IPv4 or IPv6
fn get_ip_port(socket: &str) -> std::io::Result<Socket> {
    let s;
    if socket.len() < 14 {  // kludge to distringuish ipv4 from ipv6 sockets. Do something more professional!
        s = get_ipv4_port(socket)?;
    } else {
        s = get_ipv6_port(socket)?;
    }
    return Ok(s);
}

/*
    report on network connections for each process
    /proc/net/{tcp, tcp6, udp, udp6}
*/
fn process_net_conn(path: &str, conn: &str, pid: i32) -> std::io::Result<()> {
    const NET_CONNS: [&str; 4] = ["tcp", "tcp6", "udp", "udp6"];
    let tmp: Vec<&str> = conn.split("[").collect();
    if tmp.len() > 1 {
        let inode = tmp[1].replace("]", "");
        for f in NET_CONNS.iter() {
            let conns = push_file_path("/proc/net/", f);
            let file_contents = read_file_string(&conns)?;
            let search = "(?mi)^.+ ".to_owned() + &inode + " .+$";
            let re = Regex::new(&search).expect("bad regex");
            let mut matched = false;
            for c in re.captures_iter(&file_contents) {
                let line = &c[0];
                let fields: Vec<&str> = line.trim().split(" ").collect();
                if fields.len() > 8 {
                    let local = get_ip_port(fields[1])?;
                    let remote = get_ip_port(fields[2])?;
                    TxNetConn::new("Process".to_string(), "NetConn".to_string(), get_now()?, 
                                            path.to_string(), pid, to_int32(fields[7]), local.ip, 
                                            local.port, remote.ip, remote.port, get_tcp_state(fields[3]), 
                                            to_int128(&inode)).report_log();
                }
                matched = true;
            }
            if matched { break };
        }
    }
    Ok(())
}

/*
    examine file descriptors
    /proc/{PID}/fd

    socket: --> open network connection
    pipe: --> open redirector
*/
fn process_file_dscriptors(path: &str, root_path: &str, pid: i32) -> std::io::Result<()> {
    let descriptors = push_file_path(root_path, "/fd");
    for d in WalkDir::new(descriptors)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok()) {
        let entry: String = resolve_link(d.path())?.to_string_lossy().into();
        if entry.contains("socket:") {
            process_net_conn(path, &entry, pid)?;
        } else if entry.contains("pipe:") {
            process_open_file(&entry, pid)?;
        } else {

        }
    }
    Ok(())
}

// gather and report process information via procfs
fn process_process(root_path: &str, bin: std::path::PathBuf) -> std::io::Result<()> {
    let path: String = resolve_link(&bin)?.to_string_lossy().into();
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
                            path.clone(), cmd, pid, ppid, env, root.to_string_lossy().into(),
                            cwd.to_string_lossy().into()).report_log();
    process_file_dscriptors(&path, root_path, pid)?;
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

// parse local users
fn parse_users(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(":").collect();
        let account_name = values[0].to_string();
        let uid = to_int32(values[2]);
        let gid = to_int32(values[3]);
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

// find SUID and SGID files
fn find_suid_sgid(already_seen: &mut Vec<String>) -> std::io::Result<()> {
    for entry in WalkDir::new("/")
                    .into_iter()
                    .filter_map(|e| e.ok()) {
        let md = entry.metadata()?;
        if md.is_file() {
            let mode = md.mode();
            let pdt = is_suid_sgid(mode);
            if !pdt.is_empty() {
                process_file(&pdt, &entry.into_path(), already_seen)?;
            }
            thread::sleep(std::time::Duration::from_millis(1));  // sleep so we aren't chewing up too much cpu
        }
    }
    Ok(())
}

// let's start this thing
fn main() -> std::io::Result<()> {
    let mut already_seen = vec![];  // cache directories and files already examined to avoid multiple touches and possible infinite loops

    for path in WATCH_PATHS.iter() {
        if !path_exists(path) { continue }
        let md = fs::metadata(path)?;
        let pdt = is_suid_sgid(md.mode());
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
    find_suid_sgid(&mut already_seen)?; // WARNING: searches entire directory structure
    Ok(())
}