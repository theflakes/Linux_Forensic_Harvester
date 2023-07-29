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
extern crate memmap2;

#[macro_use] extern crate lazy_static;

mod data_defs;
mod file_op;
mod mutate;
mod time;
mod hunts;

use chrono::format::format;
use hunts::*;
use serde::de::IntoDeserializer;
use walkdir::WalkDir;
use std::{fs::{self, DirEntry, File}, path::{PathBuf, Path}};
use regex::Regex;
use {data_defs::*, file_op::*, mutate::*, time::*};
use std::os::unix::fs::MetadataExt;
use nix::unistd::Uid;
use std::sync::Mutex;
use std::process;
use memmap2::{Mmap, MmapOptions};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashSet;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

lazy_static! {
    pub static ref IS_ROOT: bool = Uid::effective().is_root();
}

// file paths we want to watch all files in
const WATCH_PATHS: [&str; 14] = [
    "/etc",
    "/home",
    "/lib/modules",
    "/proc",
    "/root",
    "/srv",
    "/tmp",
    "/usr/lib/systemd/system",
    "/usr/local/var/www/html",
    "/usr/share/nginx/html",
    "/usr/share/nginx/www",
    "/var/log",
    "/var/spool/cron",
    "/var/www",
    ];
// files mime types whose content we want to look at for interesting things
const WATCH_FILE_TYPES: [&str; 25] = [
    "abiword",
    "/pdf",
    "/pkix-cert+pem",
    "/rtf",
    "/vnd.iccprofile",
    "/x-desktop",
    "/x-object",
    "/x-pcapng",
    "/x-perl",
    "/x-sh",
    "/x-tcl",
    "/xml",
    "bittorrent",
    "excel",
    "javascript",
    "json",
    "msword",
    "officedocument",
    "opendocument",
    "powerpoint",
    "presentation",
    "stardivision",
    "text/",
    "wordperfect",
    "yaml",
    ];

fn run_hunts(pdt: &str, file: &str, text: &str) ->  std::io::Result<Vec<String>> {
    let mut tags: Vec<String> = Vec::new();
    if found_base64(pdt, file, text, &"base64")? { tags.push("base64".to_string()) }
    if found_email(pdt, file, text, &"email")? { tags.push("email".to_string()) }
    if found_encoding(pdt, file, text, &"encoding")? { tags.push("encoding".to_string()) }
    if found_hex(&text.as_bytes().to_vec(), &FIND_HEX)? {tags.push("hex".to_string())}
    if found_ipv4(pdt, file, text, &"ipv4")? { tags.push("ipv4".to_string()) }
    if found_ipv6(pdt, file, text, &"ipv6")? { tags.push("ipv6".to_string()) }
    if found_obfuscation(pdt, file, text, &"obfuscation")? { tags.push("obfuscation".to_string()) }
    if found_regex(pdt, file, text, &"regex")? { tags.push("regex".to_string()) }
    if found_righttoleft(pdt, file, file, &"rightleft")? { tags.push("rightleft".to_string()) }
    if found_shell(pdt, file, text, &"shell")? { tags.push("shell".to_string()) }
    if found_shellcode(pdt, file, text, &"shellcode")? { tags.push("shellcode".to_string()) }
    if found_suspicious(pdt, file, text, &"suspicious")? { tags.push("suspicious".to_string()) }
    if found_unc(pdt, file, text, &"unc")? { tags.push("unc".to_string()) }
    if found_url(pdt, file, text, &"url")? { tags.push("url".to_string()) }
    if found_webshell(pdt, file, text, &"webshell")? { tags.push("webshell".to_string()) }
    Ok(tags)
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
        let path = Path::new(&c[1]);
        process_file("FileContent", path, already_seen)?;
    }
    Ok(())
}

// take IPv4 socket and translate it
fn get_ipv4_port(socket: &str) -> std::io::Result<(String, u16)> {
    let (ip, port) =
        match socket
            .split(':')
            .map(|s| {
                u32::from_str_radix(s, 0x10)
                    .expect("hex number")
            })
            .collect::<::arrayvec::ArrayVec<u32, 2>>()
            [..]
        {
            | [ip, port] => (std::net::Ipv4Addr::from(u32::from_be(ip)).to_string(), port as u16),
            | _          => panic!("Invalid input!"),
        };
    return Ok((ip, port));
}

// take IPv6 socket and translate it
fn get_ipv6_port(socket: &str) -> std::io::Result<(String, u16)> {
    let (ip, port) = match socket
            .split(':')
            .map(|s| {
                u128::from_str_radix(s, 0x10)
                    .expect("hex number")
            })
            .collect::<::arrayvec::ArrayVec<u128, 2>>()
            [..]
        {
            | [ip, port] => (u128_to_ipv6(u128::from(ip))?.to_string(), port as u16),
            | _          => panic!("Invalid input!"),
        };
    return Ok((ip, port));
}

// is the IP an IPv4 or IPv6
fn get_ip_port(socket: &str) -> std::io::Result<(String, u16)> {
    let (ip, port) = match socket.len() {
        13 => get_ipv4_port(socket)?,
        _ => get_ipv6_port(socket)?
    };
    return Ok((ip, port));
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
            let conns = push_file_path("/proc/net/", f)?;
            let file_contents = read_file_string(&conns)?;
            let search = "(?mi)^.+ ".to_owned() + &inode + " .+$";
            let re = Regex::new(&search).expect("bad regex");
            let mut matched = false;
            for c in re.captures_iter(&file_contents) {
                let line = &c[0];
                let fields: Vec<&str> = line.trim().split(" ").collect();
                if fields.len() > 8 {
                    let (local_ip, local_port) = get_ip_port(fields[1].trim())?;
                    let (remote_ip, remote_port) = get_ip_port(fields[2].trim())?;
                    TxNetConn::new(*IS_ROOT, "Process".to_string(), "NetConn".to_string(), get_now()?, 
                                    path.to_string(), pid, to_int32(fields[7])?, local_ip, 
                                    local_port, remote_ip, remote_port, get_tcp_state(fields[3])?, 
                                    to_int128(&inode)?, Vec::new()).report_log();
                }
                matched = true;
            }
            if matched { break };
        }
    }
    Ok(())
}

/*
    report on open files for each process
*/
fn process_open_file(pdt: &str, fd: &str, path: &str, pid: i32, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let data_type = "ProcessOpenFile".to_string();
    TxProcessFile::new(*IS_ROOT, pdt.to_string(), data_type.clone(), get_now()?, 
                        pid, fd.to_string(), path.to_string(), 
                        path_exists(fd), Vec::new()).report_log();
    process_file(&data_type, Path::new(path), already_seen)?;
    Ok(())
}

/*
    examine file descriptors
    /proc/{PID}/fd

    socket: --> open network connection
    pipe: --> open redirector
*/
fn process_file_descriptors(path: &str, root_path: &str, pid: i32, pdt: &str, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let descriptors = push_file_path(root_path, "/fd")?;
    for d in WalkDir::new(descriptors)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok()).skip(1) {   // skip the first entry as it's just the "./fd" directory 
        let entry: String = resolve_link(d.path())?.to_string_lossy().into();
        match entry {
            ref s if s.contains("socket:") => process_net_conn(path, &entry, pid)?,
            _ => match process_open_file(&pdt, &d.path().to_string_lossy(), &entry, pid, already_seen) {
                Ok(f) => f,
                Err(_e) => continue }
        };
    }
    Ok(())
}

// gather and report process information via procfs
fn process_process(pdt: &str, root_path: &str, bin: &PathBuf, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let path: String = resolve_link(&bin)?.to_string_lossy().into();
    let exists = path_exists(&path);
    let cmd = read_file_string(&push_file_path(root_path, "/cmdline")?)?;
    let cwd = resolve_link(&push_file_path(root_path, "/cwd")?)?;
    let env = read_file_string(&push_file_path(root_path, "/environ")?)?;
    let root = resolve_link(&push_file_path(root_path, "/root")?)?;
    let subs = split_to_vec(root_path, "/")?;
    let sub = match subs.iter().next_back() {
        Some(s) => s,
        None => ""
    };
    let pid = to_int32(sub)?;
    let stat = split_to_vec(&read_file_string(&push_file_path(root_path, "/stat")?)?, " ")?;
    let mut data_type = "Process".to_string();
    let ppid = to_int32(&stat[3])?;
    TxProcess::new(*IS_ROOT, pdt.to_string(), data_type.clone(), get_now()?, 
                    path.clone(), exists, cmd, pid, ppid, env, 
                    root.to_string_lossy().into(),
                    cwd.to_string_lossy().into(), Vec::new()).report_log();
    if pdt.eq("Rootkit") { data_type = "Rootkit".to_string(); }
    process_file_descriptors(&path, root_path, pid, &data_type, already_seen)?;
    Ok(())
}

fn find_rootkit_hidden_procs(already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let mut visible = HashSet::new();
    let proc_dir = Path::new("/proc");
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    for entry in fs::read_dir(proc_dir)? {
        let entry = entry?;
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            visible.insert(pid);
        }
    }

    let pid_max = fs::read_to_string("/proc/sys/kernel/pid_max")?
        .trim()
        .parse::<u32>()
        .unwrap();
    for pid in 2..=pid_max {
        if visible.contains(&pid) {
            continue;
        }
        let status_path = proc_dir.join(pid.to_string()).join("status");
        if !status_path.exists() {
            continue;
        }
        if status_path.metadata()?.mtime() as u64 >= start {
            continue;
        }

        let status = fs::read_to_string(status_path)?;
        let tgid = status
            .lines()
            .find(|line| line.starts_with("Tgid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|tgid| tgid.parse::<u32>().ok())
            .unwrap();
        if tgid != pid {
            continue;
        }
        let exe_path = proc_dir.join(pid.to_string()).join("exe");
        let exe = fs::read_link(&exe_path).ok();
        process_process(&"Rootkit", &proc_dir.to_string_lossy(), &exe_path, already_seen)?;
    }

    Ok(())
}

// parse modules in /proc/modules
fn parse_modules(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(" ").collect();
        let name = values[0].to_string();
        let size = to_int64(values[1])?;
        let loaded = to_int8(values[2])?;
        let mut dependencies = values[3].replace(",", ", ").trim().to_string();
        if dependencies.ends_with(",") { dependencies.pop(); }
        let state = values[4].to_string();
        let offset = values[5].to_string();
        TxLoadedModule::new(*IS_ROOT, pdt.to_string(), "KernelModule".to_string(), get_now()?, 
                            name, size, loaded, dependencies, state, offset, Vec::new()).report_log();
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
        TxMountPoint::new(*IS_ROOT, pdt.to_string(), "MountPoint".to_string(), get_now()?, 
                            name, mount_point, file_system_type, mount_options, Vec::new()).report_log();
    }
    Ok(())
}

// start processing procfs to gather process metadata
fn examine_procs(pdt: &str, path: &str, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    lazy_static! { 
        static ref PID: Regex = Regex::new(r#"(?mix)^/proc/\d{1,5}$"#)
                                        .expect("Invalid Regex");
    }
    let pid_ends = format!("/{}", process::id());
    let pid_contains = format!("{}/", pid_ends);
    for entry in WalkDir::new(path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok()) {
        let p: &str = &*(entry.path().to_string_lossy().to_string());
        if p.ends_with(&pid_ends) || p.contains(&pid_contains) { continue; } // do not examine our own process
        match p {
            "/proc/modules" => parse_modules(pdt, &p)?,
            "/proc/mounts" => parse_mounts(pdt, &p)?,
            _ => {
                if !PID.is_match(&p) { continue };
                let bin = push_file_path(p, "/exe")?;
                process_process(&pdt, &p, &bin, already_seen)?;
                match process_file("Process", &bin, already_seen)  {
                    Ok(_) => continue,
                    Err(_) => continue,
                };
            }
        };
        sleep();
    }
    Ok(())
}

// parse local users
fn parse_users(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(":").collect();
        let account_name = values[0].to_string();
        let uid = to_int32(values[2])?;
        let gid = to_int32(values[3])?;
        let description = values[4].to_string();
        let home_directory = values[5].to_string();
        let shell = values[6].to_string();
        TxLocalUser::new(*IS_ROOT, pdt.to_string(), "LocalUser".to_string(), get_now()?, 
                        account_name, uid, gid, description, home_directory, 
                        shell, Vec::new()).report_log();
    }
    Ok(())
}

// parse local groups
fn parse_groups(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        let values: Vec<&str> = line.split(":").collect();
        let group_name = values[0].to_string();
        let gid: u32 = values[2].to_string().parse().unwrap();
        let members = values[3].to_string();
        TxLocalGroup::new(*IS_ROOT, pdt.to_string(), "LocalGroup".to_string(), get_now()?, 
                            group_name, gid, members, Vec::new()).report_log();
    }
    Ok(())
}

// parse cron files
fn parse_cron(pdt: &str, path: &str) -> std::io::Result<()> {
    let lines = file_to_vec(path)?;
    for line in lines {
        if line.starts_with("#") { continue }
        let fields: Vec<&str> = line.splitn(7, ' ').collect();
        if fields.len() != 7 { continue }
        let minute = fields[0].to_string();
        let hour = fields[1].to_string();
        let day_of_month = fields[2].to_string();
        let month = fields[3].to_string();
        let day_of_week = fields[4].to_string();
        let account_name = fields[5].to_string();
        let command_line = fields[6].to_string();
        TxCron::new(*IS_ROOT, pdt.to_string(), "Cron".to_string(), get_now()?, 
                    path.to_string(), minute, hour, day_of_month, month, 
                    day_of_week, account_name, command_line, Vec::new()).report_log();
    }
    Ok(())
}

// process cron directories
fn process_cron(pdt: &str, path: &str, mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    for entry in WalkDir::new(path)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir()) {
            parse_cron(pdt, &entry.path().to_string_lossy())?;
            match process_file("Cron", entry.path(), &mut already_seen) {
                Ok(_) => continue,
                Err(_) => continue,
            };
    }
    Ok(())
}

/*
    Compare file read by std api with mmap read file
    and report any bytes that are only found in mmap
    based upon a byte by byte comparison
    See: https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
*/
fn get_rootkit_hidden_file_data(file_path: &Path, size: u64) -> std::io::Result<()> {
    let file = fs::File::open(file_path)?;
    let contents = read_file_bytes(&file)?;
    let size_read = contents.len() as u64;
    // if file size on disk is larger than file size read, there may be a root kit hiding data in the file
    if size <= size_read { return Ok(()) }
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let mut differences = Vec::new();
    for (i, (a, b)) in contents.iter().zip(mmap.iter()).enumerate() {
        if a != b {
            differences.extend_from_slice(&mmap[i..]); // starting at the first difference found copy it and the rest of the file
            break;
        }
    }
    TxRootkit::new(*IS_ROOT, 
                    "File".to_string(), 
                    "Rootkit".to_string(), 
                    get_now()?, 
                    (file_path.to_string_lossy()).into_owned(), 
                    size, 
                    size_read, Vec::new()).report_log();
    if differences.is_empty() { return Ok(()) }
    TxFileContent::new(*IS_ROOT, 
        "Rootkit".to_string(), 
        "FileContent".to_string(), 
        get_now()?, 
        file_path.to_string_lossy().into_owned(), 
        String::from_utf8_lossy(&differences).into_owned(), 
        u8_to_hex_string(&differences)?, Vec::new()).report_log();
    Ok(())
}

/*
    check if a given file is one we want to inspect the contents of 
    for interesting strings and references to other files
*/
fn watch_file(pdt: &str, file_path: &Path, path: &str, mime_type: &str, size: u64, already_seen: &mut Vec<String>) -> std::io::Result<(Vec<String>)> {
    let mut tags: Vec<String> = Vec::new();
    if WATCH_FILE_TYPES.iter().any(|m| mime_type.contains(m)) {
        let data = read_file_string(file_path)?;
        if !data.is_empty() {
            find_paths(&data, already_seen)?;
            let size_read = data.len() as u64;
            get_rootkit_hidden_file_data(file_path, size)?;
            if size_read < ARGS.flag_max { tags = run_hunts(pdt, path, &data)? };
        }
    }
    Ok(tags)
}

// harvest a file's metadata
fn process_file(mut pdt: &str, file_path: &Path, already_seen: &mut Vec<String>) -> std::io::Result<()> {
    let p: String = file_path.to_string_lossy().into();
    if (file_path.is_symlink() || file_path.is_file()) && !already_seen.contains(&p.clone()) {
        already_seen.push(p);    // track files we've processed so we don't process them more than once
        let (parent_data_type, path_buf) = get_link_info(&pdt, file_path)?;   // is this file a symlink? TRUE: get symlink info and path to linked file
        
        let file = open_file(&path_buf)?;
        let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
        if file.metadata()?.created().is_ok() { 
            ctime = format_date(file.metadata()?.created()?.into())?; 
        }
        let atime = format_date(file.metadata()?.accessed()?.into())?;
        let wtime = format_date(file.metadata()?.modified()?.into())?;
        if not_in_time_window(&atime, &ctime, &wtime)? { return Ok(()) }
        let mut tags: Vec<String> = Vec::new(); 
        let size = file.metadata()?.len();
        let uid = file.metadata()?.uid();
        let gid = file.metadata()?.gid();
        let nlink = file.metadata()?.nlink();
        let inode = file.metadata()?.ino();
        let path_str = match path_buf.to_str() {
            Some(s) => s,
            None => ""
            };
        let mode = file.metadata()?.mode();
        let perms = parse_permissions(mode);
        let (is_suid, is_sgid) = is_suid_sgid(mode);
        if is_suid { tags.push("suid".to_string()) }
        if is_sgid { tags.push("sgid".to_string()) }
        let (md5, mime_type) = get_file_content_info(&file)?;

        // certain files we want to parse explicitely
        let orig_path = file_path.clone();
        let path = file_path.to_string_lossy();
        if pdt.is_empty() { pdt = &"File" }
        match path.as_ref() {
            "/etc/passwd" => parse_users(pdt, "/etc/passwd".into())?,
            "/etc/group" => parse_groups(pdt, "/etc/group".into())?,
            "/etc/crontab" => parse_cron(pdt, "/etc/crontab".into())?,
            _ => {
                tags.extend(watch_file(pdt, orig_path, path_str, &mime_type, size, already_seen)?)
            }
        }
        TxFile::new(*IS_ROOT, parent_data_type, "File".to_string(), get_now()?, 
            path_str.into(), md5, mime_type.clone(), atime, wtime, 
            ctime, size, is_hidden(&path_buf), uid, gid, 
            nlink, inode, perms, tags).report_log();
    }
    Ok(())
}

// process directories and sub dirs we are interested in
fn process_directory_files(pdt: &str, path: &str, mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    match path {
        "/proc" => examine_procs(&pdt, &path, &mut already_seen)?,
        "/etc/cron.d" => process_cron(&pdt, path, &mut already_seen)?,
        "/var/spool/cron" => process_cron(&pdt, path, &mut already_seen)?,
        _ => for entry in WalkDir::new(path)
                    .max_depth(ARGS.flag_depth)
                    .into_iter()
                    .filter_map(|e| e.ok()) {
                process_file(&pdt, entry.path(), &mut already_seen)?;
                sleep();
            },
    }
    Ok(())
}

fn str_starts_with(path: &str) -> bool {
    let does_start_with = ((WATCH_PATHS.iter().any(|p| path.starts_with(p))) 
                            || (["/dev/", "/mnt/", "/proc/", "/sys/"]
                            .iter().any(|p| path.starts_with(p))));
    return does_start_with
}

/*
 find SUID and SGID files
 Weird issue getting hung on a /proc dir on my box: /proc/4635/task/4635/net
    ls: reading directory '/proc/4635/task/4635/net': Invalid argument
    total 0
*/
fn find_suid_sgid(already_seen: &mut Vec<String>) -> std::io::Result<()> {
    for entry in WalkDir::new("/")
                    .into_iter()
                    .filter_entry(|e| !str_starts_with(&e.path().to_string_lossy()))
                    .filter_map(|e| e.ok()) {
        let md = match entry.metadata() {
            Ok(d) => d,
            Err(_e) => continue     // catch errors so we can finish searching all dirs
            };
        if md.is_file() {
            let mode = md.mode();
            let (is_suid, is_sgid) = is_suid_sgid(mode);
            if is_suid || is_sgid {
                match process_file("SuidSgid", entry.path(), already_seen) {
                    Ok(_) => continue,
                    Err(_) => continue,
                };
            }
            sleep();
        }
    }
    Ok(())
}

fn examine_kernel_taint() -> std::io::Result<()> {
    let mut taint_bits = HashMap::new();
    taint_bits.insert(0, "proprietary module was loaded");
    taint_bits.insert(1, "module was force loaded");
    taint_bits.insert(2, "kernel running on an out of specification system");
    taint_bits.insert(3, "module was force unloaded");
    taint_bits.insert(4, "processor reported a Machine Check Exception (MCE)");
    taint_bits.insert(5, "bad page referenced or some unexpected page flags");
    taint_bits.insert(6, "taint requested by userspace application");
    taint_bits.insert(7, "kernel died recently, i.e. there was an OOPS or BUG");
    taint_bits.insert(8, "ACPI table overridden by user");
    taint_bits.insert(9, "kernel issued warning");
    taint_bits.insert(10, "staging driver was loaded");
    taint_bits.insert(11, "workaround for bug in platform firmware applied");
    taint_bits.insert(12, "externally-built (out-of-tree) module was loaded");
    taint_bits.insert(13, "unsigned module was loaded");
    taint_bits.insert(14, "soft lockup occurred");
    taint_bits.insert(15, "kernel has been live patched");
    taint_bits.insert(16, "auxiliary taint, defined for and used by distros");
    taint_bits.insert(17, "kernel was built with the struct randomization plugin");
    taint_bits.insert(18, "an in-kernel test has been run");

    let taint = fs::read_to_string("/proc/sys/kernel/tainted").unwrap();
    let taint = taint.trim().parse::<u32>().unwrap();
    
    if taint == 0 { return Ok(()); }
    let is_tainted = true;

    let mut results = String::new();
    results.push_str(&format!("kernel taint value: {}\n", taint));
    for i in 1..=18 {
        let bit = i - 1;
        let match_ = (taint >> bit) & 1;
        if match_ == 0 {
            continue;
        }
        results.push_str(&format!("* matches bit {}: {}\n", bit, taint_bits[&bit]));
    }
    results.push_str("\n");
    results.push_str("dmesg:\n");
    
    let file = fs::File::open("/var/log/dmesg").unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        if line.contains("taint") {
            results.push_str(&format!("{}\n", line));
        }
    }
    
    TxKernelTaint::new(*IS_ROOT, "Rootkit".to_string(), 
                        "KernelTaint".to_string(), get_now()?, 
                        is_tainted, taint, results, 
                        Vec::new()).report_log();
    
    Ok(())
}

fn rootkit_hunt(mut already_seen: &mut Vec<String>) -> std::io::Result<()> {
    examine_kernel_taint();
    find_rootkit_hidden_procs(&mut already_seen)?;
    Ok(())
}


// let's start this thing
fn main() -> std::io::Result<()> {
    let mut already_seen = vec![];  // cache directories and files already examined to avoid multiple touches and possible infinite loops

    for path in WATCH_PATHS.iter() {
        if !path_exists(path) { continue }
        match process_directory_files("", path, &mut already_seen) {
            Ok(f) => f,
            Err(_e) => continue};
    }

    rootkit_hunt(&mut already_seen)?;
    
    if ARGS.flag_suidsgid {
        find_suid_sgid(&mut already_seen)?; 
    }
    Ok(())
}