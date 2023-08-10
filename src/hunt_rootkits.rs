/*
    References: 
        https://github.com/tstromberg/sunlight/tree/main
        https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
        https://www.linkedin.com/pulse/detecting-linux-kernel-process-masquerading-command-line-rowland/

    Needs major cleanups but just want to get it to work as soon as I can.
    A lot of duplicate logic and too many unwraps.
*/

use std::{
    collections::{HashSet, HashMap}, 
    time::{SystemTime, UNIX_EPOCH}, 
    path::{Path, PathBuf}, os::unix::prelude::{MetadataExt, PermissionsExt, FileTypeExt}, 
    fs, 
    io::{BufReader, BufRead, self, Read}};
use memmap2::MmapOptions;
use crate::{process_process, 
    process_file, 
    data_defs::{TxKernelTaint, TxHiddenData, TxFileContent, sort_hashset, TxProcessMaps, TxGeneral, TxDirContentCounts, TxCharDevice, sleep}, 
    time::{get_now, get_epoch_start}, 
    file_op::{read_file_bytes, u8_to_hex_string, find_files_with_permissions, get_directory_content_counts, parse_permissions}, 
        mutate::{to_u128, to_int32, push_file_path, format_date}};


pub fn rootkit_hunt(files_already_seen: &mut HashSet<String>, 
                    procs_already_seen: &mut HashMap<String, String>) -> io::Result<()> {
    let mut tags = reset_tags("Rootkit", 
                        ["KernelTaint".to_string()].to_vec());
    examine_kernel_taint(&mut tags);

    tags = reset_tags("Rootkit", 
                    ["ProcHidden".to_string()].to_vec());
    find_hidden_procs(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ProcLockWorldRead".to_string()].to_vec());
    find_files_with_permissions(Path::new("/run"), 
                    0o644, files_already_seen, 
                    &"Rootkit",
                    tags);

    tags = reset_tags("Rootkit", 
                    ["ProcMimic".to_string()].to_vec());
    match find_proc_mimics(files_already_seen, procs_already_seen, &mut tags) {
        Ok(it) => it,
        Err(err) => (()),
    };

    tags = reset_tags("Rootkit", 
                    ["ProcHiddenParent".to_string()].to_vec());
    find_hidden_parent_procs(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ThreadMimic".to_string()].to_vec());
    find_thread_mimics(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ModuleHidden".to_string()].to_vec());
    find_hidden_sys_modules(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["PacketSniffer".to_string()].to_vec());
    find_raw_packet_sniffer(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ProcLockSus".to_string()].to_vec());
    find_odd_run_locks(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ProcTakeover".to_string()].to_vec());
    find_proc_takeover(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["ProcRootSocketNoDeps".to_string()].to_vec());
    find_proc_root_socket_no_deps(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", 
                    ["CharDeviceMimic".to_string()].to_vec());
    find_char_device_mimic(&mut tags)?;
    Ok(())
}

fn reset_tags(always_add: &str, extend_with: Vec<String>) -> HashSet<String> {
    let mut tags: HashSet<String> = HashSet::new();
    tags.insert(always_add.to_string());
    tags.extend(extend_with);
    return tags
}

fn examine_kernel_taint(tags: &mut HashSet<String>) -> io::Result<()> {
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
    TxKernelTaint::new("Rootkit".to_string(), 
                        "KernelTaint".to_string(), get_now()?, 
                        is_tainted, taint, results, 
                        sort_hashset(tags.clone())).report_log();
    Ok(())
}

/*
    Compare file read by std api with mmap read file
    and report any bytes that are only found in mmap
    based upon a byte by byte comparison
    See: https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
*/
pub fn get_rootkit_hidden_file_data(file_path: &Path, size_on_disk: u64) -> io::Result<HashSet<String>> {
    let mut tags: HashSet<String> = HashSet::new();
    let mut file = fs::File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let std_read_size = contents.len() as u64;
    let contents_str = String::from_utf8_lossy(&contents);
    // if file size on disk is larger than file size read, there may be a root kit hiding data in the file
    if size_on_disk <= std_read_size { return Ok(tags) }

    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let mmap_read_size = mmap.len() as u64;
    let mmap_str = std::str::from_utf8(&mmap[..]).unwrap_or_default();
    let mmap_contents: Vec<&str> = mmap_str.lines().collect();

    let mut diff = Vec::new();
    let mut diff_bytes = Vec::new();
    for line in mmap_contents {
        if !contents_str.contains(&line.to_string()) {
            diff.push(line.to_string());
            diff_bytes.extend_from_slice(line.as_bytes());
        }
    }
    if diff.is_empty() { return Ok(tags) }
    let diff_string = format!("{:?}", diff);
    tags.insert("DataHidden".to_string());
    let bytes = u8_to_hex_string(&diff_bytes)?;
    TxHiddenData::new(
        "File".to_string(), 
        "DataHidden".to_string(), 
        get_now()?, 
        (file_path.to_string_lossy()).into_owned(), 
        size_on_disk, 
        std_read_size, 
        mmap_read_size,
        diff_string.clone(),
        bytes.clone(),
        sort_hashset(tags.clone())).report_log();
    TxFileContent::new(
        "Rootkit".to_string(), 
        "FileContent".to_string(), 
        get_now()?, 
        file_path.to_string_lossy().into_owned(), 
        diff_string, 
        bytes, sort_hashset(tags.clone())).report_log();
    Ok(tags)
}

/*
    This function needs work to remove unwraps.

    Quickly converted from: https://github.com/tstromberg/sunlight/blob/main/fake-name.sh
    Need to better understand it.
*/
fn find_proc_mimics(mut files_already_seen: &mut HashSet<String>, 
                    procs_already_seen: &mut HashMap<String, String>,
                    tags: &mut HashSet<String>) -> Result<(), Box<dyn std::error::Error>> {
    let expected: HashMap<String, i32> = [
        ("/bin/bash".to_string(), 1),
        ("/bin/dash".to_string(), 1),
        ("/usr/bin/bash".to_string(), 1),
        ("/usr/bin/perl".to_string(), 1),
        ("/usr/bin/udevadm".to_string(), 1),
        ("/usr/bin/zsh".to_string(), 1),
        ("/usr/lib/electron##/electron".to_string(), 1),
        ("/usr/lib/firefox/firefox".to_string(), 1),
        ("/usr/lib/firefox/firefox-bin".to_string(), 1),
        ("/usr/lib/systemd/systemd".to_string(), 1),
        ("/usr/local/bin/rootlesskit".to_string(), 1),
        ("/usr/bin/python#.#".to_string(), 1),
        ("/usr/bin/python#.##".to_string(), 1),
    ]
    .iter()
    .cloned()
    .collect();
    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() { return Ok(()) }

    for e in fs::read_dir(proc_dir)? {
        let entry = e?;
        let base_path = entry.path();
        let exe_path = base_path.join("exe");
        if !exe_path.exists() || base_path.to_str().unwrap().contains("self") { continue; }

        let path = fs::read_link(&exe_path)?;
        let name = fs::read_to_string(base_path.join("comm"))?;
        let short_name: String = name.trim()
            .split(|c| c == '-' || c == ':' || c == ' ')
            .next()
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid short name"))?
            .to_string();
        let short_base: String = base_path.to_str().unwrap().chars().take(5).collect();

        if path.to_str().unwrap().contains(&short_name) || name.trim().contains(&short_base) {
            continue;
        }

        let pattern: String = path
            .to_str()
            .unwrap()
            .chars()
            .map(|c| if c.is_numeric() { '#' } else { c })
            .collect();
        if expected.get(&pattern) == Some(&1) { continue; }
        process_process(&"Rootkit", &base_path.to_string_lossy(), &exe_path, 
                        files_already_seen, tags, procs_already_seen)?;
        sleep();
    }
    Ok(())
}

fn find_hidden_parent_procs(files_already_seen: &mut HashSet<String>,
                            procs_already_seen: &mut HashMap<String, String>, 
                            tags: &mut HashSet<String>) -> io::Result<()> {
    let proc_dir = Path::new("/proc");
    for entry in fs::read_dir(proc_dir)? {
        let e = entry?;
        let path = e.path();
        let exe_path = path.join("exe");
        let file_name = path.file_name().unwrap().to_str().unwrap();
        if file_name == "self" || !exe_path.exists() {
            continue;
        }
        let status = fs::read_to_string(path.join("status"))?;
        let parent: u32 = status
            .lines()
            .find(|line| line.starts_with("PPid:"))
            .map(|line| line.split_whitespace().nth(1).unwrap())
            .unwrap()
            .parse()
            .unwrap();
        if parent == 0 { continue; }
        if !proc_dir.join(parent.to_string()).join("comm").exists() {
            process_process(&"Rootkit", &path.to_string_lossy(), &exe_path, 
                            files_already_seen, tags, procs_already_seen)?;
            let pid = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        }
        sleep();
    }
    Ok(())
}

fn find_hidden_procs(files_already_seen: &mut HashSet<String>, 
                            procs_already_seen: &mut HashMap<String, String>, 
                            mut tags: &mut HashSet<String>) -> io::Result<()> {
    let mut visible = HashSet::new();
    let proc_dir = Path::new("/proc");

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
    for pid in 2..pid_max {
        if visible.contains(&pid) { continue; }
        let status_path = proc_dir.join(pid.to_string()).join("status");
        if !status_path.exists() { continue; }

        let status = fs::read_to_string(status_path)?;
        let tgid = status
            .lines()
            .find(|line| line.starts_with("Tgid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|tgid| tgid.parse::<u32>().ok())
            .unwrap_or_default();
        if tgid != pid { continue; }

        let exe_path = proc_dir.join(pid.to_string()).join("exe");
        let exe = fs::read_link(&exe_path).ok();
        process_process(&"Rootkit", &proc_dir.to_string_lossy(), &exe_path, 
                        files_already_seen, &mut tags, procs_already_seen)?;
        sleep();
    }

    Ok(())
}

fn find_thread_mimics(files_already_seen: &mut HashSet<String>,
                            procs_already_seen: &mut HashMap<String, String>, 
                            tags: &mut HashSet<String>) -> io::Result<()> {
    let process_dir = Path::new("/proc");
    for entry in fs::read_dir(process_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let pid = path.file_name().unwrap_or_default().to_str().unwrap_or_default();
            if pid.chars().all(char::is_numeric) {
                let cmdline_path = path.join("cmdline");
                let cmdline = fs::read_to_string(cmdline_path)?;
                if cmdline.starts_with('[') {
                    let exe = path.join("exe");
                    process_process(&"Rootkit", &path.to_string_lossy(), &exe, 
                                    files_already_seen, tags, procs_already_seen)?;
                }
            }
        }
        sleep();
    }
    Ok(())
}

fn find_hidden_sys_modules(files_already_seen: &mut HashSet<String>,
                            procs_already_seen: &mut HashMap<String, String>, 
                            tags: &mut HashSet<String>) -> io::Result<()> {
    let (hard_links, visible_entries, hidden_count) = get_directory_content_counts(Path::new("/sys/module"))?;
    if hidden_count > 0 {
        let pdt = "Rootkit".to_string();
        TxDirContentCounts::new(pdt.to_string(), 
                "ModuleHidden".to_owned(), get_now()?, "/sys/module".to_string(), 
                hard_links,visible_entries, hidden_count, 
                sort_hashset(tags.clone())).report_log();
        process_file(&pdt, Path::new("/sys/module"), files_already_seen, tags);
    }
    Ok(())
}

fn find_raw_packet_sniffer(files_already_seen: &mut HashSet<String>,
                            procs_already_seen: &mut HashMap<String, String>, 
                            tags: &mut HashSet<String>) -> io::Result<()> {
    let packet = fs::read_to_string("/proc/net/packet")?;
    let inodes: Vec<String> = packet
        .lines()
        .filter(|line| !line.starts_with("sk") && !line.contains(" 888e "))
        .map(|line| line.split_whitespace().nth(8).unwrap_or_default().to_string())
        .collect();

    let pdt = "Rootkit".to_string();
    for inode in inodes {
        let mut proc = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() { continue; }
            let path = entry.path().join("fd");
            if !path.exists() { continue; }
            for fd_entry in fs::read_dir(path)? {
                let fd_entry = fd_entry?;
                let link = fd_entry.path().read_link()?;
                if link.to_string_lossy().contains(&format!("socket:[{}]", inode)) {
                    proc.push(entry.path());
                    break;
                }
            }
        }
        if proc.is_empty() { continue; }
        let pid = proc[0].file_name().unwrap_or_default().to_string_lossy();
        let path = Path::new(&format!("/proc/{}", pid)).to_owned();
        let exe = Path::new(&format!("/proc/{}/exe", pid)).to_owned();
        process_process(&pdt, &path.to_string_lossy(), &exe, 
                        files_already_seen, tags, procs_already_seen)?;
        for line in packet.lines() {
            if line.starts_with("sk") || line.contains(&format!(" {}", inode)) {
                TxGeneral::new(pdt.clone(), 
                        "PacketSniffer".to_string(), 
                        get_now()?, line.to_string(), 
                        sort_hashset(tags.clone())).report_log();
            }
        }
    }
    Ok(())
}

fn find_odd_run_locks(files_already_seen: &mut HashSet<String>,
                    procs_already_seen: &mut HashMap<String, String>, 
                    tags: &mut HashSet<String>) -> io::Result<()> {
    let mut pids = Vec::new();
    let self_pid = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() 
            || entry.path().ends_with(std::process::id().to_string()) { continue; }
        let path = entry.path().join("fd");
        if !path.exists() { continue; }
        for fd_entry in fs::read_dir(path)? {
            let fd_entry = fd_entry?;
            let link = fd_entry.path().read_link()?;
            let l = link.to_string_lossy();
            if l.starts_with("/run/") && l.ends_with(".lock") {
                pids.push(entry.file_name().into_string().unwrap_or_default());
                break;
            }
        }
    }
    let dt = "ProcLockSus".to_string();
    for pid in pids {
        let path = Path::new(&format!("/proc/{}", pid)).to_owned();
        let exe = Path::new(&format!("/proc/{}/exe", pid)).to_owned();
        process_process(&dt, &path.to_string_lossy(), &exe, 
                        files_already_seen, tags, procs_already_seen)?;
        let fd = format!("/proc/{}/fd", pid);
        for entry in fs::read_dir(fd)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() { continue; }
            let link = entry.path().read_link()?;
            if link.to_string_lossy().contains("lock") {
                process_file(&dt, &entry.path(), files_already_seen, tags);
            }
            sleep();
        }
    }
    Ok(())
}

/*
    Need to research and test this method more, not understanding it completely

    The /proc/[pid]/map_files directory in the Linux procfs file system contains 
    symbolic links to the memory-mapped files of a process. Each entry in this 
    directory represents a memory-mapped file, with the name of the entry indicating 
    the memory address range occupied by the mapping. The symbolic link points to the 
    file that is mapped into memory.

    Memory-mapped files are used by processes to map the contents of a file into their 
    virtual address space, allowing them to access the file’s data as if it were in memory. 
    This can be useful for applications that need to work with large data sets, as it 
    allows them to access the data more efficiently.
*/
fn find_proc_takeover(files_already_seen: &mut HashSet<String>,
                        procs_already_seen: &mut HashMap<String, String>, 
                        tags: &mut HashSet<String>) -> io::Result<()> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if !path.join("exe").exists() 
            || path.ends_with("self") 
            || path.ends_with(std::process::id().to_string()) {
            continue;
        }
        let exe_path = fs::read_link(path.join("exe"))?;
        let exe = exe_path.to_string_lossy().to_string();
        let maps = fs::read_to_string(path.join("maps"))?;
        let init = maps.lines().find(|line| line.contains("r--p 00000000"));
        if init.is_none() || init.unwrap_or_default().contains("[vvar]") 
            || init.unwrap_or_default().contains(&exe) {
            continue;
        }
        let dev = init.unwrap_or_default().split_whitespace().nth(3).unwrap_or_default();
        let inode = init.unwrap_or_default().split_whitespace().nth(4).unwrap_or_default();
        if dev != "00:00" || inode != "0" { continue; }
        let segment = init.unwrap_or_default().chars().next().unwrap_or_default();
        if segment == '0' {
            let pid = path.file_name().unwrap_or_default().to_str().unwrap_or_default();
            process_process(&"Rootkit", &path.to_string_lossy(), &exe_path, 
                                    files_already_seen, tags, procs_already_seen)?;
        }
        sleep();
    }
    Ok(())
}

fn find_proc_root_socket_no_deps(files_already_seen: &mut HashSet<String>,
                                procs_already_seen: &mut HashMap<String, String>, 
                                tags: &mut HashSet<String>) -> io::Result<()> {
    let false_positive: HashMap<&str, u8> = [
        ("/usr/bin/containerd", 1),
        ("/usr/bin/fusermount3", 1),
        ("/usr/sbin/acpid", 1),
        ("/usr/sbin/mcelog", 1),
        ("/usr/bin/docker-proxy", 1),
    ]
    .iter()
    .cloned()
    .collect();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if !path.join("exe").exists() || path.ends_with("self") { continue; }
        let status = fs::read_to_string(path.join("status"))?;
        let euid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .unwrap_or_default()
            .split_whitespace()
            .nth(1)
            .unwrap();
        if euid != "0" { continue; }
        let sockets = fs::read_dir(path.join("fd"))?
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .read_link()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with("socket:")
            })
            .count();
        if sockets == 0 { continue; }
        let libs = fs::read_dir(path.join("map_files"))
            .unwrap()
            .filter_map(|entry| {
                let link = entry.unwrap().path().read_link().unwrap_or_default();
                if link.to_string_lossy().ends_with(".so") {
                    Some(link)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .len();
        if libs != 2 { continue; }
        let exe_path = fs::read_link(path.join("exe"))?;
        if false_positive.contains_key(exe_path.to_str().unwrap_or_default()) { continue; }
        process_process(&"Rootkit", &path.to_string_lossy(), &exe_path, 
                        files_already_seen, tags, procs_already_seen)?;
        sleep();
    }
    Ok(())
}

fn find_char_device_mimic(tags: &mut HashSet<String>) -> io::Result<()> {
    let expected_major: HashMap<u64, &str> = [
        (1, "memory"),
        (2, "pty master"),
        (3, "pty slave"),
        (4, "tty"),
        (5, "alt tty"),
        (6, "parallel"),
        (7, "vcs"),
        (8, "scsi tape"),
        (9, "md"),
        (10, "misc"),
        (13, "input"),
        (21, "scsi"),
        (29, "fb"),
        (81, "v4l"),
        (89, "i2c"),
        (90, "memorydev"),
        (108, "ppp"),
        (116, "alsa"),
        (180, "usb"),
        (189, "usb serial"),
        (202, "msr"),
        (203, "cpu"),
        (226, "dri"),
        (246, "ptp"),
        (247, "pps"),
        (509, "media"),
        (510, "mei"),
        (511, "hidraw")
    ].iter().cloned().collect();

    let expected_low: HashMap<&str, u32> = [
        ("bsg/", 1),
        ("dma_heap/system", 1),
        ("gpiochip", 1),
        ("hidraw", 1),
        ("media", 1),
        ("mei", 1),
        ("ngn", 1),
        ("nvme", 1),
        ("rtc", 1),
        ("watchdog", 1),
        ("tpmrm", 1)
    ].iter().cloned().collect();

    let expected_high: HashMap<&str, u32> = [
        ("drm_dp_aux", 1),
        ("iiodevice", 1),
        ("hidraw", 1),
        ("media", 1),
        ("mei", 1),
        ("tpmrm", 1)
    ].iter().cloned().collect();

    for entry in fs::read_dir("/dev")? {
        let path = entry?.path();
        
        if path.metadata()?.file_type().is_char_device() {
            let hex = path.metadata()?.rdev();
            let major = hex >> 8;
            let pattern = path.strip_prefix("/dev/")
                                .unwrap().to_str().unwrap_or_default()
                                .replace(|c: char| c.is_numeric(), "");

            if major >= 136 && major <= 143 { continue; }
            if expected_major.contains_key(&major) { continue; }

            let mut class = String::from("UNKNOWN");
            if major >= 60 && major <= 63 || major >= 120 && major <= 127 {
                class = String::from("LOCAL/EXPERIMENTAL");
            }
            if major >= 234 && major <= 254 {
                class = String::from("low dynamic");
                if expected_low.contains_key(pattern.as_str()) { continue; }
                if expected_high.contains_key(pattern.as_str()) { continue; }
            }
            if major >= 384 && major <= 511 {
                class = String::from("high dynamic");
                if expected_high.contains_key(pattern.as_str()) { continue; }
            }
            let md = fs::metadata(&path)?;
            let permissions = parse_permissions(md.mode());
            let uid = md.uid();
            let gid = md.gid();
            let inode = md.ino();
            let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
            if md.created().is_ok() { 
                ctime = format_date(md.created()?.into())?; 
            }
            let atime = format_date(md.accessed()?.into())?;
            let wtime = format_date(md.modified()?.into())?;
            let p = path.to_string_lossy();
            TxCharDevice::new("Rootkit".to_string(), "CharDeviceMimic".to_string(), 
                        get_now()?, p.to_string(), class, pattern, major, permissions,
                        uid, gid, inode, atime, wtime, ctime,
                        sort_hashset(tags.clone())).report_log();
        }
        sleep();
    }
    Ok(())
}