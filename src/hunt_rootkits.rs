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
    path::{Path, PathBuf}, os::unix::prelude::{MetadataExt, PermissionsExt}, 
    fs, 
    io::{BufReader, BufRead, self}};
use memmap2::MmapOptions;
use crate::{process_process, 
    process_file, 
    data_defs::{TxKernelTaint, TxHiddenData, TxFileContent, sort_hashset, TxProcessMaps, TxGeneral}, 
    time::get_now, 
    file_op::{read_file_bytes, u8_to_hex_string, find_files_with_permissions}, 
        mutate::{to_u128, to_int32, push_file_path}};


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
                    ["ModulesHidden".to_string()].to_vec());
    find_hidden_sys_modules(files_already_seen, procs_already_seen, &mut tags)?;
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
pub fn get_rootkit_hidden_file_data(file_path: &Path, size: u64) -> io::Result<HashSet<String>> {
    let file = fs::File::open(file_path)?;
    let contents = read_file_bytes(&file)?;
    let size_read = contents.len() as u64;
    // if file size on disk is larger than file size read, there may be a root kit hiding data in the file
    let mut tags: HashSet<String> = HashSet::new();
    if size <= size_read { return Ok(tags) }
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let mut differences = Vec::new();
    for (i, (a, b)) in contents.iter().zip(mmap.iter()).enumerate() {
        if a != b {
            differences.extend_from_slice(&mmap[i..]); // starting at the first difference found copy it and the rest of the file
            break;
        }
    }
    if differences.is_empty() { return Ok(tags) }
    tags.insert("HiddenData".to_string());
    TxHiddenData::new(
        "File".to_string(), 
        "HiddenData".to_string(), 
        get_now()?, 
        (file_path.to_string_lossy()).into_owned(), 
        size, size_read, sort_hashset(tags.clone())).report_log();
    TxFileContent::new(
        "Rootkit".to_string(), 
        "FileContent".to_string(), 
        get_now()?, 
        file_path.to_string_lossy().into_owned(), 
        String::from_utf8_lossy(&differences).into_owned(), 
        u8_to_hex_string(&differences)?, sort_hashset(tags.clone())).report_log();
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
        let pid = base_path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        get_process_maps("ProcMimic", &base_path, pid, files_already_seen, 
                        procs_already_seen, tags)?;
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
            get_process_maps("ProcHiddenParent", &path, pid, files_already_seen, 
                            procs_already_seen, tags)?;
        }
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
        get_process_maps("ProcHidden", &proc_dir.to_path_buf(), &pid.to_string(), 
                        files_already_seen, procs_already_seen, tags)?;
    }

    Ok(())
}

fn get_process_maps(pdt: &str, proc_path: &PathBuf, pid: &str, files_already_seen: &mut HashSet<String>,
                    procs_already_seen: &mut HashMap<String, String>, 
                    tags: &mut HashSet<String>) -> io::Result<()> {
    let maps_path = proc_path.join("maps");
    let file = fs::File::open(maps_path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let address_range = fields[0].to_string();
        let permissions = fields[1].to_string();
        let offset = fields[2].to_string();
        let device = fields[3].to_string();
        let inode = to_u128(fields[4])?;
        let map_path = fields.get(5).unwrap_or(&"").to_string();
        let data_type = "ProcessMap".to_string();
        TxProcessMaps::new(pdt.to_string(), 
                data_type.clone(), get_now()?, 
                map_path.clone(), to_int32(pid)?, address_range, 
                permissions, offset, device, inode,
                sort_hashset(tags.clone())).report_log();
        let mp = push_file_path(&map_path, "")?;
        process_file(&data_type, &mp, files_already_seen, tags);
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
                    get_process_maps("ThreadMimic", &path, pid, files_already_seen, 
                                    procs_already_seen, tags)?;
                }
            }
        }
    }
    Ok(())
}

fn find_hidden_sys_modules(files_already_seen: &mut HashSet<String>,
                            procs_already_seen: &mut HashMap<String, String>, 
                            tags: &mut HashSet<String>) -> io::Result<()> {
    let metadata = fs::metadata("/sys/module")?;
    let hard_links = metadata.nlink();

    let visible_entries = fs::read_dir("/sys/module")?
        .filter(|entry| entry.is_ok())
        .count() as u64;

    let hidden_count = hard_links - visible_entries - 2;

    if hidden_count > 0 {
        let msg = format!("Hard Links: {}; Visible Entries: {}; Hidden Count: {}", 
                                hard_links, visible_entries, hidden_count);
        let pdt = "Rootkit".to_string();
        TxGeneral::new(pdt.to_string(), 
                "ModuleHidden".to_owned(), get_now()?, msg,
                sort_hashset(tags.clone())).report_log();
        process_file(&pdt, Path::new("/sys"), files_already_seen, tags);
    }
    Ok(())
}