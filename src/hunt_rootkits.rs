/*
    References:
        https://github.com/tstromberg/sunlight/tree/main
        https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
        https://www.linkedin.com/pulse/detecting-linux-kernel-process-masquerading-command-line-rowland/

    Needs major cleanups but just want to get it to work as soon as I can.
    A lot of duplicate logic and too many unwraps.
*/

use crate::{
    data_defs::{
        sleep, sort_hashset, TxCharDevice, TxDirContentCounts, TxFileContent, TxGeneral,
        TxHiddenData, TxKernelTaint, TxProcessMaps,
    },
    file_op::{
        find_files_with_permissions, get_directory_content_counts, parse_permissions,
        read_file_bytes, read_file_string, resolve_link, u8_to_hex_string,
    },
    mutate::{format_date, push_file_path, to_int32, to_u128},
    process_file, process_process,
    time::{get_epoch_start, get_now},
};
use chrono::NaiveDateTime;
use memmap2::MmapOptions;
use path_abs::PathOps;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, BufRead, BufReader, Read},
    os::unix::prelude::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn rootkit_hunt(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
) -> io::Result<()> {
    let mut tags = reset_tags("Rootkit", ["KernelTaint".to_string()].to_vec());
    examine_kernel_taint(&mut tags);

    tags = reset_tags("Rootkit", ["ProcHidden".to_string()].to_vec());
    find_hidden_procs(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ProcLockWorldRead".to_string()].to_vec());
    find_files_with_permissions(
        Path::new("/run"),
        0o644,
        files_already_seen,
        &"Rootkit",
        tags,
    );

    tags = reset_tags("Rootkit", ["ProcMimic".to_string()].to_vec());
    match find_proc_mimics(files_already_seen, procs_already_seen, &mut tags) {
        Ok(it) => it,
        Err(err) => (()),
    };

    tags = reset_tags("Rootkit", ["ProcHiddenParent".to_string()].to_vec());
    find_hidden_parent_procs(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ThreadMimic".to_string()].to_vec());
    find_thread_mimics(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ModuleHidden".to_string()].to_vec());
    find_hidden_sys_modules(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["PacketSniffer".to_string()].to_vec());
    find_raw_packet_sniffer(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ProcLockSus".to_string()].to_vec());
    find_odd_run_locks(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ProcTakeover".to_string()].to_vec());
    find_proc_takeover(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["ProcRootSocketNoDeps".to_string()].to_vec());
    find_proc_root_socket_no_deps(files_already_seen, procs_already_seen, &mut tags)?;

    tags = reset_tags("Rootkit", ["CharDeviceMimic".to_string()].to_vec());
    find_char_device_mimic(&mut tags)?;
    Ok(())
}

fn reset_tags(always_add: &str, extend_with: Vec<String>) -> HashSet<String> {
    let mut tags: HashSet<String> = HashSet::new();
    tags.insert(always_add.to_string());
    tags.extend(extend_with);
    return tags;
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

    // Safely read the kernel taint value; propagate errors instead of panicking
    let taint_str = fs::read_to_string("/proc/sys/kernel/tainted")?;
    let taint: u32 = taint_str
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if taint == 0 {
        return Ok(());
    }
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

    // Safely read dmesg lines, handling I/O errors gracefully
    let file = fs::File::open("/var/log/dmesg")?;
    for line_res in BufReader::new(file).lines() {
        let line = line_res?;
        if line.contains("taint") {
            results.push_str(&format!("{}\n", line));
        }
    }
    TxKernelTaint::new(
        "Rootkit".to_string(),
        "KernelTaint".to_string(),
        get_now()?,
        is_tainted,
        taint,
        results,
        sort_hashset(tags.clone()),
    )
    .report_log();
    Ok(())
}

/*
    Compare file read by std api with mmap read file
    and report any bytes that are only found in mmap
    based upon a byte by byte comparison
    See: https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
*/
pub fn get_rootkit_hidden_file_data(
    file_path: &Path,
    size_on_disk: u64,
) -> io::Result<HashSet<String>> {
    let mut tags: HashSet<String> = HashSet::new();
    let mut file = fs::File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let std_read_size = contents.len() as u64;
    // if file size on disk is larger than file size read, there may be a root kit hiding data in the file
    if size_on_disk <= std_read_size {
        return Ok(tags);
    }

    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let mmap_read_size = mmap.len() as u64;
    let mmap_str = std::str::from_utf8(&mmap[..]).unwrap_or_default();
    let mmap_contents: Vec<&str> = mmap_str.lines().collect();

    let mut diff = Vec::new();
    let mut diff_bytes = Vec::new();
    let contents_str = String::from_utf8_lossy(&contents);
    for line in mmap_contents {
        if !contents_str.contains(&line.to_string()) {
            diff.push(line.to_string());
            diff_bytes.extend_from_slice(line.as_bytes());
        }
    }
    if diff.is_empty() {
        return Ok(tags);
    }
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
        sort_hashset(tags.clone()),
    )
    .report_log();
    TxFileContent::new(
        "Rootkit".to_string(),
        "FileContent".to_string(),
        get_now()?,
        file_path.to_string_lossy().into_owned(),
        diff_string,
        bytes,
        sort_hashset(tags.clone()),
    )
    .report_log();
    Ok(tags)
}

fn starts_with_any(path: &PathBuf, prefixes: &[&str]) -> bool {
    let path_as_os_str = path.to_string_lossy();
    prefixes
        .iter()
        .any(|&prefix| path_as_os_str.starts_with(prefix))
}

/*
    Quickly converted from: https://github.com/tstromberg/sunlight/blob/main/fake-name.sh
    Need to better understand it.
*/
fn find_proc_mimics(
    mut files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Known legitimate executables that may appear as “process mimics”.
    // These are filtered out before we flag a process as suspicious.
    const PROC_MIMIC_FALSE_POSITIVES: [&str; 4] = [
        "/usr/lib/systemd/systemd-executor",
        "/usr/sbin/sshd",
        "/usr/bin/dbus-daemon",
        "/usr/bin/gala",
    ];
    let expected: HashMap<String, i32> = [
        ("/app/lib/firefox/firefox-bin".to_string(), 1),
        ("/bin/bash".to_string(), 1),
        ("/bin/dash".to_string(), 1),
        ("/init".to_string(), 1),
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
    let prefixes = ["/.local/share/Steam/steamapps/common/Proton", "/snap/"];
    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return Ok(());
    }

    for e in fs::read_dir(proc_dir)? {
        let entry = e?;
        let base_path = entry.path();
        let exe_path = base_path.join("exe");
        // Skip entries without an executable or those pointing to the current process
        if !exe_path.exists() || base_path.to_str().map_or(false, |s| s.contains("self")) {
            continue;
        }

        // Resolve the target of the symlink; propagate errors instead of panicking
        let path = fs::read_link(&exe_path)?;

        // Filter out known false positives for proc mimics.
        if PROC_MIMIC_FALSE_POSITIVES.contains(&path.to_string_lossy().as_ref()) {
            continue;
        }
        if starts_with_any(&path, &prefixes) {
            continue;
        }
        let name = fs::read_to_string(base_path.join("comm"))?;
        // Derive a short name from the comm field; fail gracefully if malformed
        let short_name: String = name
            .trim()
            .split(|c| c == '-' || c == ':' || c == ' ')
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid short name"))?
            .to_string();
        // Use a safe conversion for the base path; skip if it cannot be represented as UTF‑8
        let short_base: String = base_path
            .to_str()
            .map_or_else(String::new, |s| s.chars().take(5).collect());
        if path.to_str().map_or(false, |p| p.contains(&short_name))
            || name.trim().contains(&short_base)
        {
            continue;
        }

        // Build a pattern by replacing numeric characters with '#'; handle non‑UTF8 paths safely
        let pattern: String = path
            .to_str()
            .map(|p| {
                p.chars()
                    .map(|c| if c.is_ascii_digit() { '#' } else { c })
                    .collect::<String>()
            })
            .unwrap_or_default();
        if expected.get(&pattern) == Some(&1) {
            continue;
        }
        process_process(
            &"Rootkit",
            &base_path.to_string_lossy(),
            &exe_path,
            files_already_seen,
            tags,
            procs_already_seen,
        )?;
        sleep();
    }
    Ok(())
}

fn find_hidden_parent_procs(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    let proc_dir = Path::new("/proc");
    // Guard against missing /proc (e.g., in very constrained containers)
    if !proc_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(proc_dir)? {
        let e = entry?;
        let path = e.path();
        let exe_path = path.join("exe");
        // Safely obtain the filename as a string; skip if unavailable
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if file_name == "self" || !exe_path.exists() {
            continue;
        }
        // Safely read the parent PID; return an error if parsing fails
        let status = fs::read_to_string(path.join("status"))?;
        // Safely read the parent PID; propagate parsing errors without panicking
        let parent: u32 = status
            .lines()
            .find(|line| line.starts_with("PPid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing PPid"))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if parent == 0 {
            continue;
        }
        // Skip known false‑positive hidden parents (e.g., containers or sandbox helpers)
        const HIDDEN_PARENT_FALSE_POSITIVES: [&str; 3] = [
            "/usr/libexec/xdg-desktop-portal",
            "/usr/bin/docker-proxy",
            "/usr/sbin/lxc-start",
        ];
        if let Ok(resolved) = resolve_link(&exe_path) {
            if HIDDEN_PARENT_FALSE_POSITIVES.contains(&resolved.to_string_lossy().as_ref()) {
                continue;
            }
        }
        if !proc_dir.join(parent.to_string()).join("comm").exists() {
            process_process(
                &"Rootkit",
                &path.to_string_lossy(),
                &exe_path,
                files_already_seen,
                tags,
                procs_already_seen,
            )?;
            let pid = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
        }
        sleep();
    }
    Ok(())
}

fn find_hidden_procs(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    mut tags: &mut HashSet<String>,
) -> io::Result<()> {
    let mut visible = HashSet::new();
    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(proc_dir)? {
        let entry = entry?;
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            visible.insert(pid);
        }
    }

    // Read the maximum PID value; propagate parsing errors instead of panicking
    let pid_max: u32 = fs::read_to_string("/proc/sys/kernel/pid_max")?
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    for pid in 2..pid_max {
        if visible.contains(&pid) {
            continue;
        }
        let status_path = proc_dir.join(pid.to_string()).join("status");
        if !status_path.exists() {
            continue;
        }

        let status = fs::read_to_string(status_path)?;
        let tgid = status
            .lines()
            .find(|line| line.starts_with("Tgid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|tgid| tgid.parse::<u32>().ok())
            .unwrap_or_default();
        if tgid != pid {
            continue;
        }

        let exe_path = proc_dir.join(pid.to_string()).join("exe");
        let exe = fs::read_link(&exe_path).ok();
        // Skip known legitimate hidden processes to avoid false positives
        const HIDDEN_PROC_FALSE_POSITIVES: [&str; 3] = [
            "/usr/libexec/xdg-desktop-portal",
            "/usr/bin/docker-proxy",
            "/usr/sbin/lxc-start",
        ];
        if let Some(ref link) = exe {
            if HIDDEN_PROC_FALSE_POSITIVES.contains(&link.to_string_lossy().as_ref()) {
                continue;
            }
        }
        process_process(
            &"Rootkit",
            &proc_dir.to_string_lossy(),
            &exe_path,
            files_already_seen,
            &mut tags,
            procs_already_seen,
        )?;
        std::hint::spin_loop();
    }

    Ok(())
}

fn find_thread_mimics(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    let process_dir = Path::new("/proc");
    for entry in fs::read_dir(process_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let pid = path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            if pid.chars().all(char::is_numeric) {
                let cmdline_path = path.join("cmdline");
                let cmdline = fs::read_to_string(cmdline_path)?;
                if cmdline.starts_with('[') {
                    let exe = path.join("exe");
                    process_process(
                        &"Rootkit",
                        &path.to_string_lossy(),
                        &exe,
                        files_already_seen,
                        tags,
                        procs_already_seen,
                    )?;
                }
            }
        }
        sleep();
    }
    Ok(())
}

fn find_hidden_sys_modules(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    let (hard_links, visible_entries, hidden_count) =
        get_directory_content_counts(Path::new("/sys/module"))?;
    if hidden_count > 0 {
        let pdt = "Rootkit".to_string();
        TxDirContentCounts::new(
            pdt.to_string(),
            "ModuleHidden".to_owned(),
            get_now()?,
            "/sys/module".to_string(),
            hard_links,
            visible_entries,
            hidden_count,
            sort_hashset(tags.clone()),
        )
        .report_log();
        process_file(&pdt, Path::new("/sys/module"), files_already_seen, tags);
    }
    Ok(())
}

fn find_raw_packet_sniffer(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    const FALSE_POSITIVES: [&str; 5] = [
        "/usr/sbin/NetworkManager",
        "/usr/sbin/wpa_supplicant",
        "/usr/lib/systemd/systemd-networkd",
        "/opt/sysmon/sysmon (deleted)",
        "/opt/sysmon/sysmon",
    ];
    let packet = fs::read_to_string("/proc/net/packet")?;
    let inodes: Vec<String> = packet
        .lines()
        .filter(|line| !line.starts_with("sk") && !line.contains(" 888e "))
        .map(|line| {
            line.split_whitespace()
                .nth(8)
                .unwrap_or_default()
                .to_string()
        })
        .collect();

    let pdt = "Rootkit".to_string();
    for inode in inodes {
        let mut proc = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path().join("fd");
            if !path.exists() {
                continue;
            }
            for fd_entry in fs::read_dir(path)? {
                let fd_entry = fd_entry?;
                let link = fd_entry.path().read_link()?;
                if link
                    .to_string_lossy()
                    .contains(&format!("socket:[{}]", inode))
                {
                    proc.push(entry.path());
                    break;
                }
            }
        }
        if proc.is_empty() {
            continue;
        }
        let pid = proc[0].file_name().unwrap_or_default().to_string_lossy();
        let path = Path::new(&format!("/proc/{}", pid)).to_owned();
        let exe = Path::new(&format!("/proc/{}/exe", pid)).to_owned();
        if FALSE_POSITIVES.contains(&resolve_link(&exe)?.to_string_lossy().as_ref()) {
            continue;
        }
        process_process(
            &pdt,
            &path.to_string_lossy(),
            &exe,
            files_already_seen,
            tags,
            procs_already_seen,
        )?;
        for line in packet.lines() {
            if line.starts_with("sk") || line.contains(&format!(" {}", inode)) {
                TxGeneral::new(
                    pdt.clone(),
                    "PacketSniffer".to_string(),
                    get_now()?,
                    line.to_string(),
                    sort_hashset(tags.clone()),
                )
                .report_log();
            }
        }
    }
    Ok(())
}

fn find_odd_run_locks(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    const PROC_FALSE_POSITIVES: [&str; 3] =
        ["/usr/bin/pipewire", "/usr/bin/gnome-shell", "/usr/bin/gala"];
    const CMD_FALSE_POSITIVES: [&str; 1] = ["C:\\windows\\system32\\services.exe"];
    let mut pids = Vec::new();
    let self_pid = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entry.path().ends_with(std::process::id().to_string()) {
            continue;
        }
        let path = entry.path().join("fd");
        if !path.exists() {
            continue;
        }
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
        if PROC_FALSE_POSITIVES.contains(&resolve_link(&exe)?.to_string_lossy().as_ref()) {
            continue;
        }
        let cmd = path.join("cmdline");
        let cmdline: &str = &read_file_string(&cmd)?;
        if CMD_FALSE_POSITIVES.contains(&cmdline) {
            continue;
        }
        process_process(
            &dt,
            &path.to_string_lossy(),
            &exe,
            files_already_seen,
            tags,
            procs_already_seen,
        )?;
        let fd = format!("/proc/{}/fd", pid);
        for entry in fs::read_dir(fd)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
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
fn find_proc_takeover(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
    // Steam and Proton create a lot of noise
    const CMD_FALSE_POSITIVES: [&str; 5] = [
        "C:\\windows\\system32\\services.exe",
        "C:\\windows\\system32\\plugplay.exe",
        "C:\\windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted",
        "C:\\windows\\system32\\rpcss.exe",
        "C:\\windows\\system32\\winedevice.exe",
    ];
    const CMD_FALSE_POSITIVES_CONTAINS: [&str; 1] =
        ["--database=C:\\users\\steamuser\\AppData\\Local\\"];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if !path.join("exe").exists()
            || path.ends_with("self")
            || path.ends_with(std::process::id().to_string())
        {
            continue;
        }
        let exe_path = fs::read_link(path.join("exe"))?;
        let exe = exe_path.to_string_lossy().to_string();
        let maps = fs::read_to_string(path.join("maps"))?;
        let init = maps.lines().find(|line| line.contains("r--p 00000000"));
        if init.is_none()
            || init.unwrap_or_default().contains("[vvar]")
            || init.unwrap_or_default().contains(&exe)
        {
            continue;
        }
        let cmd = path.join("cmdline");
        let cmdline: &str = &read_file_string(&cmd)?;
        if CMD_FALSE_POSITIVES.contains(&cmdline)
            || CMD_FALSE_POSITIVES_CONTAINS
                .iter()
                .any(|&s| cmdline.contains(s))
        {
            continue;
        }
        let dev = init
            .unwrap_or_default()
            .split_whitespace()
            .nth(3)
            .unwrap_or_default();
        let inode = init
            .unwrap_or_default()
            .split_whitespace()
            .nth(4)
            .unwrap_or_default();
        if dev != "00:00" || inode != "0" {
            continue;
        }
        let segment = init.unwrap_or_default().chars().next().unwrap_or_default();
        if segment == '0' {
            let pid = path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            process_process(
                &"Rootkit",
                &path.to_string_lossy(),
                &exe_path,
                files_already_seen,
                tags,
                procs_already_seen,
            )?;
        }
        sleep();
    }
    Ok(())
}

fn find_proc_root_socket_no_deps(
    files_already_seen: &mut HashSet<String>,
    procs_already_seen: &mut HashMap<String, String>,
    tags: &mut HashSet<String>,
) -> io::Result<()> {
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
        if !path.join("exe").exists() || path.ends_with("self") {
            continue;
        }
        let status = fs::read_to_string(path.join("status"))?;
        // Extract the effective UID safely; handle missing or malformed entries gracefully
        let euid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing Uid"))?;
        if euid != "0" {
            continue;
        }
        // Count file descriptors that are sockets, handling any errors gracefully.
        let sockets = fs::read_dir(path.join("fd"))?
            .filter(|entry| match entry {
                Ok(e) => e
                    .path()
                    .read_link()
                    .ok()
                    .and_then(|l| {
                        let s = l.to_string_lossy();
                        if s.starts_with("socket:") {
                            Some(())
                        } else {
                            None
                        }
                    })
                    .is_some(),
                Err(_) => false,
            })
            .count();
        if sockets == 0 {
            continue;
        }
        // Attempt to read the map_files directory; treat errors as an empty set of libraries
        let libs_iter = match fs::read_dir(path.join("map_files")) {
            Ok(it) => it,
            Err(_) => continue,
        };
        let libs = libs_iter
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    e.path()
                        .read_link()
                        .ok()
                        .filter(|link| link.to_string_lossy().ends_with(".so"))
                })
            })
            .collect::<Vec<_>>()
            .len();
        if libs != 2 {
            continue;
        }
        let exe_path = fs::read_link(path.join("exe"))?;
        if false_positive.contains_key(exe_path.to_str().unwrap_or_default()) {
            continue;
        }
        process_process(
            &"Rootkit",
            &path.to_string_lossy(),
            &exe_path,
            files_already_seen,
            tags,
            procs_already_seen,
        )?;
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
        (229, "hvc"),
        (246, "ptp"),
        (247, "pps"),
        (509, "media"),
        (510, "mei"),
        (511, "hidraw"),
    ]
    .iter()
    .cloned()
    .collect();

    let expected_low: HashMap<&str, u32> = [
        ("bsg/", 1),
        ("dma_heap/system", 1),
        ("gpiochip", 1),
        ("hidraw", 1),
        ("iio:device", 1),
        ("media", 1),
        ("mei", 1),
        ("ngn", 1),
        ("nvme", 1),
        ("ptp", 1),
        ("ptp_hyperv", 1),
        ("rtc", 1),
        ("watchdog", 1),
        ("tpmrm", 1),
    ]
    .iter()
    .cloned()
    .collect();

    let expected_high: HashMap<&str, u32> = [
        ("drm_dp_aux", 1),
        ("iiodevice", 1),
        ("hidraw", 1),
        ("media", 1),
        ("mei", 1),
        ("nvidia-uvm", 1),
        ("nvidia-uvm-tools", 1),
        ("tpmrm", 1),
    ]
    .iter()
    .cloned()
    .collect();

    let unknown: HashMap<&str, u32> = [
        ("nvidia", 1),
        ("nvidiactl", 1),
        ("nvidia-modeset", 1),
        ("tpmrm", 1),
        ("acpi_thermal_rel", 1),
        ("cpu_dma_latency", 1),
        ("udmabuf", 1),
        ("ecryptfs", 1),
        ("userfaultfd", 1),
        ("vga_arbiter", 1),
    ]
    .iter()
    .cloned()
    .collect();

    let unknown_partial_names: [&str; 1] = ["HID-SENSOR-"];

    for entry in fs::read_dir("/dev")? {
        let path = entry?.path();

        if path.metadata()?.file_type().is_char_device() {
            let hex = path.metadata()?.rdev();
            let major = hex >> 8;
            // Safely strip the /dev/ prefix and remove numeric characters from the device name
            let mut pattern = match path.strip_prefix("/dev/") {
                Ok(p) => p
                    .to_string_lossy()
                    .to_string()
                    .replace(|c: char| c.is_ascii_digit(), ""),
                Err(_) => continue,
            };

            if major >= 136 && major <= 143 {
                continue;
            }
            if expected_major.contains_key(&major) {
                continue;
            }

            let mut class = String::from("UNKNOWN");
            if unknown.contains_key(pattern.as_str())
                || unknown_partial_names
                    .iter()
                    .any(|&name| pattern.contains(name))
            {
                continue;
            }
            if major >= 60 && major <= 63 || major >= 120 && major <= 127 {
                class = String::from("LOCAL/EXPERIMENTAL");
            }
            if major >= 234 && major <= 254 {
                if expected_low.contains_key(pattern.as_str()) {
                    continue;
                }
                if expected_high.contains_key(pattern.as_str()) {
                    continue;
                }
                class = String::from("low dynamic");
            }
            if major >= 384 && major <= 511 {
                if expected_high.contains_key(pattern.as_str()) {
                    continue;
                }
                class = String::from("high dynamic");
            }
            let md = fs::metadata(&path)?;
            let permissions = parse_permissions(md.mode());
            let uid = md.uid();
            let gid = md.gid();
            let inode = md.ino();
            let mut ctime = get_epoch_start(); // Most linux versions do not support created timestamps
            if md.created().is_ok() {
                ctime = format_date(md.created()?.into())?;
            }
            let atime = format_date(md.accessed()?.into())?;
            let wtime = format_date(md.modified()?.into())?;
            let p = path.to_string_lossy();
            TxCharDevice::new(
                "Rootkit".to_string(),
                "CharDeviceMimic".to_string(),
                get_now()?,
                p.to_string(),
                class,
                pattern,
                major,
                permissions,
                uid,
                gid,
                inode,
                atime,
                wtime,
                ctime,
                sort_hashset(tags.clone()),
            )
            .report_log();
        }
        sleep();
    }
    Ok(())
}
