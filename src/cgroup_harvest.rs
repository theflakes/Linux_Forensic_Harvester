use crate::data_defs::{TxCgroup, TxCgroupMeta};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Parse a cgroup line from /proc/<pid>/cgroup (v1 or v2 format)
/// v1 format: hierarchy-ID:relative-path
/// v2 format: "0::/"
fn parse_cgroup_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.splitn(3, ':').collect();
    if parts.len() >= 3 && !parts[2].is_empty() {
        Some(parts[2].trim_end_matches('/').to_string())
    } else if parts.len() >= 3 && parts[2].trim_end_matches('/').is_empty() {
        Some("".to_string())
    } else {
        None
    }
}

/// Extract forensic insights from a cgroup path
fn parse_cgroup_path(path: &str) -> (String, String, String, String, String, String, String) {
    let mut container_runtime = String::new();
    let mut container_id = String::new();
    let mut systemd_unit = String::new();
    let mut systemd_slice = String::new();
    let mut user_session_id = String::new();
    let mut kubernetes_pod_id = String::new();
    let mut kubernetes_class = String::new();

    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for (i, component) in components.iter().enumerate() {
        if *component == "docker" && i + 1 < components.len() {
            container_runtime = "docker".to_string();
            container_id = components[i + 1].to_string();
        }

        if component.len() == 64 && container_runtime.is_empty() {
            let is_hex = component.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex {
                container_runtime = "runc".to_string();
                container_id = component.to_string();
            }
        }

        if component.starts_with("libpod-") && container_id.is_empty() {
            container_runtime = "podman".to_string();
            container_id = component.trim_start_matches("libpod-").to_string();
        }
        if *component == "libpod_parent" && i + 1 < components.len() {
            container_runtime = "podman".to_string();
            if !container_id.is_empty() {
                container_id = components[i + 1].trim_start_matches("libpod-").to_string();
            }
        }

        if *component == "kubepods" && i + 1 < components.len() {
            container_runtime = "kubernetes".to_string();
            kubernetes_class = components[i + 1].to_string();
            if i + 2 < components.len() && components[i + 2].starts_with("pod") {
                kubernetes_pod_id = components[i + 2].trim_start_matches("pod").to_string();
                if i + 3 < components.len() {
                    container_id = components[i + 3].to_string();
                }
            }
        }

        if component.starts_with("kubepods-") && component.ends_with(".slice") {
            if container_runtime.is_empty() {
                container_runtime = "kubernetes".to_string();
            }
            kubernetes_class = component
                .trim_end_matches(".slice")
                .trim_start_matches("kubepods-")
                .to_string();
        }
        if component.ends_with(".slice")
            && !kubernetes_pod_id.is_empty()
            && *component != "kubepods.slice"
        {
            let slice_name = component.trim_end_matches(".slice");
            if slice_name.len() >= 12
                && slice_name.chars().all(|c| c.is_ascii_hexdigit())
                && container_id.is_empty()
            {
                container_id = slice_name.to_string();
            }
        }

        if *component == "system.slice" && i + 1 < components.len() {
            systemd_slice = "system.slice".to_string();
            systemd_unit = components[i + 1].to_string();
        }

        if *component == "user.slice" && i + 1 < components.len() {
            systemd_slice = "user.slice".to_string();
            let user_slice = components[i + 1];
            if user_slice.starts_with("user-") && user_slice.ends_with(".slice") {
                user_session_id = user_slice
                    .trim_start_matches("user-")
                    .trim_end_matches(".slice")
                    .to_string();
            }
        }

        if component.starts_with("session-") && component.ends_with(".scope") {
            user_session_id = component
                .trim_start_matches("session-")
                .trim_end_matches(".scope")
                .to_string();
        }

        if component.ends_with(".service") && systemd_unit.is_empty() {
            let unit_name = component.trim_end_matches(".service");
            if !unit_name.is_empty() && !unit_name.chars().all(|c| c.is_ascii_digit()) {
                systemd_unit = component.to_string();
            }
        }

        if component.ends_with(".scope") && systemd_unit.is_empty() {
            systemd_unit = component.to_string();
        }
    }

    (
        container_runtime,
        container_id,
        systemd_unit,
        systemd_slice,
        user_session_id,
        kubernetes_pod_id,
        kubernetes_class,
    )
}

fn get_process_comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn get_process_command_line(pid: i32) -> String {
    match fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
        Ok(content) => content.replace('\0', " ").trim().to_string(),
        Err(_) => String::new(),
    }
}

fn get_process_uid_gid(pid: i32) -> (u32, u32) {
    let status = match fs::read_to_string(format!("/proc/{}/status", pid)) {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let mut uid = 0u32;
    let mut gid = 0u32;
    for line in status.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                uid = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("Gid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                gid = parts[1].parse().unwrap_or(0);
            }
        }
    }
    (uid, gid)
}

/// Read a file from a directory, return empty string on error
fn read_file_or_empty(dir: &Path, filename: &str) -> String {
    fs::read_to_string(dir.join(filename))
        .unwrap_or_default()
        .trim()
        .replace('\n', ",")
        .to_string()
}

/// Harvest cgroup membership for all running processes (process-level log).
/// parent_data_type = "Process"
/// Resource fields are empty; cgroup_path is a reference for joining with cgroup-level logs.
pub fn harvest_cgroups() -> Vec<TxCgroup> {
    let mut results: Vec<TxCgroup> = Vec::new();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);

    let proc_path = PathBuf::from("/proc");
    let entries = match fs::read_dir(&proc_path) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();
        if filename_str.parse::<u32>().is_err() {
            continue;
        }

        let pid: i32 = filename_str.parse().unwrap_or(-1);
        if pid <= 0 || pid == std::process::id() as i32 {
            continue;
        }

        let cgroup_content = match fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
            Ok(content) if !content.is_empty() => content,
            _ => continue,
        };

        let comm = get_process_comm(pid);
        let command_line = get_process_command_line(pid);
        let (uid, gid) = get_process_uid_gid(pid);

        for line in cgroup_content.lines() {
            if let Some(cgroup_path) = parse_cgroup_line(line) {
                let (
                    container_runtime,
                    container_id,
                    systemd_unit,
                    systemd_slice,
                    user_session_id,
                    kubernetes_pod_id,
                    kubernetes_class,
                ) = parse_cgroup_path(&cgroup_path);

                results.push(TxCgroup::new(
                    "Process".to_string(),
                    "Cgroup".to_string(),
                    timestamp.clone(),
                    pid,
                    comm.clone(),
                    command_line.clone(),
                    uid,
                    gid,
                    cgroup_path.clone(),
                    line.to_string(),
                    container_runtime,
                    container_id,
                    systemd_unit,
                    systemd_slice,
                    user_session_id,
                    kubernetes_pod_id,
                    kubernetes_class,
                    Vec::new(),
                ));
            }
        }
    }

    results
}

/// Harvest cgroup resource state from /sys/fs/cgroup (cgroup metadata log).
/// parent_data_type = "Cgroup"
/// Resource fields are populated; pids lists all PIDs in the cgroup.
pub fn harvest_cgroup_state() -> Vec<TxCgroupMeta> {
    let mut results: Vec<TxCgroupMeta> = Vec::new();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);

    let cgroup_fs = PathBuf::from("/sys/fs/cgroup");
    if !cgroup_fs.exists() {
        return results;
    }

    for entry in WalkDir::new(&cgroup_fs).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_dir() {
            continue;
        }

        let dir_path = entry.path();
        let relative_path = dir_path
            .strip_prefix(&cgroup_fs)
            .unwrap_or(dir_path)
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();

        if relative_path.is_empty() {
            continue;
        } // Skip root

        let memory_current = read_file_or_empty(dir_path, "memory.current");
        let memory_max = read_file_or_empty(dir_path, "memory.max");
        let memory_stat = read_file_or_empty(dir_path, "memory.stat");
        let memory_events = read_file_or_empty(dir_path, "memory.events");
        let memory_events_local = read_file_or_empty(dir_path, "memory.events.local");
        let cpu_max = read_file_or_empty(dir_path, "cpu.max");
        let cpu_stat = read_file_or_empty(dir_path, "cpu.stat");
        let pids_max = read_file_or_empty(dir_path, "pids.max");
        let pids_current = read_file_or_empty(dir_path, "pids.current");
        let pids_peak = read_file_or_empty(dir_path, "pids.peak");
        let io_stat = read_file_or_empty(dir_path, "io.stat");
        let io_max = read_file_or_empty(dir_path, "io.max");
        let io_events = read_file_or_empty(dir_path, "io.events");
        let cgroup_controllers = read_file_or_empty(dir_path, "cgroup.controllers");
        let cgroup_subtree_control = read_file_or_empty(dir_path, "cgroup.subtree_control");
        let cgroup_events = read_file_or_empty(dir_path, "cgroup.events");
        let cgroup_max = read_file_or_empty(dir_path, "cgroup.max");
        let cgroup_progeny = read_file_or_empty(dir_path, "cgroup.progeny");
        let cgroup_freeze = read_file_or_empty(dir_path, "cgroup.freeze");

        // Parse PIDs from cgroup.procs (v2) or tasks (v1), one PID per line
        let cgroup_pids: Vec<i32> = fs::read_to_string(dir_path.join("cgroup.procs"))
            .or_else(|_| fs::read_to_string(dir_path.join("tasks")))
            .ok()
            .map(|content| {
                content
                    .lines()
                    .filter_map(|line| line.trim().parse::<i32>().ok())
                    .collect()
            })
            .unwrap_or_default();

        let has_data = !memory_current.is_empty()
            || !memory_max.is_empty()
            || !memory_events.is_empty()
            || !memory_events_local.is_empty()
            || !cpu_max.is_empty()
            || !cpu_stat.is_empty()
            || !pids_max.is_empty()
            || !pids_current.is_empty()
            || !pids_peak.is_empty()
            || !io_stat.is_empty()
            || !io_max.is_empty()
            || !io_events.is_empty()
            || !cgroup_controllers.is_empty()
            || !cgroup_subtree_control.is_empty()
            || !cgroup_events.is_empty()
            || !cgroup_max.is_empty()
            || !cgroup_progeny.is_empty()
            || !cgroup_freeze.is_empty();
        if !has_data {
            continue;
        }

        let (
            container_runtime,
            container_id,
            systemd_unit,
            systemd_slice,
            user_session_id,
            kubernetes_pod_id,
            kubernetes_class,
        ) = parse_cgroup_path(&relative_path);

        results.push(TxCgroupMeta::new(
            "Cgroup".to_string(),
            "CgroupMeta".to_string(),
            timestamp.clone(),
            relative_path,
            container_runtime,
            container_id,
            systemd_unit,
            systemd_slice,
            user_session_id,
            kubernetes_pod_id,
            kubernetes_class,
            memory_current,
            memory_max,
            memory_stat,
            cpu_max,
            cpu_stat,
            pids_max,
            pids_current,
            pids_peak,
            memory_events,
            memory_events_local,
            io_stat,
            io_max,
            io_events,
            cgroup_controllers,
            cgroup_subtree_control,
            cgroup_events,
            cgroup_max,
            cgroup_progeny,
            cgroup_freeze,
            cgroup_pids,
            Vec::new(),
        ));
    }

    results
}
