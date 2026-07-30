use crate::data_defs::{TxTmpfiles, TIME_END, TIME_START};
use crate::process_file;
use chrono::Utc;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// The three systemd tmpfiles directories, in precedence order (later overrides earlier).
const TMPFILES_DIRS: [&str; 3] = ["/usr/lib/tmpfiles.d", "/etc/tmpfiles.d", "/run/tmpfiles.d"];

/// Represents a parsed tmpfiles.conf action line.
struct TmpfileRule {
    action: String,
    path: String,
    mode: String,
    owner: String,
    group: String,
    lifetime: String,
    comment: String,
}

/// Parse a single tmpfiles.conf action line.
/// Format: <Type> <Path> <Mode> <Owner> <Group> <Lifetime> [<Comment>]
fn parse_tmpfiles_line(line: &str) -> Option<TmpfileRule> {
    let line = line.trim();

    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Split into parts; comment may contain spaces
    let parts: Vec<&str> = line.splitn(7, ' ').collect();
    if parts.len() < 6 {
        return None;
    }

    let action = parts[0].to_string();
    let path = parts[1].to_string();
    let mode = if parts[2] == "-" {
        String::new()
    } else {
        parts[2].to_string()
    };
    let owner = if parts[3] == "-" {
        String::new()
    } else {
        parts[3].to_string()
    };
    let group = if parts[4] == "-" {
        String::new()
    } else {
        parts[4].to_string()
    };
    let lifetime = if parts[5] == "-" {
        String::new()
    } else {
        parts[5].to_string()
    };
    let comment = if parts.len() >= 7 {
        parts[6].to_string()
    } else {
        String::new()
    };

    // Validate action type
    let valid_actions = [
        "f", "F", "w", "W", "d", "D", "c", "C", "l", "L", "p", "P", "s", "Q", "q", "Z", "z", "M",
        "a", "A", "v", "V", "t", "T", "r", "R", "e", "E",
    ];
    if !valid_actions.contains(&action.as_str()) {
        return None;
    }

    Some(TmpfileRule {
        action,
        path,
        mode,
        owner,
        group,
        lifetime,
        comment,
    })
}

/// Tag a rule with forensic indicators.
fn add_tags(rule: &TmpfileRule, source: &str, tags: &mut Vec<String>) {
    // Mark admin overrides (most forensically interesting)
    if source.contains("/etc/tmpfiles.d/") {
        tags.push("admin_override".to_string());
    }
    if source.contains("/run/tmpfiles.d/") {
        tags.push("runtime_rule".to_string());
    }

    // Force actions (F, D, W) can overwrite existing files — privilege escalation vector
    if rule.action == "F" || rule.action == "D" || rule.action == "W" {
        tags.push("force_action".to_string());
    }

    // File/dir creation actions are persistence vectors
    if ["f", "F", "d", "D", "c", "C", "l", "L", "p", "P"].contains(&rule.action.as_str()) {
        tags.push("creates_path".to_string());
    }

    // Remove actions — potential evidence destruction
    if rule.action == "r" || rule.action == "R" {
        tags.push("removes_path".to_string());
    }

    // Rules with no lifetime may persist indefinitely
    if rule.lifetime.is_empty() {
        tags.push("no_lifetime".to_string());
    }

    // Root ownership — potential privilege escalation
    if rule.owner == "root" || rule.owner == "0" {
        tags.push("root_owned".to_string());
    }

    // World-writable — potential misuse
    if !rule.mode.is_empty() {
        let mode_num: u32 = rule.mode.parse().unwrap_or(0);
        if (mode_num & 0o002) != 0 {
            tags.push("world_writable".to_string());
        }
    }
}

/// Harvest tmpfiles rules from all configured directories.
/// Returns one TxTmpfiles entry per rule found.
/// parent_data_type = "Tmpfiles"
/// data_type = "TmpfileRule"
///
/// Also emits TxFile entries via process_file() for:
///   1. The .conf config files themselves (parent_data_type = "Tmpfiles")
///   2. Target files created by file-creating actions: f, F, w, W, c, C (parent_data_type = "TmpfileTarget")
pub fn harvest_tmpfiles() -> Vec<TxTmpfiles> {
    let mut results: Vec<TxTmpfiles> = Vec::new();
    let mut files_already_seen: HashSet<String> = HashSet::new();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);

    for dir in TMPFILES_DIRS {
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            continue;
        }

        let entries = match fs::read_dir(dir_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            let extension = file_path.extension().and_then(|e| e.to_str());
            if extension != Some("conf") {
                continue;
            }

            // --- Emit TxFile for the .conf file itself ---
            {
                let mut tags = HashSet::new();
                let _ = process_file("Tmpfiles", &file_path, &mut files_already_seen, &mut tags);
            }

            let source = file_path.to_string_lossy().to_string();
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                if let Some(rule) = parse_tmpfiles_line(line) {
                    // Check file-creating action BEFORE moving rule fields into TxTmpfiles
                    let is_file_action =
                        matches!(rule.action.as_str(), "f" | "F" | "w" | "W" | "c" | "C");
                    let target_path = rule.path.clone(); // save for TxFile emission after move

                    let mut tags: Vec<String> = Vec::new();
                    add_tags(&rule, &source, &mut tags);

                    // Filter by time window: tmpfiles don't have inherent timestamps,
                    // so we tag by source modification time if available
                    let mut time_tags: Vec<String> = Vec::new();
                    if let Ok(metadata) = fs::metadata(&file_path) {
                        use std::os::unix::fs::MetadataExt;
                        let mtime = metadata.mtime();
                        let mtime_ns = metadata.mtime_nsec();
                        let mtime_dt =
                            chrono::DateTime::<chrono::Utc>::from_timestamp(mtime, mtime_ns as u32);
                        if let Some(dt) = mtime_dt {
                            if dt >= *TIME_START && dt < *TIME_END {
                                time_tags.push("within_time_window".to_string());
                            }
                        }
                    }
                    tags.extend(time_tags);

                    results.push(TxTmpfiles::new(
                        "Tmpfiles".to_string(),
                        "TmpfileRule".to_string(),
                        timestamp.clone(),
                        rule.action,
                        rule.path,
                        rule.mode,
                        rule.owner,
                        rule.group,
                        rule.lifetime,
                        source.clone(),
                        rule.comment,
                        tags,
                    ));

                    // --- Emit TxFile for file-creating target paths ---
                    if is_file_action {
                        let target = Path::new(&target_path);
                        if target.exists() {
                            let mut tags = HashSet::new();
                            let _ = process_file(
                                "TmpfileTarget",
                                target,
                                &mut files_already_seen,
                                &mut tags,
                            );
                        }
                    }
                }
            }
        }
    }

    results
}
