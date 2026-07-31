use crate::data_defs::{TxSystemdUnit, TIME_END, TIME_START};
use crate::process_file;
use chrono::Utc;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Standard systemd directories where unit files reside (vendor → runtime → admin precedence).
const SYSTEMD_DIRS: [&str; 3] = [
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/etc/systemd/system",
];

/// Runtime-generated units that appear at boot or on demand.
const SYSTEMD_RUNTIME_DIRS: [&str; 1] = ["/run/systemd/system"];

/// All unit-file extensions we consider forensically relevant.
const UNIT_EXTENSIONS: [&str; 8] = [
    "service", "timer", "socket", "target", "mount", "path", "slice", "scope",
];

/// Represents a parsed systemd unit directive line (section.key=value).
struct UnitDirective {
    section: String,
    key: String,
    value: String,
}

/// Parse an `Exec*` field into individual executable paths.
/// Systemd allows space-separated args but we only care about the binary path (first token).
fn extract_exec_paths(value: &str) -> Vec<String> {
    let value = value.trim();
    if value.is_empty() {
        return vec![];
    }

    // Handle prefixes like -, +, !, !! before the command
    let mut iter = value.split_whitespace().peekable();

    // Skip systemd execution modifiers
    while let Some(&first) = iter.peek() {
        if first
            .chars()
            .all(|c| c == '-' || c == '+' || c == '!' || c == '@')
        {
            iter.next();
        } else {
            break;
        }
    }

    // The remaining first token is the executable path (or shell binary)
    match iter.peek() {
        Some(&cmd) => {
            let cmd_lower = cmd.to_lowercase();
            if cmd_lower == "/bin/sh"
                || cmd_lower == "/bin/bash"
                || cmd_lower == "/usr/bin/sh"
                || cmd_lower == "/usr/bin/bash"
            {
                // Shell-invoking commands are high-risk — collect the full value as a tag instead
                vec![value.to_string()]
            } else if cmd.starts_with('/') {
                vec![cmd.to_string()]
            } else {
                // Relative path or command not starting with / — still report it but note it's non-absolute
                vec![format!("non_absolute:{}", cmd)]
            }
        }
        None => vec![],
    }
}

/// Determine if a unit file is "enabled" by checking for symlinks in enabled/ directories.
fn is_unit_enabled(unit_name: &str) -> bool {
    let candidates = [
        "/etc/systemd/system/multi-user.target.wants",
        "/etc/systemd/system/multi-user.target.wants/",
        "/etc/systemd/system/graphical.target.wants",
        "/etc/systemd/system/graphical.target.wants/",
        "/etc/systemd/system/default.target.wants",
        "/etc/systemd/system/default.target.wants/",
    ];

    for base in candidates.iter().filter(|c| c.ends_with("/")) {
        let link_path = format!("{}{}", base, unit_name);
        if Path::new(&link_path).exists() || fs::symlink_metadata(&link_path).is_ok() {
            return true;
        }
    }

    // Also check for .service → /usr/lib/... symlink pattern (enabled via systemctl enable)
    let etc_link = format!("/etc/systemd/system/{}.symlink", unit_name);
    if Path::new(&etc_link).exists() {
        return true;
    }

    false
}

/// Tag a directive with forensic indicators.
fn add_directive_tags(key: &str, value: &str, source: &str, section: &str, tags: &mut Vec<String>) {
    // Location-based tags
    if source.contains("/etc/systemd/system/") || source.starts_with("admin:") {
        tags.push("admin_override".to_string());
    } else if source.contains("/run/systemd/system/") || source.starts_with("runtime:") {
        tags.push("runtime_rule".to_string());
    }

    // Execution directives are highest forensic interest
    if key.starts_with("Exec") {
        let value_lower = value.to_lowercase();

        // Shell invocation — attacker favorite for persistence/pivoting
        if value_lower.contains("/bin/sh")
            || value_lower.contains("/bin/bash")
            || value_lower.contains("/usr/bin/sh")
            || value_lower.contains("/usr/bin/bash")
        {
            tags.push("shell_invocation".to_string());
        }

        // Absolute path required for legitimate services
        let first_token = value.split_whitespace().next().unwrap_or("");
        if !first_token.starts_with('/')
            && !value_lower.starts_with('-')
            && !value_lower.starts_with('+')
        {
            tags.push("non_absolute_exec_path".to_string());
        }

        // Privilege-related directives
        match key {
            "User" => {
                if value == "root" || value.is_empty() {
                    tags.push("runs_as_root".to_string());
                } else if value != "-" {
                    tags.push(format!("runs_as_user:{}", value));
                }
            }
            "Group" => {
                if value != "-" && !value.is_empty() {
                    tags.push(format!("group:{}", value));
                }
            }
            _ => {}
        }

        // Dangerous environment variables in unit files
        match key {
            "EnvironmentFile" | "Environment" => {
                if value.contains("SECRET") || value.contains("PASSWORD") || value.contains("KEY") {
                    tags.push("credential_in_unit".to_string());
                }
            }
            _ => {}
        }

        // Restart policy — affects persistence after crashes
        match key {
            "Restart" if value == "always" || value == "on-failure" => {
                tags.push("auto_restart".to_string());
            }
            _ => {}
        }
    }

    // Network-relevant directives
    match section {
        "Socket" | "[Unit]" if key.contains("Listen") || key.starts_with("Bind") => {
            tags.push("network_exposed".to_string());
        }
        _ => {}
    }

    // Filesystem mounting/access — privilege escalation vectors
    if matches!(
        &*key,
        "ReadWritePaths" | "ReadOnlyPaths" | "TemporaryFileSystem" | "DevicePolicy" | "DeviceAllow"
    ) {
        tags.push("filesystem_access".to_string());
    }

    // Condition/Path directives reference system paths that can indicate targets
    if key.starts_with("ConditionPath")
        || key.starts_with("PathExists")
        || key.starts_with("ExecCondition")
    {
        tags.push("path_condition".to_string());
    }

    // WantedBy/RequiredBy — determines which target pulls this unit in
    if matches!(&*key, "WantedBy" | "RequiredBy")
        && (value.contains("multi-user.target") || value.contains("graphical.target"))
    {
        tags.push("boot_service".to_string());
    }

    // Time window tag based on source file mtime
    let _ = add_time_tags(source, tags);
}

/// Add time-window tag if the source file's mtime falls within the harvest window.
fn add_time_tags(source: &str, tags: &mut Vec<String>) -> Result<(), ()> {
    // Strip prefix for actual path lookup
    let real_path = source
        .trim_start_matches("admin:")
        .trim_start_matches("runtime:")
        .trim_start_matches("vendor:");

    if let Ok(metadata) = fs::metadata(real_path) {
        use std::os::unix::fs::MetadataExt;
        let mtime = metadata.mtime();
        let mtime_ns = metadata.mtime_nsec();
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(mtime, mtime_ns as u32);
        if let Some(date_time) = dt {
            if date_time >= *TIME_START && date_time < *TIME_END {
                tags.push("within_time_window".to_string());
            }
        }
    }
    Ok(())
}

/// Parse a systemd unit file into directives.
fn parse_unit_file(content: &str) -> Vec<UnitDirective> {
    let mut directives = Vec::new();
    let mut current_section = String::from("Unit"); // default section per spec is [Unit]

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Section headers: [SectionName]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            continue;
        }

        // Key=Value pairs
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();

            directives.push(UnitDirective {
                section: current_section.clone(),
                key,
                value,
            });
        }
    }

    directives
}

/// Extract the unit name from a file path (e.g. "nginx.service" → "nginx.service").
fn get_unit_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

/// Harvest systemd unit files from all configured directories.
/// Returns one TxSystemdUnit entry per directive line found in each unit file.
/// parent_data_type = "Systemd"
/// data_type = "ServiceRule"
///
/// Also emits TxFile entries via process_file() for:
///   1. The .service/.timer/... unit files themselves (parent_data_type = "Systemd")
///   2. Executable paths referenced in ExecStart, ExecStop, and other Exec* directives
///      (parent_data_type = "ExecBinary")
pub fn harvest_systemd_units() -> Vec<TxSystemdUnit> {
    let mut results: Vec<TxSystemdUnit> = Vec::new();
    let mut files_already_seen: HashSet<String> = HashSet::new();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);

    // Combine all directories to scan (vendor + admin + runtime)
    let mut dirs_to_scan: Vec<&str> = Vec::new();
    for &dir in SYSTEMD_DIRS.iter() {
        if Path::new(dir).is_dir() {
            dirs_to_scan.push(dir);
        }
    }
    for &dir in SYSTEMD_RUNTIME_DIRS.iter() {
        if Path::new(dir).is_dir() {
            // Only scan the runtime dir for actual unit files (not subdirectories like multi-user.target.wants/)
            let entry = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entry.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if !file_path.is_file() {
                    continue;
                }
                let extension = file_path.extension().and_then(|e| e.to_str());
                if UNIT_EXTENSIONS.iter().any(|ext| extension == Some(ext)) {
                    dirs_to_scan.push(&dir);
                    break; // only need to add the dir once
                }
            }
        }
    }

    for base_dir in &dirs_to_scan {
        let entries = match fs::read_dir(base_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            let extension = file_path.extension().and_then(|e| e.to_str());

            // Only process known unit types (skip .wants/ directories by filtering extensions)
            if !UNIT_EXTENSIONS.iter().any(|ext| extension == Some(ext)) {
                continue;
            }

            let unit_name = get_unit_name(&file_path.to_string_lossy());
            let source_prefix = match &base_dir[..] {
                "/etc/systemd/system" => "admin:",
                "/run/systemd/system" => "runtime:",
                _ => "vendor:",
            };
            let full_source = format!("{}{}", source_prefix, file_path.to_string_lossy());

            // --- Emit TxFile for the unit file itself ---
            {
                let mut tags = HashSet::new();
                if source_prefix == "admin:" {
                    tags.insert("admin_override".to_string());
                } else if source_prefix == "runtime:" {
                    tags.insert("runtime_rule".to_string());
                } else {
                    tags.insert("vendor_default".to_string());
                }

                // Check enabled status for service units
                if extension == Some("service") && is_unit_enabled(&unit_name) {
                    tags.insert("enabled".to_string());
                }

                let _ = process_file("Systemd", &file_path, &mut files_already_seen, &mut tags);
            }

            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Parse the unit file into directives
            for directive in parse_unit_file(&content) {
                let mut tags: Vec<String> = Vec::new();
                add_directive_tags(
                    &directive.key,
                    &directive.value,
                    &full_source,
                    &directive.section,
                    &mut tags,
                );

                // Build the unit path for TxSystemdUnit
                let unit_path = file_path.to_string_lossy().to_string();

                // Save copies before moving into TxSystemdUnit (needed for Exec* checks below)
                let value_copy = directive.value.clone();
                let is_exec = directive.key.starts_with("Exec") && !value_copy.is_empty();

                results.push(TxSystemdUnit::new(
                    "Systemd".to_string(),
                    "ServiceRule".to_string(),
                    timestamp.clone(),
                    directive.section,
                    directive.key,
                    directive.value,
                    unit_path.clone(),
                    unit_name.clone(),
                    base_dir.to_string(),
                    full_source.clone(),
                    tags,
                ));

                // --- Emit TxFile for Exec* binary paths ---
                if is_exec {
                    let exec_paths = extract_exec_paths(&value_copy);
                    for raw_path in &exec_paths {
                        let real_path = raw_path.strip_prefix("non_absolute:").unwrap_or(raw_path);

                        // Skip shell-invocation shortcuts — we already tagged them
                        if raw_path.starts_with("non_absolute:") {
                            continue;
                        }

                        let target = Path::new(real_path);
                        if target.exists() || value_copy.starts_with('-') {
                            // Even if the file doesn't exist, report it for non-absolute paths
                            // (attacker may have placed a malicious binary elsewhere)
                            let mut tags = HashSet::new();
                            let _ = process_file(
                                "ExecBinary",
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
