extern crate libc;
extern crate md5;
extern crate path_abs; // needed to create absolute file paths from relative
extern crate tree_magic_mini; // needed to find MIME type of files

use crate::{data_defs::*, mutate::*, process_file, time::*};
use bstr::ByteSlice;
use libc::{
    BLKSSZGET,
    S_IRGRP,
    S_IROTH,
    S_IRUSR, // see: https://www.gnu.org/software/libc/manual/html_node/Permission-Bits.html
    S_ISGID,
    S_ISUID,
    S_ISVTX,
    S_IWGRP,
    S_IWOTH,
    S_IWUSR,
    S_IXGRP,
    S_IXOTH,
    S_IXUSR,
};
use path_abs::{PathAbs, PathInfo};
use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::Hash;
use std::io;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::{MetadataExt, PermissionsExt};
use std::path::Path;
use tree_magic_mini as tree_magic;

const MAX_FILE_SIZE: u64 = 256000000;

// return file mime type string
pub fn get_filetype(buffer: &mut Vec<u8>) -> String {
    (tree_magic::from_u8(buffer)).to_string()
}

// true if path exists, false otherwise
pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

/*
    convert permissions to human readable
    see: https://gist.github.com/mre/91ebb841c34df69671bd117ead621a8b
*/
fn triplet(mode: u32, read: u32, write: u32, execute: u32) -> String {
    return match (mode & read, mode & write, mode & execute) {
        (0, 0, 0) => "---",
        (_, 0, 0) => "r--",
        (0, _, 0) => "-w-",
        (0, 0, _) => "--x",
        (_, 0, _) => "r-x",
        (_, _, 0) => "rw-",
        (0, _, _) => "-wx",
        (_, _, _) => "rwx",
    }
    .to_string();
}

// set the correct suid/sgid bit depending on if executable or not
fn set_suid_sgid_bit(mode: u32, read: u32, write: u32, execute: u32) -> String {
    let mut perms = triplet(mode, read, write, execute);
    if perms.contains("x") {
        perms = perms.replace("x", "s")
    } else {
        perms.pop();
        perms.push('S');
    }
    return perms;
}

// set sticky bit
fn set_sticky_bit(mode: u32, read: u32, write: u32, execute: u32) -> String {
    let mut perms = triplet(mode, read, write, execute);
    perms.pop();
    perms.push('t');
    return perms;
}

// convert permissions to human readable
pub fn parse_permissions(mode: u32) -> String {
    let user = match mode & S_ISUID as u32 {
        0 => triplet(mode, S_IRUSR.into(), S_IWUSR.into(), S_IXUSR.into()),
        _ => set_suid_sgid_bit(mode, S_IRUSR.into(), S_IWUSR.into(), S_IXUSR.into()),
    };
    let group = match mode & S_ISGID as u32 {
        0 => triplet(mode, S_IRGRP.into(), S_IWGRP.into(), S_IXGRP.into()),
        _ => set_suid_sgid_bit(mode, S_IRGRP.into(), S_IWGRP.into(), S_IXGRP.into()),
    };
    let other = match mode & S_ISVTX as u32 {
        0 => triplet(mode, S_IROTH.into(), S_IWOTH.into(), S_IXOTH.into()),
        _ => set_sticky_bit(mode, S_IROTH.into(), S_IWOTH.into(), S_IXOTH.into()),
    };
    return [user, group, other].join("");
}

// find if a file has the suid or sgid bit set
pub fn is_suid_sgid(mode: u32) -> (bool, bool) {
    return (
        if (mode & S_ISUID as u32) != 0 {
            true
        } else {
            false
        },
        if (mode & S_ISGID as u32) != 0 {
            true
        } else {
            false
        },
    );
}

// is a file or directory hidden
pub fn is_hidden(path: &std::path::PathBuf) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map_or(false, |s| s.starts_with("."))
    })
}

// get handle to a file
pub fn open_file(file_path: &std::path::Path) -> std::io::Result<std::fs::File> {
    match File::open(&file_path) {
        Ok(f) => return Ok(f),
        Err(e) => return Err(e),
    }
}

// read all file content for examination for interesting strings
pub fn read_file_string(file: &std::path::Path) -> std::io::Result<String> {
    match fs::read_to_string(file) {
        Ok(f) => Ok(f.replace('\u{0000}', " ").trim().to_string()), // Unicode nulls are replaced with spaces (look for better solution)
        Err(_e) => Ok("".to_string()),
    }
}

// read in file as byte vector
pub fn read_file_bytes(mut file: &std::fs::File) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(f) => f,
        Err(_e) => return Ok(vec![]),
    };
    Ok(buffer)
}

pub fn u8_to_hex_string(bytes: &Vec<u8>) -> std::io::Result<String> {
    Ok(bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join(", "))
}

// return the path that a symlink points to
pub fn resolve_link(link_path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    // Attempt to get the parent directory; if it fails, return an empty PathBuf
    let parent_dir = match get_parent_dir(link_path) {
        Ok(p) => p,
        Err(_) => return Ok(std::path::PathBuf::new()),
    };
    // Change working directory to the parent; on failure return empty PathBuf
    if std::env::set_current_dir(parent_dir).is_err() {
        return Ok(std::path::PathBuf::new());
    }
    // Read the symlink target; on failure return empty PathBuf
    let result = match fs::read_link(link_path) {
        Ok(r) => r,
        Err(_) => return Ok(std::path::PathBuf::new()),
    };
    // Resolve to an absolute path; if PathAbs fails, treat it as missing and return empty PathBuf
    match PathAbs::new(&result) {
        Ok(abs) => Ok(abs.into()),
        Err(_) => Ok(std::path::PathBuf::new()),
    }
}

fn link_target_exists(link_path: &std::path::Path) -> bool {
    if let Ok(link_target) = fs::read_link(link_path) {
        link_target.exists()
    } else {
        false
    }
}

// gather metadata for symbolic links
pub fn process_link(
    pdt: &str,
    link: std::fs::Metadata,
    link_path: String,
    file_path: String,
    hidden: bool,
    deleted: bool,
    tags: &mut HashSet<String>,
) -> std::io::Result<()> {
    let mut ctime = get_epoch_start(); // Most linux versions do not support created timestamps
    if link.created().is_ok() {
        ctime = format_date(link.created()?.into())?;
    }
    let atime = format_date(link.accessed()?.into())?;
    let wtime = format_date(link.modified()?.into())?;
    let size = link.len();
    if not_in_time_window(&atime, &ctime, &wtime)? {
        return Ok(());
    }
    let mode = link.mode();
    let perms = parse_permissions(mode);
    TxLink::new(
        pdt.to_string(),
        "ShellLink".to_string(),
        get_now()?,
        link_path,
        file_path,
        atime,
        wtime,
        ctime,
        size,
        hidden,
        deleted,
        perms,
        sort_hashset(tags.clone()),
    )
    .report_log();
    Ok(())
}

/*
    determine if a file is a symlink or not
    return parent data_type and path to file
    never return the path to a symnlink
*/
pub fn get_link_info(
    pdt: &str,
    link_path: &std::path::Path,
    tags: &mut HashSet<String>,
) -> std::io::Result<(String, std::path::PathBuf)> {
    let mut parent_data_type = pdt.to_string();
    let mut path = PathAbs::new(&link_path)?.clone().into();
    let sl = fs::symlink_metadata(&link_path)?;
    let tags_copy = tags.clone();
    if sl.file_type().is_symlink() {
        path = resolve_link(link_path)?;
        let lp = path.to_string_lossy().to_string();
        if lp.contains("(deleted)") {
            tags.insert("LinkTargetDeleted".to_string());
            let p = link_path.to_string_lossy().to_string();
            if p.starts_with("/proc/") && p.ends_with("/exe") {
                tags.insert("ProcBinDeleted".to_string());
            }
        }
        parent_data_type = "ShellLink".to_string();
        process_link(
            pdt,
            sl,
            link_path.to_string_lossy().into(),
            path.to_string_lossy().into(),
            is_hidden(&path),
            link_target_exists(link_path),
            tags,
        )?;
        tags.clear();
        tags.extend(tags_copy);
    }
    Ok((parent_data_type, path))
}

pub fn not_in_time_window(atime: &str, ctime: &str, wtime: &str) -> std::io::Result<bool> {
    if !in_time_window(&ctime)? && !in_time_window(&atime)? && !in_time_window(&wtime)? {
        return Ok(true);
    };
    Ok(false)
}

// find the parent directory of a given dir or file
pub fn get_parent_dir(path: &std::path::Path) -> std::io::Result<&std::path::Path> {
    match path.parent() {
        Some(d) => return Ok(d),
        None => return Ok(path),
    };
}

// get metadata for the file's content (md5, mime_type)
pub fn get_file_content_info(file: &std::fs::File) -> std::io::Result<(String, String)> {
    let mut md5 = "".to_string();
    let mut mime_type = "".to_string();
    if file.metadata()?.len() != 0 {
        // don't bother with opening empty files
        if file.metadata()?.len() <= MAX_FILE_SIZE {
            // don't hash very large files
            let mut buffer = read_file_bytes(file)?;
            md5 = format!("{:x}", md5::compute(&buffer)).to_lowercase();
            mime_type = get_filetype(&mut buffer);
            drop(buffer);
        }
    } else {
        md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string(); // md5 of empty file
    }
    Ok((md5, mime_type))
}

// read file's lines into a string vec for parsing
pub fn file_to_vec(filename: &str) -> io::Result<Vec<String>> {
    let file_in = fs::File::open(filename)?;
    let file_reader = BufReader::new(file_in);
    Ok(file_reader.lines().filter_map(io::Result::ok).collect())
}

pub fn find_files_with_permissions(
    start: &Path,
    permissions: u32,
    mut files_already_seen: &mut HashSet<String>,
    pdt: &str,
    mut tags: HashSet<String>,
) -> std::io::Result<()> {
    if start.is_dir() {
        for entry in fs::read_dir(start)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let metadata = fs::metadata(&path)?;
                let file_permissions = metadata.permissions().mode();
                if file_permissions == permissions {
                    process_file(pdt, &path, &mut files_already_seen, &mut tags)?
                }
            }
            sleep();
        }
    }
    Ok(())
}

pub fn get_directory_content_counts(dir: &Path) -> io::Result<(i128, i128, i128)> {
    let metadata = fs::metadata(dir)?;
    let hard_links: i128 = metadata.nlink() as i128;
    let visible_entries = fs::read_dir(dir)?.filter(|entry| entry.is_ok()).count() as i128;
    let hidden_count: i128 = hard_links - visible_entries - 2;
    Ok((hard_links, visible_entries, hidden_count))
}

// pub fn get_sector_size(file: &File) -> Result<u64, Box<dyn std::error::Error>> {
//     let fd = file.as_raw_fd();
//     let mut sector_size: u64 = 0;
//     let result = unsafe { libc::ioctl(fd, BLKSSZGET, &mut sector_size) };
//     if result == -1 {
//         return Err("Failed to get sector size".into());
//     }
//     Ok(sector_size)
// }
