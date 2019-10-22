extern crate tree_magic;        // needed to find MIME type of files
extern crate path_abs;          // needed to create absolute file paths from relative
extern crate md5;
extern crate file;

use crate::{data_def::*, mutate::*, time::*};
use std::fs::{self, File};
use std::io::{Read, BufRead, BufReader};
use std::io;
use path_abs::{PathAbs, PathInfo};

// return file mime type string
pub fn get_filetype(buffer: &mut Vec<u8>) -> String {
    tree_magic::from_u8(buffer)
}

// true if path exists, false otherwise
pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

// is a file or directory hidden
pub fn is_hidden(file_path: &std::path::PathBuf) -> bool {
    let path = match file_path.file_name() {
            Some(o) => o,
            None => return false
            };
    if file_path.is_file() {  // simple check for hidden files and directories
        path.to_string_lossy().starts_with(".")
    } else if file_path.is_dir() {
        path.to_string_lossy().contains("/.")
    } else {
        false
    }
}

// get handle to a file
pub fn open_file(file_path: &std::path::Path) -> std::io::Result<(std::fs::File)> {
    match File::open(&file_path) {
        Ok(f) => return Ok(f),
        Err(e) => return Err(e)
    }
}

// read all file content for examination for interesting strings
pub fn read_file_string(file: &std::path::Path) -> std::io::Result<(String)> {
    match fs::read_to_string(file) {
        Ok(f) => Ok(f.replace('\u{0000}', " ").trim().to_string()),  // Unicode nulls are replaced with spaces (look for better solution)
        Err(_e) => Ok("".to_string())
    }
}

// read in file as byte vector
pub fn read_file_bytes(mut file: &std::fs::File) -> std::io::Result<(Vec<u8>)> {
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(f) => f,
        Err(_e) => return Ok(vec![])
    };
    Ok(buffer)
}

// return the path that a symlink points to
pub fn resolve_link(link_path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let parent_dir = get_parent_dir(link_path);
    match std::env::set_current_dir(parent_dir) {
        Ok(f) => f,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let result = match fs::read_link(link_path) {
        Ok(r) => r,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let abs = PathAbs::new(&result)?;
    Ok(abs.into())
}

// gather metadata for symbolic links
pub fn process_link(pdt: &str, link: std::fs::Metadata, link_path: String, file_path: String, hidden: bool) -> std::io::Result<()> {
    let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
    if link.created().is_ok() {
        ctime = format_date(link.created()?.into())?;
    }
    let atime = format_date(link.accessed()?.into())?;
    let wtime = format_date(link.modified()?.into())?;
    let size = link.len();

    TxLink::new(pdt.to_string(), "ShellLink".to_string(), get_now()?, 
                            link_path, file_path, atime, wtime, 
                            ctime, size, hidden).report_log();
    Ok(())
}

/*
    determine if a file is a symlink or not
    return parent data_type and path to file
    never return the path to a symnlink
*/
pub fn get_link_info(pdt: &str, link_path: &std::path::Path) -> std::io::Result<FileParent> {
    let mut fp = FileParent {
        parent_data_type: pdt.to_string(), 
        path: PathAbs::new(&link_path)?.clone().into() 
        };
    let sl = fs::symlink_metadata(&link_path)?;
    if sl.file_type().is_symlink() {
        fp.path = resolve_link(link_path)?;
        fp.parent_data_type = "ShellLink".to_string();
        process_link(pdt, sl, 
                    link_path.to_string_lossy().into(), 
                    fp.path.to_string_lossy().into(), 
                    is_hidden(&fp.path))?;
    }
    Ok(fp)
}

// find the parent directory of a given dir or file
pub fn get_parent_dir(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(d) => return d,
        None => return path
    };
}

// get metadata for the file's content (md5, mime_type)
pub fn get_file_content_info(file: &std::fs::File) -> std::io::Result<(FileContentMetaData)> {
    let mut fc = FileContentMetaData {md5: "".to_string(), mime_type: "".to_string()};
    let mut buffer = read_file_bytes(file)?;
    fc.md5 = format!("{:x}", md5::compute(&buffer)).to_lowercase();
    fc.mime_type = get_filetype(&mut buffer);
    drop(buffer);
    Ok(fc)
}

// read file's lines into a string vec for parsing
pub fn file_to_vec(filename: &str) -> io::Result<Vec<String>> {
    let file_in = fs::File::open(filename)?;
    let file_reader = BufReader::new(file_in);
    Ok(file_reader.lines().filter_map(io::Result::ok).collect())
}