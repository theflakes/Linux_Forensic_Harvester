# Linux_Forensic_Harvester
Harvest Linux forensic data for operational triage of an event.

This tool will produce a considerable amount of Json logs.

If you just want to run it, download the "lin_fh" binary.

This tool's output is meant to be used by forensic practioners to investigate suspicious events on live Linux systems.
```
Gnome Autostart Locations:
  ~/.config/autostart
KDE Autostart Locations:
  $HOME/.kde/Autostart
  $HOME/.config/autostart
  $HOME/.config/plasma-workspace/env
  $HOME/.config/plasma-workspace/shutdown
Misc. Autostart Locations:
  /etc/xdg/autostart
  /var/spool/cron
Services:
  /etc/init.d
  /etc/systemd
User cron jobs:
  /var/spool/cron/crontabs
```
```
Linux Forensic Harvester
    Author: Brian Kellogg
    License: MIT
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

Must be run as root.

Usage:
    lin_fh [options]
    lin_fh -fksl
    lin_fh [--ip <ip> --port <port>] [--depth <depth>]
    lin_fh [--ip <ip> --port <port>] [--limit]
    lin_fh [--i <ip> -p <port>] [--suidsgid] [--limit]
    lin_fh (-s, --suidsgid) [--limit]
    lin_fh (-r <regex> | --regex <regex>) [-ls] [-d <depth>]
    lin_fh --max <bytes> [--limit] [-d <depth>]
    lin_fh (-l | --limit)
    lin_fh --start <start_time> [-d <depth>]
    lin_fh --end <start_time> [-d <depth>] [-ls]
    lin_fh --start <start_time> --end <end_time>
    lin_fh -s [-d <depth>]
    lin_fh [-sl] (-x <hex> | --hex <hex>)
    lin_fh (-h | --help)

Options:
    -d, --depth <depth>     Max directory depth to traverse [default: 5]
    -f, --forensics         Gather general forensic info
    -h, --help              Print help
    -l, --limit             Limit CPU use
    -k, --rootkit           Run rootkit hunts
    -m, --max <bytes>       Max size of a text file in bytes to inspect the content
                            of for interesting strings [default: 100000]
                            - Text files will always be searched for references
                              to other files.
  Remote logging:
    -i, --ip <ip>           IP address to send output to [default: NONE]
    -p, --port <port>       Destination port to send output to [default: 80]
  Time window:
    This option will compare the specified date window to the file's 
    ctime, atime, or mtime and only output logs where one of the dates falls 
    within that window. Window start is inclusive, window end is exclusive.
    --start <UTC_start_time>    Start of time window: [default: 0000-01-01T00:00:00]
                                - format: YYYY-MM-DDTHH:MM:SS
    --end <UTC_end_time>        End of time window: [default: 9999-12-31T23:59:59]
                                - format: YYYY-MM-DDTHH:MM:SS
  Custom hunts:
    -r, --regex <regex>     Custom regex [default: $^]
                            - Search file content using custom regex
                            - Does not support look aheads/behinds/...
                            - Uses Rust regex crate (case insensitive and multiline)
                            - Tag: RegexHunt
    -s, --suidsgid          Search for suid and sgid files
                            - This will search the entire '/' including subdirectories
                            - Can take a long time
                            - /dev/, /mnt/, /proc/, /sys/ directories are ignored
    -x, --hex <hex>         Hex search string [default: FF]
                            - Hex string length must be a multiple of two
                            - format: 0a1b2c3d4e5f
                            - Tag: HexHunt

Note:
  Must be run as root.

  A log with data_type of 'Rootkit' will be generated if the size of file read into
  memory is less that the size on disk. This is a simple possible root kit identification
  method.
  - See: https://github.com/sandflysecurity/sandfly-file-decloak
  
  To capture network output, start a netcat listener on your port of choice.
  Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

  Files larger than 256MB will not be hashed.

  Files larger than '--max' will not be inspected for interesting strings.
```

## To compile
```
sudo apt install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --release
```

## To do
* ~~Further procfs parsing~~
* ~~Expand on interesting strings to capture in "FileContent" data_type~~
* Add static examination of binaries, including interesting strings
* Add other persistence mechanisms
* ~~Report on local users, /etc/passwd, and group, /etc/groups, membership~~
* ~~Identification of "interesting" log entries~~
* ~~Output via network comms~~
* ~~Web shell detection~~
* ~~Shell histories~~
* ~~Setuid / setgid~~
* Traps
* Document parent and child data type relation
* Add more interesting strings / commands to search for in file contents specific to Linux
* ...

## Output format
Output is in Json for import into ELK or any other Json indexer. I may add other log formats.

## Tool use
No configuration files are currently included. Everything is compiled in to acheive easier remote use of the tool. Just copy file to host and run. Pipe / redirect the output with standard Linux tools. At some point I will probably add a network send option.

## About the logs
- `parent_data_type` - if a log was generated due to something found in another log this field will hold the `data_type` of the parent log that caused this log to be generated (e.g. file path was found in a file's content and therefore the tool went and gathered metadata on that file referenced in the first file's content)
- `data_type` - the source of telemetry the log is reporting on
- `tags` - tags are added to this array field when something interesting is found by a built-in hunt
Anything of interest (a hunt, e.g. for rootkits or interesting stings/content) will be noted in the `tags` field.  

Information gathered on:
- Cron jobs
  - Data type: `Cron`
- Drive mounts
  - Data type: `MountPoint`
- Groups
  - Data type: `LocalGroup`
- Interesting File Content
  - Encoded strings
    - Tag: `Encoding`, `Base64`, `Obfuscation`
  - File referenced in a file's content
    - Tag: `FilePath` - If a file's forensic data was harvested due to it being referenced in another file this tag is added
  - IPs (v4 and v6)
    - Tag: `IPv4`, `IPv6`
  - Shell code
    - Tag: `ShellCode`
  - UNCs
    - Tag: `Unc`
  - URLs
    - Tag: `Url`
  - Web shells
    - Tag: `WebShell`
  - Custom hex search
    - Tag: `Hex`
  - Custom Regex
    - Tag: `Regex`
  - Right to left trickery
    - Tag: `RightLeft`
  - Shell references (sh, bash, zsh, ...)
    - Tag: `Shell`
  - Possible suspicious commands
    - Tag: `Suspicious`
- Link files
  - Data type: `ShellLink`
- Loaded Kernel Modules
  - Data type: `KernelModule`
- Network connections (via procfs)
  - Data type: `NetConn`
- Possible rookit
  - Data type: `Rootkit`
- Processes (via procfs)
  - Data type: `Process`
  - Process file (file of the process on disk)
  - Process' open files
    - Data type: `ProcessOpenFile`
  - Process' loaded libraries
    - Data type: `ProcessMap`
  - Process' mem mapped files
    - Data type: `ProcessMaps`
- Users
  - Data type: `LocalUser`

## Rootkit detection techniques
NOTE: Live machine analysis for rootkits is not entirely reliable. Well written rootkits will probably not be able to be discovered reliably with live machine forensics.
- Any logs generated due to a rootkit hunt will have `Rootkit` set as their `parent_data_type`
- File data that is found in memory mapped read files not found via a standard file read
  - Tag: `DataHidden`
- Directory with hidden contents
  - Tag: `DirContentsHidden`
- Tainted kernel module information
  - Tag: `KernelTaint`
- Hidden processes
  - Tag: `ProcHidden`
- World readable run lock files
  - Tag: `ProcLockWorldRead`
- Odd run lock files
  - Tag: `ProcLockSus`
- Legit process mimicry
  - Tag: `ProcMimic`
- Processes thread mimicry
  - Tag: `ThreadMimic`
- Hidden sys modules
  - Tag: `ModuleHidden`
- Raw packet sniffing processes
  - Tag: `PacketSniffer`
- Process takeovers
  - Tag: `ProcTakeover`
- Proccess run as root with socket and no deps outside of libc
  - Tag: `ProcRootSocketNoDeps`
- Odd character devices
  - Tag: `CharDeviceMimic`
##### See:
- https://github.com/tstromberg/sunlight/tree/main
- https://sandflysecurity.com/blog/how-to-detect-and-decloak-linux-stealth-rootkit-data/
- https://www.linkedin.com/pulse/detecting-linux-kernel-process-masquerading-command-line-rowland/

Some file contents are examined looking for other interesting strings. For example, if another file is referenced within a file, that file's metadata will also be retreived. Other strings of interest found in file contents are reported: IPs, file paths, URLs, shellcode, Base64 and misc encodings, and UNC paths.  
  
Process information is retreived via ProcFS parsing.  
  
The "data_type" field is used to report what the metadata in that log is pulled from. e.g. File, FileContent, Process, ... .  
The "parent_data_type" field is used to report if that log was generated due to examining another data_type. e.g. the "FileContent" data_type may trigger a "File" data_type if a file path is found in a file's contents.

The network connection logs do not show originator or responder perspectives simply because procfs reports the IPs as local and remote. You can make a good guess as to whether a network connection is incoming or outgoing based upon which port is higher than the other. But, this will not always yeild the correct direction.

If you want to change the field name(s) of any fields please edit the struct field names in the data_def source file.

## Disclaimer
This tool comes with no warranty or support. If anyone chooses to use it, you accept all responsability and liability.

```Rust
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
```
