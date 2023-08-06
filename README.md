# Linux_Forensic_Harvester
Harvest Linux forensic data for operational triage of an event.

This tool will produce a considerable amount of Json logs.

If you just want to run it, download the "lin_fh" binary.

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
    ctime, atime, or mtime and only output logs where the one of the dates falls 
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
  If not run as root some telemetry cannot be harvested.

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
* ...

## Output format
Output is in Json for import into ELK or any other Json indexer. I may add other log formats.

## Tool use
No configuration files are currently included. Everything is compiled in to acheive easier remote use of the tool. Just copy file to host and run. Pipe / redirect the output with standard Linux tools. At some point I will probably add a network send option.

## About the logs
Information gathered on:
- Cron jobs
- Drive mounts
- Groups
- Interesting File Content
  - Encoded strings
  - File
  - File paths
  - IPs (v4 and v6)
  - Shell code
  - UNCs
  - URLs
  - Web shells
  - Custom hex search
  - Custom Regex
  - Right to left trickery
  - Shell references (sh, bash, zsh, ...)
- Link files
- Loaded Kernel Modules
- Network connections (via procfs)
- Possible rookit
- Processes (via procfs)
  - Process file (file of the process on disk)
  -- Process' open files
  -- Process' loaded libraries
  -- Process mem mapped files
- Users

## Rootkit detection techniques
- Searching for and reporting on a file that is larger on disk than when read into memory
- File data that is found in memory mapped read files not found via a standard file read
- Tainted kernel module information
- Hidden processes
- World readable run lock files
- Odd run lock files
- Legit process mimicry
- Processes mimicing threads
- Hidden sys modules
- Raw packet sniffing processes
- Process takeovers
- Proccess run as root with socket and no deps outside of libc
- Odd character devices
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
