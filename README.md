# Linux_Forensic_Harvester
Harvest Linux forensic data for operational triage of an event.

If you just want to run it, download the "lin_fh" binary.

```
Linux Forensic Harvester
    Author: Brian Kellogg
    License: MIT
    Disclaimer:
        This tool comes with no warranty or support.
        If anyone chooses to use it, you accept all responsibility and liability.

If not run as root, not all telemetry can be harvested.

Usage:
  lin_fh [--ip <ip> --port <port>]
  lin_fh [--ip <ip> --port <port>] [--limit]
  lin_fh --limit
  lin_fh --help

Options:
  -h, --help            Show this screen
  -i, --ip <ip>         IP address to send output to [default: NONE]
  -p, --port <port>     Destination port to send output to [default: 80]
  -l, --limit           Limit CPU use

Note:
  If not run as root some telemetry cannot be harvested.

  To capture network output, start a netcat listener on your port of choice.
  Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

  Files larger than 256MB will not be hashed.
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
- Link files
- Loaded Kernel Modules
- Network connections (via procfs)
- Processes (via procfs)
- Process file (file of the process on disk)
- Users

Some file contents are examined looking for other interesting strings. For example, if another file is referenced within a file, that file's metadata will also be retreived. Other strings of interest found in file contents are reported: IPs, file paths, URLs, shellcode, Base64 and misc encodings, and UNC paths.  
  
Process information is retreived via ProcFS parsing.  
  
The "data_type" field is used to report what the metadata in that log is pulled from. e.g. File, FileContent, Process, ... .  
The "parent_data_type" field is used to report if that log was generated due to examining another data_type. e.g. the "FileContent" data_type may trigger a "File" data_type if a file path is found in a file's contents.

The network connection logs do not show originator or responder perspectives simply because procfs reports the IPs as local and remote. You can make a good guess as to whether a network connection is incoming or outgoing based upon which port is higher than the other. But, this will not always yeild the correct direction.

If you want to change the field name(s) of any fields please edit the struct field names in the data_def source file.

## Disclaimer
This tool comes with no warranty or support. If anyone chooses to use it, you accept all responsability and liability.
