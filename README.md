# Linux_Forensic_Harvester
Harvest Linux forensic data for operational triage of an event.

## Why this tool
I am writing this in Rust for two reasons:
* I want to learn and get better programming in Rust.
* I find that programming forensics tools helps me learn and retain things better.

## Output Format
Output is in Json for import into ELK or any other Json indexer.

## Tool use
No configuration files are currently included. Everything is compiled in to acheive easier remote use of the tool. Just copy file to host and run. Pipe / redirect the output with standard Linux tools. At some point I will probably add a network send option.

## 
Presently only directory and file metadata are examined. Some file contents are examined looking for other interesting strings. For example, if another file is referenced within a file, that file's metadata will also be retreived. Other strings of interest found in file contents are reported: IPs, file paths, URLs, shellcode, Base64 and misc encodings, and UNC paths.  
  
Process information is retreived via ProcFS parsing.  
  
The "data_type" field is used to report what the metadata in that log is pulled from. e.g. File, FileContent, Process, ... .  
The "parent_data_type" field is used to report if that log was generated due to examining another data_type. e.g. the "FileContent" data_type may trigger a "File" data_type if a file path is found in a file's contents.
