use netscope_core::ProcessMetadata;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

pub struct ProcessResolver {
    inode_to_pid: HashMap<u64, u32>,
    pid_cache: HashMap<u32, ProcessMetadata>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            inode_to_pid: HashMap::new(),
            pid_cache: HashMap::new(),
        }
    }

    /// Scans /proc to build a mapping from socket inodes to PIDs
    pub fn refresh(&mut self) -> Result<(), std::io::Error> {
        let mut new_inode_to_pid = HashMap::new();
        let mut new_pid_cache = HashMap::new();

        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(proc_dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue, // not a PID directory
            };

            let pid_path = entry.path();
            let fd_dir = pid_path.join("fd");

            // Read process metadata
            let metadata = Self::read_process_metadata(pid, &pid_path);
            new_pid_cache.insert(pid, metadata);

            // Read file descriptors
            if let Ok(fds) = fs::read_dir(fd_dir) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                new_inode_to_pid.insert(inode, pid);
                            }
                        } else if link_str.starts_with("[0000]:") {
                            // Some kernels/filesystems format socket as [0000]:<inode>
                            let inode_str = &link_str[7..];
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                new_inode_to_pid.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }

        self.inode_to_pid = new_inode_to_pid;
        self.pid_cache = new_pid_cache;
        debug!("Refreshed process resolver: {} socket mappings, {} processes", self.inode_to_pid.len(), self.pid_cache.len());
        Ok(())
    }

    pub fn get_process_by_inode(&self, inode: u64) -> Option<ProcessMetadata> {
        self.inode_to_pid.get(&inode).and_then(|pid| self.pid_cache.get(pid).cloned())
    }

    pub fn get_process_by_pid(&self, pid: u32) -> Option<ProcessMetadata> {
        self.pid_cache.get(&pid).cloned()
    }

    pub fn all_processes(&self) -> Vec<ProcessMetadata> {
        self.pid_cache.values().cloned().collect()
    }

    fn read_process_metadata(pid: u32, pid_path: &Path) -> ProcessMetadata {
        // Read comm or status for process name
        let mut name = String::new();
        if let Ok(comm) = fs::read_to_string(pid_path.join("comm")) {
            name = comm.trim().to_string();
        }

        // Executable path
        let exe_path: Option<PathBuf> = fs::read_link(pid_path.join("exe")).ok();
        if name.is_empty() {
            if let Some(ref path) = exe_path {
                if let Some(file_name) = path.file_name() {
                    name = file_name.to_string_lossy().to_string();
                }
            }
        }
        if name.is_empty() {
            name = format!("[pid {}]", pid);
        }

        // Command line arguments
        let mut cmdline = Vec::new();
        if let Ok(cmd_bytes) = fs::read(pid_path.join("cmdline")) {
            for arg in cmd_bytes.split(|&b| b == 0) {
                if !arg.is_empty() {
                    cmdline.push(String::from_utf8_lossy(arg).to_string());
                }
            }
        }

        // UID and user
        let mut uid = 0;
        let mut user = None;
        if let Ok(status) = fs::read_to_string(pid_path.join("status")) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        if let Ok(u) = parts[1].parse::<u32>() {
                            uid = u;
                            if uid == 0 {
                                user = Some("root".to_string());
                            } else if let Ok(u_name) = std::env::var("USER") {
                                user = Some(u_name);
                            }
                        }
                    }
                    break;
                }
            }
        }

        ProcessMetadata {
            pid,
            name,
            exe_path,
            cmdline,
            uid,
            user,
            start_time: None,
        }
    }
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}
