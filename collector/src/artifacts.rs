use crate::filesystem::NtfsFileSystem;
use anyhow::{Result, bail};
use parser::mft::{parse_file_record_header, parse_attributes, parse_non_resident_header, parse_runlist};
use std::collections::HashSet;
use std::io::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactTarget {
    MFT, LogFile, Amcache,
    RegistrySAM, RegistrySECURITY, RegistrySOFTWARE, RegistrySYSTEM,
    Prefetch, EventLogs, ScheduledTasks, RecycleBin, USBLog
}

pub enum TargetType {
    SingleFile { path: &'static str },
    Directory { path: &'static str, extension: Option<&'static str>, recursive: bool },
}

impl ArtifactTarget {
    pub fn get_details(&self) -> Vec<TargetType> {
        match self {
            Self::MFT => vec![TargetType::SingleFile { path: "$MFT" }],
            Self::LogFile => vec![TargetType::SingleFile { path: "$LogFile" }],
            Self::RegistrySAM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SAM" }],
            Self::RegistrySECURITY => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SECURITY" }],
            Self::RegistrySOFTWARE => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SOFTWARE" }],
            Self::RegistrySYSTEM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SYSTEM" }],
            Self::Amcache => vec![TargetType::SingleFile { path: "Windows\\AppCompat\\Programs\\Amcache.hve" }],
            Self::Prefetch => vec![TargetType::Directory { path: "Windows\\Prefetch", extension: Some("pf"), recursive: false }],
            Self::EventLogs => vec![TargetType::Directory { path: "Windows\\System32\\winevt\\Logs", extension: Some("evtx"), recursive: false }],
            Self::USBLog => vec![TargetType::SingleFile { path: "Windows\\inf\\setupapi.dev.log" }],
            Self::ScheduledTasks => vec![TargetType::Directory { path: "Windows\\System32\\Tasks", extension: None, recursive: true }],
            Self::RecycleBin => vec![TargetType::Directory { path: "$Recycle.Bin", extension: None, recursive: true }],
        }
    }
}

pub struct ForensicCollector<'a> { 
    fs: NtfsFileSystem<'a> 
}

impl<'a> ForensicCollector<'a> {
    pub fn new(fs: NtfsFileSystem<'a>) -> Self { Self { fs } }

    pub fn collect_to_memory_stream(&mut self, target: &ArtifactTarget) -> Result<(usize, u64)> {
        let mut processed_count = 0;
        let mut total_bytes_streamed = 0;
        
        for detail in target.get_details() {
            match detail {
                TargetType::SingleFile { path } => {
                    match self.fs.get_inode_by_path(path) {
                        Ok(inode) => {
                            let file_name = path.split('\\').last().unwrap();
                            let mut virtual_sink = std::io::sink();
                            
                            match self.extract_comprehensive_data(inode, &mut virtual_sink) {
                                Ok(written) => {
                                    tracing::info!("    [+] Streamed: {} ({} bytes)", file_name, written);
                                    if written > 0 {
                                        processed_count += 1;
                                        total_bytes_streamed += written;
                                    }
                                },
                                Err(e) => tracing::warn!("    [-] Failed to stream {}: {}", file_name, e),
                            }
                        },
                        Err(e) => tracing::error!("    [-] Failed to locate {}: {}", path, e),
                    }
                },
                TargetType::Directory { path, extension, recursive } => {
                    match self.fs.get_inode_by_path(path) {
                        Ok(root_inode) => {
                            tracing::info!("  [*] Directory located: {} (Inode: {})", path, root_inode);
                            let mut stack = vec![(root_inode, String::new())];
                            let mut seen_dirs = HashSet::new();
                            let mut processed_inodes = HashSet::new();
                            
                            while let Some((dir_inode, rel_path)) = stack.pop() {
                                if !seen_dirs.insert(dir_inode) { continue; }
                                
                                if let Ok(entries) = self.fs.list_directory(dir_inode) {
                                    if rel_path.is_empty() {
                                        tracing::info!("      [*] Found {} raw entries in Root Directory", entries.len());
                                    }

                                    for entry in entries {
                                        let name = entry.filename.trim_matches(char::from(0)).trim();
                                        if name.is_empty() || name == "." || name == ".." { continue; }

                                        if name.contains('~') && name.len() <= 12 { continue; }
                                        if !processed_inodes.insert(entry.file_reference) { continue; }

                                        let mut is_real_directory = entry.is_directory;
                                        let mut is_in_use = true;
                                        
                                        match self.fs.mft.read_record(entry.file_reference) {
                                            Ok(rec) => {
                                                if let Ok(hdr) = parse_file_record_header(&rec) {
                                                    is_in_use = (hdr.flags & 0x01) != 0;
                                                    is_real_directory = (hdr.flags & 0x02) != 0;
                                                }
                                            },
                                            Err(_) => continue,
                                        }

                                        if is_real_directory {
                                            if recursive {
                                                stack.push((entry.file_reference, format!("{}\\{}", rel_path, name)));
                                            }
                                        } else {
                                            if let Some(ext) = extension { 
                                                if !name.to_lowercase().ends_with(&ext.to_lowercase()) { continue; } 
                                            }
                                            
                                            let s_name = format!("{}_{}", rel_path.replace("\\", "_"), name).trim_start_matches('_').to_string();
                                            let mut virtual_sink = std::io::sink();
                                            
                                            match self.extract_comprehensive_data(entry.file_reference, &mut virtual_sink) {
                                                Ok(written) => {
                                                    if is_in_use {
                                                        tracing::info!("    [+] Streamed: {} ({} bytes)", s_name, written);
                                                    } else {
                                                        tracing::info!("    [RECOVERED] Streamed Deleted Slack Data: {} ({} bytes)", s_name, written);
                                                    }
                                                    if written > 0 { 
                                                        processed_count += 1;
                                                        total_bytes_streamed += written;
                                                    }
                                                },
                                                Err(e) => {
                                                    // 더 이상 숨기지 않는다. 에러 발생 시 무조건 출력한다!
                                                    tracing::warn!("    [-] Failed to stream {}: {}", s_name, e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Err(e) => tracing::error!("  [-] Directory resolution failed: {}", e),
                    }
                }
            }
        }
        Ok((processed_count, total_bytes_streamed))
    }

    fn extract_comprehensive_data(&mut self, base_index: u64, writer: &mut dyn Write) -> Result<u64> {
        let mut inodes = vec![base_index];
        let mut total_written: u64 = 0;
        
        let record = match self.fs.mft.read_record(base_index) { Ok(rec) => rec, Err(e) => bail!("MFT Read Error: {}", e) };
        let header = match parse_file_record_header(&record) { Ok(h) => h, Err(e) => bail!("MFT Header Error: {}", e) };

        let attrs = match parse_attributes(&record, &header) { Ok(a) => a, Err(_) => vec![] };

        for attr in &attrs {
            if attr.type_code == 0x20 { 
                let v_off = u16::from_le_bytes([record[attr.offset+20], record[attr.offset+21]]) as usize;
                let list = if attr.non_resident_flag == 0 { 
                    let end = std::cmp::min(attr.offset + attr.length as usize, record.len());
                    if attr.offset + v_off <= end {
                        record[attr.offset+v_off .. end].to_vec() 
                    } else { vec![] }
                } else { 
                    if let Ok(nr) = parse_non_resident_header(&record[attr.offset..]) {
                        let start = attr.offset + nr.run_array_offset as usize;
                        let end = std::cmp::min(attr.offset + attr.length as usize, record.len());
                        if start <= end {
                            if let Ok(runs) = parse_runlist(&record[start..end]) {
                                self.fs.mft.read_data_from_runlist(&runs, nr.real_size).unwrap_or_default()
                            } else { vec![] }
                        } else { vec![] }
                    } else { vec![] }
                };
                
                let mut cur = 0;
                while cur + 26 <= list.len() {
                    let t = u32::from_le_bytes(list[cur..cur+4].try_into().unwrap());
                    if t == 0x80 {
                        let r = u64::from_le_bytes(list[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                        if !inodes.contains(&r) { inodes.push(r); }
                    }
                    let l = u16::from_le_bytes(list[cur+4..cur+6].try_into().unwrap()) as usize;
                    if l == 0 { break; } cur += l;
                }
            }
        }

        // [Ultimate Power Move] WOF(Windows Overlay Filter) 압축 데이터 자동 감지
        let mut target_ads = "";
        for &inode in &inodes {
            if let Ok(r) = self.fs.mft.read_record(inode) {
                if let Ok(h) = parse_file_record_header(&r) {
                    let inode_attrs = parse_attributes(&r, &h).unwrap_or_default();
                    for attr in inode_attrs {
                        if attr.type_code == 0x80 && attr.name_length > 0 {
                            let ns = attr.offset + attr.name_offset as usize;
                            let end = std::cmp::min(ns + (attr.name_length as usize * 2), r.len());
                            if ns <= end {
                                if let Some(nb) = r.get(ns..end) {
                                    let u16v: Vec<u16> = nb.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                                    let name = String::from_utf16_lossy(&u16v);
                                    if name.eq_ignore_ascii_case("WofCompressedData") {
                                        target_ads = "WofCompressedData"; // Windows 10/11 압축 파일 발견!
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut data_attr_found = false;

        for &inode in &inodes {
            let r = match self.fs.mft.read_record(inode) { Ok(rec) => rec, Err(_) => continue };
            let h = match parse_file_record_header(&r) { Ok(hdr) => hdr, Err(_) => continue };
            
            let inode_attrs = parse_attributes(&r, &h).unwrap_or_default();
            for attr in inode_attrs {
                if attr.type_code == 0x80 {
                    let mut name = String::new();
                    if attr.name_length > 0 {
                        let ns = attr.offset + attr.name_offset as usize;
                        let end = std::cmp::min(ns + (attr.name_length as usize * 2), r.len());
                        if ns <= end {
                            if let Some(nb) = r.get(ns..end) {
                                let u16v: Vec<u16> = nb.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                                name = String::from_utf16_lossy(&u16v);
                            }
                        }
                    }
                    
                    if name.eq_ignore_ascii_case(target_ads) {
                        data_attr_found = true;
                        
                        if attr.non_resident_flag == 0 {
                            let data_size = u32::from_le_bytes([
                                r[attr.offset + 16], r[attr.offset + 17], 
                                r[attr.offset + 18], r[attr.offset + 19]
                            ]) as usize;
                            
                            let data_offset = u16::from_le_bytes([
                                r[attr.offset + 20], r[attr.offset + 21]
                            ]) as usize;

                            let start = attr.offset + data_offset;
                            let end = start + data_size;

                            if start < r.len() && end <= r.len() {
                                writer.write_all(&r[start..end])?;
                                total_written += data_size as u64;
                            }
                        } else {
                            if let Ok(nr) = parse_non_resident_header(&r[attr.offset..]) {
                                let start = attr.offset + nr.run_array_offset as usize;
                                let end = std::cmp::min(attr.offset + attr.length as usize, r.len());
                                if start <= end {
                                    let runs = parse_runlist(&r[start..end])?; // 에러 숨기지 않음
                                    // 에러 발생 시 0으로 삼키지 않고 바깥으로 내던짐!
                                    let written = self.fs.mft.extract_runlist_to_writer(&runs, nr.real_size, writer)?;
                                    total_written += written;
                                }
                            }
                        }
                    }
                }
            }
        }

        if !data_attr_found {
            bail!("Missing $DATA attribute (0 bytes or purely Sparse)");
        }
        
        Ok(total_written)
    }
}