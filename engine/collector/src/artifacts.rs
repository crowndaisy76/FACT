use crate::filesystem::NtfsFileSystem;
use anyhow::{Result, bail};
use parser::mft::{parse_file_record_header, parse_attributes, parse_non_resident_header, parse_runlist};
use std::collections::HashSet;
use std::io::{Write, Cursor};
use models::artifact::{ArtifactTarget, TargetType};

pub struct ForensicCollector { 
    pub fs: NtfsFileSystem 
}

impl ForensicCollector {
    pub fn new(fs: NtfsFileSystem) -> Self { Self { fs } }

    pub fn collect_to_memory_stream<F>(&mut self, target: &ArtifactTarget, mut callback: F) -> Result<(usize, u64)> 
    where
        F: FnMut(&str, &[u8]),
    {
        let mut processed_count = 0;
        let mut total_bytes_streamed = 0;
        
        for detail in target.get_details() {
            match detail {
                TargetType::SingleFile { path } => {
                    let parts: Vec<&str> = path.split(':').collect();
                    let file_path = parts[0];
                    let requested_ads = if parts.len() > 1 { parts[1] } else { "" };
                    let file_name = file_path.split('\\').last().unwrap_or("unknown");
                    
                    match self.fs.get_inode_by_path(file_path) {
                        Ok(inode) => {
                            let mut buffer = Vec::new();
                            let mut virtual_sink = Cursor::new(&mut buffer);
                            
                            match self.extract_comprehensive_data(inode, requested_ads, &mut virtual_sink) {
                                Ok(written) => {
                                    if written > 0 {
                                        callback(file_name, &buffer);
                                        processed_count += 1;
                                        total_bytes_streamed += written;
                                    } else {
                                        tracing::warn!("  [?] 0 bytes extracted for SingleFile: {}", file_path);
                                    }
                                },
                                Err(e) => tracing::error!("  [!] Extraction failed for {}: {}", file_path, e),
                            }
                        },
                        Err(e) => tracing::error!("  [!] get_inode_by_path failed for {}: {}", file_path, e),
                    }
                },
                TargetType::Directory { path, extension, recursive } => {
                    match self.fs.get_inode_by_path(path) {
                        Ok(root_inode) => {
                            let mut stack = vec![(root_inode, String::new())];
                            let mut seen_dirs = HashSet::new();
                            let mut processed_inodes = HashSet::new();
                            
                            while let Some((dir_inode, rel_path)) = stack.pop() {
                                if !seen_dirs.insert(dir_inode) { continue; }
                                
                                match self.fs.list_directory(dir_inode) {
                                    Ok(entries) => {
                                        for entry in entries {
                                            let name = entry.filename.trim_matches(char::from(0)).trim();
                                            if name.is_empty() || name == "." || name == ".." { continue; }
                                            if !processed_inodes.insert(entry.file_reference) { continue; }

                                            if entry.is_directory {
                                                if recursive {
                                                    stack.push((entry.file_reference, format!("{}\\{}", rel_path, name)));
                                                }
                                            } else {
                                                if let Some(ext) = extension { 
                                                    if !name.to_lowercase().ends_with(&ext.to_lowercase()) { continue; }
                                                }
                                                let mut buffer = Vec::new();
                                                match self.extract_comprehensive_data(entry.file_reference, "", &mut Cursor::new(&mut buffer)) {
                                                    Ok(written) => {
                                                        if written > 0 { 
                                                            let s_name = format!("{}_{}", rel_path.replace("\\", "_"), name).trim_start_matches('_').to_string();
                                                            callback(&s_name, &buffer);
                                                            processed_count += 1;
                                                            total_bytes_streamed += written;
                                                        }
                                                    },
                                                    Err(e) => tracing::error!("  [!] Extraction failed for {} in directory: {}", name, e),
                                                }
                                            }
                                        }
                                    },
                                    Err(e) => tracing::error!("  [!] list_directory failed for Inode {} in path {}: {}", dir_inode, path, e),
                                }
                            }
                        },
                        Err(e) => tracing::error!("  [!] get_inode_by_path failed for Directory target {}: {}", path, e),
                    }
                }
            }
        }
        Ok((processed_count, total_bytes_streamed))
    }

    fn extract_comprehensive_data(&mut self, base_index: u64, requested_ads: &str, writer: &mut dyn Write) -> Result<u64> {
        let mut inodes = vec![base_index];
        let mut total_written: u64 = 0;
        
        let record = match self.fs.mft.read_record(base_index) {
            Ok(r) => r,
            Err(e) => bail!("MFT read_record failed: {}", e),
        };
        
        let header = match parse_file_record_header(&record) {
            Ok(h) => h,
            Err(e) => bail!("parse_file_record_header failed: {:?}", e),
        };
        
        let attrs = parse_attributes(&record, &header).unwrap_or_default();

        for attr in &attrs {
            if attr.type_code == 0x20 { 
                let v_off = u16::from_le_bytes([record[attr.offset+20], record[attr.offset+21]]) as usize;
                let list = if attr.non_resident_flag == 0 {
                    record[attr.offset+v_off..std::cmp::min(attr.offset + attr.length as usize, record.len())].to_vec()
                } else {
                    let nr = parse_non_resident_header(&record[attr.offset..])?;
                    let runs = parse_runlist(&record[attr.offset+nr.run_array_offset as usize..std::cmp::min(attr.offset + attr.length as usize, record.len())])?;
                    self.fs.mft.read_data_from_runlist(&runs, nr.real_size).unwrap_or_default()
                };
                let mut cur = 0;
                while cur + 26 <= list.len() {
                    if u32::from_le_bytes(list[cur..cur+4].try_into().unwrap()) == 0x80 {
                        let r = u64::from_le_bytes(list[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                        if !inodes.contains(&r) { inodes.push(r); }
                    }
                    let l = u16::from_le_bytes(list[cur+4..cur+6].try_into().unwrap()) as usize;
                    if l == 0 { break; } cur += l;
                }
            }
        }

        let mut target_stream = requested_ads.to_string();
        if target_stream.is_empty() {
            for &inode in &inodes {
                if let Ok(r) = self.fs.mft.read_record(inode) {
                    if let Ok(h) = parse_file_record_header(&r) {
                        for attr in parse_attributes(&r, &h).unwrap_or_default() {
                            if attr.type_code == 0x80 && attr.name_length > 0 {
                                let ns = attr.offset + attr.name_offset as usize;
                                let name = String::from_utf16_lossy(&r[ns..ns+(attr.name_length as usize * 2)].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>());
                                if name.eq_ignore_ascii_case("WofCompressedData") { target_stream = "WofCompressedData".to_string(); }
                            }
                        }
                    }
                }
            }
        }

        for &inode in &inodes {
            if let Ok(r) = self.fs.mft.read_record(inode) {
                if let Ok(h) = parse_file_record_header(&r) {
                    for attr in parse_attributes(&r, &h).unwrap_or_default() {
                        if attr.type_code == 0x80 {
                            let mut name = String::new();
                            if attr.name_length > 0 {
                                let ns = attr.offset + attr.name_offset as usize;
                                name = String::from_utf16_lossy(&r[ns..ns+(attr.name_length as usize * 2)].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>());
                            }
                            if name.eq_ignore_ascii_case(&target_stream) {
                                if attr.non_resident_flag == 0 {
                                    let size = u32::from_le_bytes([r[attr.offset+16], r[attr.offset+17], r[attr.offset+18], r[attr.offset+19]]) as usize;
                                    let off = u16::from_le_bytes([r[attr.offset+20], r[attr.offset+21]]) as usize;
                                    writer.write_all(&r[attr.offset+off..attr.offset+off+size])?;
                                    total_written += size as u64;
                                } else {
                                    let nr = parse_non_resident_header(&r[attr.offset..])?;
                                    let runs = parse_runlist(&r[attr.offset+nr.run_array_offset as usize..std::cmp::min(attr.offset + attr.length as usize, r.len())])?;
                                    total_written += self.fs.mft.extract_runlist_to_writer(&runs, nr.real_size, writer).unwrap_or(0);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(total_written)
    }
}