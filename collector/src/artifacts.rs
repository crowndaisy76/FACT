use crate::filesystem::NtfsFileSystem;
use anyhow::{Result, bail};
use parser::mft::{parse_file_record_header, parse_attributes, parse_non_resident_header, parse_runlist};
use std::collections::HashSet;
use std::io::{Write, Cursor};
// [New] models 크레이트에서 공통 타겟 모델을 가져온다.
use models::artifact::{ArtifactTarget, TargetType};

pub struct ForensicCollector<'a> { 
    fs: NtfsFileSystem<'a> 
}

impl<'a> ForensicCollector<'a> {
    pub fn new(fs: NtfsFileSystem<'a>) -> Self { Self { fs } }

    pub fn collect_to_memory_stream<F>(&mut self, target: &ArtifactTarget, mut callback: F) -> Result<(usize, u64)> 
    where
        F: FnMut(&str, &[u8]),
    {
        let mut processed_count = 0;
        let mut total_bytes_streamed = 0;
        
        for detail in target.get_details() {
            match detail {
                TargetType::SingleFile { path } => {
                    if let Ok(inode) = self.fs.get_inode_by_path(path) {
                        let file_name = path.split('\\').last().unwrap();
                        
                        let mut buffer = Vec::new();
                        let mut virtual_sink = Cursor::new(&mut buffer);
                        
                        match self.extract_comprehensive_data(inode, &mut virtual_sink) {
                            Ok(written) => {
                                if written > 0 {
                                    callback(file_name, &buffer);
                                    processed_count += 1;
                                    total_bytes_streamed += written;
                                }
                            },
                            Err(e) => tracing::debug!("    [-] Failed to stream {}: {}", file_name, e),
                        }
                    }
                },
                TargetType::Directory { path, extension, recursive } => {
                    if let Ok(root_inode) = self.fs.get_inode_by_path(path) {
                        tracing::info!("  [*] Directory located: {} (Inode: {})", path, root_inode);
                        let mut stack = vec![(root_inode, String::new())];
                        let mut seen_dirs = HashSet::new();
                        let mut processed_inodes = HashSet::new();
                        
                        while let Some((dir_inode, rel_path)) = stack.pop() {
                            if !seen_dirs.insert(dir_inode) { continue; }
                            
                            if let Ok(entries) = self.fs.list_directory(dir_inode) {
                                for entry in entries {
                                    let name = entry.filename.trim_matches(char::from(0)).trim();
                                    if name.is_empty() || name == "." || name == ".." { continue; }
                                    if name.contains('~') && name.len() <= 12 { continue; }
                                    if !processed_inodes.insert(entry.file_reference) { continue; }

                                    let mut is_real_directory = entry.is_directory;
                                    if let Ok(rec) = self.fs.mft.read_record(entry.file_reference) {
                                        if let Ok(hdr) = parse_file_record_header(&rec) {
                                            is_real_directory = (hdr.flags & 0x02) != 0;
                                        }
                                    }

                                    if is_real_directory {
                                        if recursive {
                                            stack.push((entry.file_reference, format!("{}\\{}", rel_path, name)));
                                        }
                                    } else {
                                        if let Some(ext) = extension { 
                                            let target_ext = ext.to_lowercase();
                                            let file_ext = name.split('.').last().unwrap_or("").to_lowercase();
                                            if file_ext != target_ext { continue; }
                                        }
                                        
                                        let s_name = format!("{}_{}", rel_path.replace("\\", "_"), name).trim_start_matches('_').to_string();
                                        
                                        let mut buffer = Vec::new();
                                        let mut virtual_sink = Cursor::new(&mut buffer);
                                        
                                        if let Ok(written) = self.extract_comprehensive_data(entry.file_reference, &mut virtual_sink) {
                                            if written > 0 { 
                                                callback(&s_name, &buffer);
                                                processed_count += 1;
                                                total_bytes_streamed += written;
                                            }
                                        }
                                    }
                                }
                            }
                        }
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
                                        target_ads = "WofCompressedData";
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
                                    if let Ok(runs) = parse_runlist(&r[start..end]) {
                                        total_written += self.fs.mft.extract_runlist_to_writer(&runs, nr.real_size, writer).unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !data_attr_found {
            bail!("Missing $DATA attribute");
        }
        
        Ok(total_written)
    }
}