use crate::mft::{MftReader, apply_fixup};
use anyhow::{Result, bail};
use models::mft::IndexEntry;
use parser::mft::{
    parse_file_record_header, parse_attributes, parse_non_resident_header, 
    parse_runlist, parse_index_entries, parse_index_record
};

pub struct NtfsFileSystem<'a> {
    pub mft: &'a mut MftReader,
}

impl<'a> NtfsFileSystem<'a> {
    pub fn new(mft: &'a mut MftReader) -> Self {
        Self { mft }
    }

    pub fn list_directory(&mut self, dir_index: u64) -> Result<Vec<IndexEntry>> {
        let mut entries = Vec::new();
        let mut queue = vec![dir_index];
        let mut seen = std::collections::HashSet::new();
        
        while let Some(idx) = queue.pop() {
            if !seen.insert(idx) { continue; }
            let data = match self.mft.read_record(idx) { 
                Ok(d) => d, 
                Err(e) => { tracing::warn!("      [!] Failed to read dir inode {}: {}", idx, e); continue; } 
            };
            let head = match parse_file_record_header(&data) { Ok(h) => h, Err(_) => continue };
            
            for attr in parse_attributes(&data, &head).unwrap_or_default() {
                match attr.type_code {
                    0x20 => { 
                        let v_off = u16::from_le_bytes([data[attr.offset+20], data[attr.offset+21]]) as usize;
                        if attr.non_resident_flag == 0 { 
                            let end = std::cmp::min(attr.offset + attr.length as usize, data.len());
                            if attr.offset + v_off <= end {
                                let list = data[attr.offset+v_off .. end].to_vec();
                                let mut cur = 0;
                                while cur + 26 <= list.len() {
                                    let t = u32::from_le_bytes(list[cur..cur+4].try_into().unwrap());
                                    if t == 0x90 || t == 0xA0 { 
                                        let r = u64::from_le_bytes(list[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                                        if r != idx && r != 0 { queue.push(r); }
                                    }
                                    let l = u16::from_le_bytes(list[cur+4..cur+6].try_into().unwrap()) as usize;
                                    if l == 0 { break; } cur += l;
                                }
                            }
                        } else { 
                            if let Ok(nr) = parse_non_resident_header(&data[attr.offset..]) {
                                let start = attr.offset + nr.run_array_offset as usize;
                                let end = std::cmp::min(attr.offset + attr.length as usize, data.len());
                                if start <= end {
                                    if let Ok(runs) = parse_runlist(&data[start..end]) {
                                        if let Ok(list) = self.mft.read_data_from_runlist(&runs, nr.real_size) {
                                            let mut cur = 0;
                                            while cur + 26 <= list.len() {
                                                let t = u32::from_le_bytes(list[cur..cur+4].try_into().unwrap());
                                                if t == 0x90 || t == 0xA0 { 
                                                    let r = u64::from_le_bytes(list[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                                                    if r != idx && r != 0 { queue.push(r); }
                                                }
                                                let l = u16::from_le_bytes(list[cur+4..cur+6].try_into().unwrap()) as usize;
                                                if l == 0 { break; } cur += l;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    0x90 => { 
                        let v_off = u16::from_le_bytes([data[attr.offset+20], data[attr.offset+21]]) as usize;
                        let end = std::cmp::min(attr.offset + attr.length as usize, data.len());
                        if attr.offset + v_off <= end {
                            let rd = &data[attr.offset+v_off .. end];
                            if rd.len() >= 32 {
                                let first_entry = u32::from_le_bytes([rd[16], rd[17], rd[18], rd[19]]) as usize;
                                if 16 + first_entry < rd.len() {
                                    let entries_data = &rd[16 + first_entry..];
                                    if let Ok(p) = parse_index_entries(entries_data) { entries.extend(p); }
                                }
                            }
                        }
                    },
                    0xA0 => { 
                        if let Ok(nr) = parse_non_resident_header(&data[attr.offset..]) {
                            let start = attr.offset + nr.run_array_offset as usize;
                            let end = std::cmp::min(attr.offset + attr.length as usize, data.len());
                            if start <= end {
                                if let Ok(runs) = parse_runlist(&data[start..end]) {
                                    if let Ok(id) = self.mft.read_data_from_runlist(&runs, u64::MAX) {
                                        for chunk in id.chunks(4096) { 
                                            if chunk.len() < 4096 { continue; }
                                            let mut fixed_chunk = chunk.to_vec();
                                            let _ = apply_fixup(&mut fixed_chunk);
                                            if let Ok(p) = parse_index_record(&fixed_chunk) {
                                                entries.extend(p);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
        Ok(entries)
    }

    pub fn get_inode_by_path(&mut self, path: &str) -> Result<u64> {
        let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
        let mut cur = 5;
        
        for (i, part) in parts.iter().enumerate() {
            if i == 0 && part.eq_ignore_ascii_case("$Extend") { cur = 11; continue; }
            let entries = self.list_directory(cur)?;
            let mut found = false;
            
            for e in entries {
                if e.filename.trim_matches(char::from(0)).trim().eq_ignore_ascii_case(part) {
                    cur = e.file_reference;
                    found = true;
                    break;
                }
            }
            if !found { bail!("Path component '{}' not found in Parent Inode {}", part, cur); }
        }
        Ok(cur)
    }
}