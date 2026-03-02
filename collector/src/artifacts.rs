use crate::mft::MftReader;
use anyhow::{Result, Context, bail};
use parser::mft::{parse_file_record_header, parse_attributes, parse_non_resident_header, parse_runlist};
use std::collections::HashSet;

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
            Self::Prefetch => vec![TargetType::Directory { path: "Windows\\Prefetch", extension: Some(".pf"), recursive: false }],
            Self::EventLogs => vec![TargetType::Directory { path: "Windows\\System32\\winevt\\Logs", extension: Some(".evtx"), recursive: false }],
            Self::USBLog => vec![TargetType::SingleFile { path: "Windows\\inf\\setupapi.dev.log" }],
            Self::ScheduledTasks => vec![TargetType::Directory { path: "Windows\\System32\\Tasks", extension: None, recursive: true }],
            Self::RecycleBin => vec![TargetType::Directory { path: "$Recycle.Bin", extension: None, recursive: true }],
        }
    }
}

pub struct ExtractedFile { pub name: String, pub data: Vec<u8> }
pub struct ForensicCollector { reader: MftReader }

impl ForensicCollector {
    pub fn new(reader: MftReader) -> Self { Self { reader } }

    pub fn collect(&mut self, target: &ArtifactTarget) -> Result<Vec<ExtractedFile>> {
        let mut results = Vec::new();
        for detail in target.get_details() {
            match detail {
                TargetType::SingleFile { path } => {
                    if let Ok(inode) = self.reader.get_inode_by_path(path) {
                        if let Ok(data) = self.extract_comprehensive_data(inode, "") {
                            results.push(ExtractedFile { name: path.split('\\').last().unwrap().into(), data });
                        }
                    }
                },
                TargetType::Directory { path, extension, recursive } => {
                    if let Ok(root_inode) = self.reader.get_inode_by_path(path) {
                        let mut stack = vec![(root_inode, String::new())];
                        let mut seen = HashSet::new();
                        while let Some((dir_inode, rel_path)) = stack.pop() {
                            if !seen.insert(dir_inode) { continue; }
                            if let Ok(entries) = self.reader.list_directory(dir_inode) {
                                for entry in entries {
                                    let name = entry.filename.trim_matches(char::from(0)).trim();
                                    if name.is_empty() || name == "." || name == ".." { continue; }
                                    if entry.flags & 0x0001 != 0 && recursive {
                                        stack.push((entry.file_reference, format!("{}\\{}", rel_path, name)));
                                    } else {
                                        if let Some(ext) = extension { if !name.to_lowercase().ends_with(&ext.to_lowercase()) { continue; } }
                                        if let Ok(data) = self.extract_comprehensive_data(entry.file_reference, "") {
                                            let s_name = format!("{}_{}", rel_path.replace("\\", "_"), name).trim_start_matches('_').to_string();
                                            results.push(ExtractedFile { name: s_name, data });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    fn extract_comprehensive_data(&mut self, base_index: u64, target_ads: &str) -> Result<Vec<u8>> {
        let mut inodes = vec![base_index];
        let mut final_data = Vec::new();
        let record = self.reader.read_record(base_index)?;
        let header = parse_file_record_header(&record)?;
        let mut off = header.attr_offset as usize;
        for attr in parse_attributes(&record, &header)? {
            if attr.type_code == 0x20 { 
                let v_off = u16::from_le_bytes([record[off+20], record[off+21]]) as usize;
                let list = if attr.non_resident_flag == 0 { record.get(off+v_off..off+attr.length as usize).unwrap_or(&[]).to_vec() }
                           else { let nr = parse_non_resident_header(&record[off..])?;
                                  let runs = parse_runlist(&record[off+nr.run_array_offset as usize..])?;
                                  self.reader.read_data_from_runlist(&runs, nr.real_size)? };
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
            off += attr.length as usize;
        }
        for &inode in &inodes {
            let r = self.reader.read_record(inode)?;
            let h = parse_file_record_header(&r)?;
            let mut a_off = h.attr_offset as usize;
            for attr in parse_attributes(&r, &h)? {
                if attr.type_code == 0x80 {
                    let mut name = String::new();
                    if attr.name_length > 0 {
                        let ns = a_off + attr.name_offset as usize;
                        if let Some(nb) = r.get(ns..ns + (attr.name_length as usize * 2)) {
                            let u16v: Vec<u16> = nb.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                            name = String::from_utf16_lossy(&u16v);
                        }
                    }
                    if name.eq_ignore_ascii_case(target_ads) {
                        if attr.non_resident_flag == 0 {
                            let v_o = u16::from_le_bytes(r[a_off+20..a_off+22].try_into()?) as usize;
                            let v_s = u32::from_le_bytes(r[a_off+16..a_off+20].try_into()?) as usize;
                            final_data.extend(r.get(a_off+v_o..a_off+v_o+v_s).unwrap_or(&[]));
                        } else {
                            let nr = parse_non_resident_header(&r[a_off..])?;
                            let runs = parse_runlist(&r[a_off+nr.run_array_offset as usize..])?;
                            final_data.extend(self.reader.read_data_from_runlist(&runs, nr.real_size)?);
                        }
                    }
                }
                a_off += attr.length as usize;
            }
        }
        if final_data.is_empty() { bail!("No data"); } Ok(final_data)
    }
}