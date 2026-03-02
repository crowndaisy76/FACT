use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use anyhow::{Result, Context, bail};
use models::mft::{DataRun, IndexEntry};
use parser::ntfs::parse_boot_sector;
use parser::mft::{
    parse_file_record_header, parse_attributes, parse_non_resident_header, 
    parse_runlist, parse_index_root, parse_index_entries, parse_index_record
};

pub struct MftReader {
    file: File,                 
    cluster_size: u64,          
    record_size: u64,           
    mft_runlist: Vec<DataRun>,  
}

impl MftReader {
    pub fn bootstrap(mut file: File) -> Result<Self> {
        let mut vbr = [0u8; 512];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut vbr)?;
        let boot = parse_boot_sector(&vbr)?;
        let cluster_size = boot.cluster_size();
        let mft_offset = boot.mft_offset();
        file.seek(SeekFrom::Start(mft_offset))?;
        let mut mft_0 = vec![0u8; 1024];
        file.read_exact(&mut mft_0)?;
        let header = parse_file_record_header(&mft_0)?;
        let mut mft_runlist = Vec::new();
        let mut offset = header.attr_offset as usize;
        for attr in parse_attributes(&mft_0, &header)? {
            if attr.type_code == 0x80 && attr.non_resident_flag == 1 {
                let nr = parse_non_resident_header(&mft_0[offset..])?;
                mft_runlist = parse_runlist(&mft_0[offset + nr.run_array_offset as usize..])?;
                break;
            }
            offset += attr.length as usize;
        }
        Ok(Self { file, cluster_size, record_size: 1024, mft_runlist })
    }

    pub fn read_record(&mut self, index: u64) -> Result<Vec<u8>> {
        let v_off = index.checked_mul(self.record_size).context("MFT Overflow")?;
        let target_vcn = v_off / self.cluster_size;
        let mut current_vcn = 0;
        for run in &self.mft_runlist {
            if target_vcn >= current_vcn && target_vcn < current_vcn + run.length {
                let lcn = run.start_lcn + (target_vcn - current_vcn);
                let phys_off = lcn.checked_mul(self.cluster_size).context("Phys Overflow")? + (v_off % self.cluster_size);
                self.file.seek(SeekFrom::Start(phys_off))?;
                let mut buf = vec![0u8; self.record_size as usize];
                self.file.read_exact(&mut buf)?;
                return Ok(buf);
            }
            current_vcn += run.length;
        }
        bail!("Inode {} OOB", index)
    }

    pub fn read_data_from_runlist(&mut self, runlist: &[DataRun], max_size: u64) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut total_read: u64 = 0;
        for run in runlist {
            if total_read >= max_size { break; }
            let run_len = run.length.checked_mul(self.cluster_size).unwrap_or(u64::MAX);
            let size = std::cmp::min(run_len, max_size - total_read);
            let mut chunk = vec![0u8; size as usize];
            if run.start_lcn != u64::MAX {
                if let Some(off) = run.start_lcn.checked_mul(self.cluster_size) {
                    self.file.seek(SeekFrom::Start(off))?;
                    let _ = self.file.read_exact(&mut chunk);
                }
            }
            buffer.extend(chunk);
            total_read += size;
        }
        Ok(buffer)
    }

    pub fn list_directory(&mut self, dir_index: u64) -> Result<Vec<IndexEntry>> {
        let mut entries = Vec::new();
        let mut queue = vec![dir_index];
        let mut seen = std::collections::HashSet::new();
        while let Some(idx) = queue.pop() {
            if !seen.insert(idx) { continue; }
            let data = match self.read_record(idx) { Ok(d) => d, Err(_) => continue };
            let head = parse_file_record_header(&data)?;
            let mut off = head.attr_offset as usize;
            for attr in parse_attributes(&data, &head)? {
                match attr.type_code {
                    0x20 => { // $ATTRIBUTE_LIST 분산 데이터 통합
                        let v_off = u16::from_le_bytes([data[off+20], data[off+21]]) as usize;
                        let list = if attr.non_resident_flag == 0 { data.get(off+v_off..off+attr.length as usize).unwrap_or(&[]).to_vec() }
                                   else { let nr = parse_non_resident_header(&data[off..])?;
                                          let runs = parse_runlist(&data[off+nr.run_array_offset as usize..])?;
                                          self.read_data_from_runlist(&runs, nr.real_size).unwrap_or_default() };
                        let mut cur = 0;
                        while cur + 26 <= list.len() {
                            let t = u32::from_le_bytes(list[cur..cur+4].try_into().unwrap());
                            if t == 0x90 || t == 0xA0 {
                                let r = u64::from_le_bytes(list[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                                if r != idx { queue.push(r); }
                            }
                            let l = u16::from_le_bytes(list[cur+4..cur+6].try_into().unwrap()) as usize;
                            if l == 0 { break; } cur += l;
                        }
                    },
                    0x90 => { // $INDEX_ROOT
                        let v_off = u16::from_le_bytes([data[off+20], data[off+21]]) as usize;
                        if let Some(rd) = data.get(off+v_off..off+attr.length as usize) {
                            if let Ok(root) = parse_index_root(rd) {
                                if let Ok(p) = parse_index_entries(&rd[16+root.header.first_entry_offset as usize..]) { entries.extend(p); }
                            }
                        }
                    },
                    0xA0 => { // $INDEX_ALLOCATION 대형 디렉토리 전수 조사
                        if let Ok(nr) = parse_non_resident_header(&data[off..]) {
                            let runs = parse_runlist(&data[off+nr.run_array_offset as usize..])?;
                            if let Ok(id) = self.read_data_from_runlist(&runs, nr.real_size) {
                                for chunk in id.chunks_exact(4096) { if let Ok(p) = parse_index_record(chunk) { entries.extend(p); } }
                            }
                        }
                    },
                    _ => {}
                }
                off += attr.length as usize;
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
            cur = entries.iter().find(|e| e.filename.trim_matches(char::from(0)).trim().eq_ignore_ascii_case(part))
                         .map(|e| e.file_reference).context(format!("'{}' not found", part))?;
        }
        Ok(cur)
    }
}