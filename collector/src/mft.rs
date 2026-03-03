use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use anyhow::{Result, Context, bail};
use models::mft::DataRun;
use parser::mft::{
    parse_file_record_header, parse_attributes, parse_non_resident_header, 
    parse_runlist, parse_boot_sector_manual
};

pub(crate) fn apply_fixup(data: &mut [u8]) -> Result<()> {
    if data.len() < 512 { return Ok(()); }
    let signature = &data[0..4];
    if signature != b"FILE" && signature != b"INDX" { return Ok(()); }
    let usa_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
    let usa_count = u16::from_le_bytes([data[6], data[7]]) as usize;
    if usa_offset == 0 || usa_count <= 1 || usa_offset + (usa_count * 2) > data.len() { return Ok(()); }
    let update_seq_num = [data[usa_offset], data[usa_offset+1]];
    let sector_count = usa_count - 1;
    let sector_size = 512;
    for i in 0..sector_count {
        let sector_end = (i + 1) * sector_size - 2;
        let fixup_idx = usa_offset + 2 + (i * 2);
        if sector_end + 2 > data.len() || fixup_idx + 2 > data.len() { break; }
        if data[sector_end] == update_seq_num[0] && data[sector_end+1] == update_seq_num[1] {
            data[sector_end] = data[fixup_idx];
            data[sector_end+1] = data[fixup_idx+1];
        }
    }
    Ok(())
}

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
        let boot = parse_boot_sector_manual(&vbr)?;
        let cluster_size = boot.cluster_size();
        let mft_offset = boot.mft_offset();
        
        file.seek(SeekFrom::Start(mft_offset))?;
        let mut mft_0 = vec![0u8; 1024];
        file.read_exact(&mut mft_0)?;
        apply_fixup(&mut mft_0)?;
        
        let header = parse_file_record_header(&mft_0)?;
        let attrs = parse_attributes(&mft_0, &header)?;
        
        let mut initial_runlist = Vec::new();
        let mut attr_list_data = Vec::new();
        
        for attr in &attrs {
            if attr.type_code == 0x20 { 
                let v_off = u16::from_le_bytes([mft_0[attr.offset+20], mft_0[attr.offset+21]]) as usize;
                if attr.non_resident_flag == 0 {
                    let end = std::cmp::min(attr.offset + attr.length as usize, mft_0.len());
                    if attr.offset + v_off <= end {
                        attr_list_data = mft_0[attr.offset+v_off .. end].to_vec();
                    }
                }
            } else if attr.type_code == 0x80 && attr.non_resident_flag == 1 {
                if let Ok(nr) = parse_non_resident_header(&mft_0[attr.offset..]) {
                    let start = attr.offset + nr.run_array_offset as usize;
                    let end = std::cmp::min(attr.offset + attr.length as usize, mft_0.len());
                    if start <= end {
                        if let Ok(runs) = parse_runlist(&mft_0[start..end]) {
                            initial_runlist = runs;
                        }
                    }
                }
            }
        }

        let mut mft_runlist = initial_runlist.clone();
        
        if !attr_list_data.is_empty() {
            let mut extents = Vec::new();
            let mut cur = 0;
            while cur + 26 <= attr_list_data.len() {
                let t = u32::from_le_bytes(attr_list_data[cur..cur+4].try_into().unwrap());
                let l = u16::from_le_bytes(attr_list_data[cur+4..cur+6].try_into().unwrap()) as usize;
                if l == 0 { break; }
                
                if t == 0x80 { 
                    let lowest_vcn = u64::from_le_bytes(attr_list_data[cur+8..cur+16].try_into().unwrap());
                    let mft_ref = u64::from_le_bytes(attr_list_data[cur+16..cur+24].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                    extents.push((lowest_vcn, mft_ref));
                }
                cur += l;
            }

            extents.sort_by_key(|e| e.0);
            let mut temp_reader = Self { file: file.try_clone()?, cluster_size, record_size: 1024, mft_runlist: mft_runlist.clone() };

            for (lowest_vcn, mft_ref) in extents {
                if lowest_vcn == 0 || mft_ref == 0 { continue; } 
                if let Ok(child_data) = temp_reader.read_record(mft_ref) {
                    if let Ok(child_header) = parse_file_record_header(&child_data) {
                        if let Ok(child_attrs) = parse_attributes(&child_data, &child_header) {
                            for c_attr in child_attrs {
                                if c_attr.type_code == 0x80 && c_attr.non_resident_flag == 1 {
                                    if let Ok(nr) = parse_non_resident_header(&child_data[c_attr.offset..]) {
                                        let start = c_attr.offset + nr.run_array_offset as usize;
                                        let end = std::cmp::min(c_attr.offset + c_attr.length as usize, child_data.len());
                                        if start <= end {
                                            if let Ok(runs) = parse_runlist(&child_data[start..end]) {
                                                mft_runlist.extend(runs);
                                                temp_reader.mft_runlist = mft_runlist.clone(); 
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

        if mft_runlist.is_empty() { bail!("Failed to locate $MFT Runlist"); }
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
                apply_fixup(&mut buf)?;
                return Ok(buf);
            }
            current_vcn += run.length;
        }
        bail!("Inode {} OOB", index)
    }

    pub fn read_data_from_runlist(&mut self, runlist: &[DataRun], max_size: u64) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut total_read: u64 = 0;
        let cluster_size = self.cluster_size;

        for run in runlist {
            if total_read >= max_size { break; }
            let run_len = run.length.checked_mul(cluster_size).unwrap_or(u64::MAX);
            let size = std::cmp::min(run_len, max_size - total_read);
            
            if run.start_lcn != u64::MAX {
                if let Some(phys_off) = run.start_lcn.checked_mul(cluster_size) {
                    self.file.seek(SeekFrom::Start(phys_off))?;
                    // [BINGO] Sector Alignment 적용
                    let aligned_size = ((size + cluster_size - 1) / cluster_size) * cluster_size;
                    let mut chunk = vec![0u8; aligned_size as usize];
                    let _ = self.file.read_exact(&mut chunk); // 에러 무시하고 읽힌 만큼 쓴다
                    
                    chunk.truncate(size as usize);
                    buffer.extend(chunk);
                }
            } else {
                buffer.extend(vec![0u8; size as usize]); // Sparse 구역
            }
            total_read += size;
        }
        Ok(buffer)
    }

    pub fn extract_runlist_to_writer(&mut self, runlist: &[DataRun], max_size: u64, writer: &mut dyn Write) -> Result<u64> {
        let mut total_written: u64 = 0;
        let cluster_size = self.cluster_size;

        for run in runlist {
            if total_written >= max_size { break; }
            if run.start_lcn == u64::MAX { 
                let run_len = run.length.checked_mul(cluster_size).unwrap_or(u64::MAX);
                let size = std::cmp::min(run_len, max_size - total_written);
                total_written += size;
                continue;
            }

            let run_bytes = run.length.checked_mul(cluster_size).context("Runlist overflow")?;
            let mut run_remaining = std::cmp::min(run_bytes, max_size - total_written);
            let phys_off = run.start_lcn.checked_mul(cluster_size).context("LCN overflow")?;
            
            self.file.seek(SeekFrom::Start(phys_off))?;

            // [Ultimate Fix] 라이브 디스크 I/O 에러 87(Invalid Parameter) 방지를 위한 섹터 정렬 청크 읽기
            let clusters_to_read = (run_remaining + cluster_size - 1) / cluster_size;
            let aligned_read_size = clusters_to_read * cluster_size;
            const MAX_CHUNK: u64 = 4 * 1024 * 1024;
            let mut buffer = vec![0u8; MAX_CHUNK as usize];

            let mut aligned_remaining = aligned_read_size;
            let mut exact_remaining = run_remaining;

            while aligned_remaining > 0 {
                let current_aligned_read = std::cmp::min(MAX_CHUNK, aligned_remaining);
                let slice = &mut buffer[..current_aligned_read as usize];
                
                // 섹터 배수로 정확히 읽음. 실패 시 에러 전파하여 원인 파악
                self.file.read_exact(slice).context("Sector-aligned Block I/O Error")?;

                let current_exact_write = std::cmp::min(current_aligned_read, exact_remaining);
                writer.write_all(&slice[..current_exact_write as usize])?;

                aligned_remaining -= current_aligned_read;
                exact_remaining -= current_exact_write;
                total_written += current_exact_write;
            }
        }
        Ok(total_written)
    }
}