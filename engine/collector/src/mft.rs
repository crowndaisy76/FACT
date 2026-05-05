use std::fs::File;
use std::io::Write;
use std::os::windows::fs::FileExt;
use anyhow::{Result, Context, bail};
use models::mft::DataRun;
use parser::mft::{
    parse_file_record_header, parse_attributes, parse_non_resident_header, 
    parse_runlist, parse_boot_sector_manual
};

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> Result<()> {
    let mut total_read = 0;
    while total_read < buf.len() {
        let n = file.seek_read(&mut buf[total_read..], offset + total_read as u64)?;
        if n == 0 { break; }
        total_read += n;
    }
    if total_read < buf.len() {
        bail!("failed to fill whole buffer at offset {}", offset);
    }
    Ok(())
}

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

#[derive(Debug, Clone)]
pub struct OptimizedDataRun {
    pub vcn_start: u64,
    pub lcn_start: u64,
    pub length: u64,
}

pub struct MftReader {
    file: File,                 
    cluster_size: u64,          
    record_size: u64,           
    optimized_runlist: Vec<OptimizedDataRun>,
    mft_runlist: Vec<DataRun>,
}

impl MftReader {
    pub fn clone_reader(&self) -> Result<Self> {
        Ok(Self {
            file: self.file.try_clone().context("Failed to clone file handle")?,
            cluster_size: self.cluster_size,
            record_size: self.record_size,
            optimized_runlist: self.optimized_runlist.clone(),
            mft_runlist: self.mft_runlist.clone(),
        })
    }

    pub fn bootstrap(file: File) -> Result<Self> {
        let mut vbr = [0u8; 512];
        read_exact_at(&file, &mut vbr, 0)?;
        let boot = parse_boot_sector_manual(&vbr)?;
        let cluster_size = boot.cluster_size();
        let mft_offset = boot.mft_offset();
        
        let mut mft_0 = vec![0u8; 1024];
        read_exact_at(&file, &mut mft_0, mft_offset)?;
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
            
            let mut current_mft_runs = mft_runlist.clone();
            for (_vcn, mft_ref) in extents {
                if mft_ref == 0 { continue; } 
                
                let v_off = mft_ref * 1024;
                let target_vcn = v_off / cluster_size;
                let mut current_vcn = 0;
                let mut phys_off = 0;
                let mut found = false;
                
                for run in &current_mft_runs {
                    if target_vcn >= current_vcn && target_vcn < current_vcn + run.length {
                        let lcn = run.start_lcn + (target_vcn - current_vcn);
                        phys_off = (lcn * cluster_size) + (v_off % cluster_size);
                        found = true;
                        break;
                    }
                    current_vcn += run.length;
                }
                
                if found {
                    let mut child_data = vec![0u8; 1024];
                    if read_exact_at(&file, &mut child_data, phys_off).is_ok() {
                        let _ = apply_fixup(&mut child_data);
                        if let Ok(child_header) = parse_file_record_header(&child_data) {
                            if let Ok(child_attrs) = parse_attributes(&child_data, &child_header) {
                                for c_attr in child_attrs {
                                    if c_attr.type_code == 0x80 && c_attr.non_resident_flag == 1 {
                                        if let Ok(nr) = parse_non_resident_header(&child_data[c_attr.offset..]) {
                                            let start = c_attr.offset + nr.run_array_offset as usize;
                                            let end = std::cmp::min(c_attr.offset + c_attr.length as usize, child_data.len());
                                            if start <= end {
                                                if let Ok(runs) = parse_runlist(&child_data[start..end]) {
                                                    mft_runlist.extend(runs.clone());
                                                    current_mft_runs.extend(runs);
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
        }
        if mft_runlist.is_empty() { bail!("Failed to locate $MFT Runlist"); }

        let mut vcn_acc = 0;
        let optimized_runlist = mft_runlist.iter().map(|r| {
            let res = OptimizedDataRun { vcn_start: vcn_acc, lcn_start: r.start_lcn, length: r.length };
            vcn_acc += r.length;
            res
        }).collect();

        Ok(Self { file, cluster_size, record_size: 1024, mft_runlist, optimized_runlist })
    }

    pub fn read_record(&mut self, index: u64) -> Result<Vec<u8>> {
        let v_off = index.checked_mul(self.record_size).context("MFT Overflow")?;
        let target_vcn = v_off / self.cluster_size;
        
        let idx = self.optimized_runlist.partition_point(|r| r.vcn_start <= target_vcn);
        if idx == 0 { bail!("Inode {} OOB", index); }
        let run = &self.optimized_runlist[idx - 1];
        let phys_off = (run.lcn_start + (target_vcn - run.vcn_start)) * self.cluster_size + (v_off % self.cluster_size);
        
        let mut buf = vec![0u8; 1024];
        read_exact_at(&self.file, &mut buf, phys_off)?;
        apply_fixup(&mut buf)?;
        Ok(buf)
    }

    pub fn read_data_from_runlist(&mut self, runlist: &[DataRun], max_size: u64) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut total_read = 0;
        for run in runlist {
            if total_read >= max_size { break; }
            let run_len = run.length * self.cluster_size;
            let size = std::cmp::min(run_len, max_size - total_read);
            if run.start_lcn != u64::MAX {
                // 섹터(512바이트) 단위로 정렬된 버퍼 사용
                let aligned_size = ((size + 511) / 512) * 512;
                let mut chunk = vec![0u8; aligned_size as usize];
                read_exact_at(&self.file, &mut chunk, run.start_lcn * self.cluster_size)?;
                chunk.truncate(size as usize);
                buffer.extend(chunk);
            } else {
                buffer.resize(buffer.len() + size as usize, 0);
            }
            total_read += size;
        }
        Ok(buffer)
    }

    pub fn extract_runlist_to_writer(&mut self, runlist: &[DataRun], max_size: u64, writer: &mut dyn Write) -> Result<u64> {
        let mut total_written = 0;
        for run in runlist {
            if total_written >= max_size { break; }
            if run.start_lcn == u64::MAX { 
                total_written += std::cmp::min(run.length * self.cluster_size, max_size - total_written);
                continue; 
            }
            let mut remaining = std::cmp::min(run.length * self.cluster_size, max_size - total_written);
            let mut offset = run.start_lcn * self.cluster_size;
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, 1024 * 1024);
                // 섹터(512바이트) 단위로 정렬된 버퍼 사용
                let aligned_to_read = ((to_read + 511) / 512) * 512;
                let mut buf = vec![0u8; aligned_to_read as usize];
                read_exact_at(&self.file, &mut buf, offset)?;
                writer.write_all(&buf[..to_read as usize])?;
                remaining -= to_read;
                offset += to_read;
                total_written += to_read as u64;
            }
        }
        Ok(total_written)
    }
}