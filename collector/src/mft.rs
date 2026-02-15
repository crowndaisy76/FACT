use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use anyhow::{Result, Context, bail};
use models::mft::{DataRun, IndexEntry};
use parser::ntfs::parse_boot_sector;
use parser::mft::{
    parse_file_record_header, parse_attributes, parse_non_resident_header, 
    parse_runlist, parse_index_root, parse_index_entries, parse_index_record
};

/// $MFT 파일 시스템을 전담하여 읽는 리더기
pub struct MftReader {
    file: File,                 
    cluster_size: u64,          
    record_size: u64,           
    mft_runlist: Vec<DataRun>,  
}

impl MftReader {
    pub fn bootstrap(mut file: File) -> Result<Self> {
        let mut vbr_buffer = [0u8; 512];
        file.seek(SeekFrom::Start(0)).context("Failed to seek to VBR")?;
        file.read_exact(&mut vbr_buffer).context("Failed to read VBR")?;
        
        let vbr = parse_boot_sector(&vbr_buffer).context("Failed to parse VBR")?;
        let cluster_size = vbr.cluster_size();
        let mft_offset = vbr.mft_offset();
        let record_size = 1024;

        file.seek(SeekFrom::Start(mft_offset)).context("Failed to seek to $MFT")?;
        let mut mft_0_buffer = vec![0u8; record_size as usize];
        file.read_exact(&mut mft_0_buffer).context("Failed to read MFT Entry 0")?;

        let header = parse_file_record_header(&mft_0_buffer)?;
        let attributes = parse_attributes(&mft_0_buffer, &header)?;
        
        let mut mft_runlist = Vec::new();
        let mut current_offset = header.attr_offset as usize;

        for attr in attributes {
            if attr.type_code == 0x80 && attr.non_resident_flag == 1 {
                let attr_data = &mft_0_buffer[current_offset..current_offset + attr.length as usize];
                let nr_header = parse_non_resident_header(attr_data)?;
                let runlist_data = &attr_data[nr_header.run_array_offset as usize..];
                mft_runlist = parse_runlist(runlist_data)?;
                break; 
            }
            current_offset += attr.length as usize;
        }

        if mft_runlist.is_empty() {
            bail!("Failed to extract $MFT runlist from Entry 0.");
        }

        Ok(Self {
            file,
            cluster_size,
            record_size,
            mft_runlist,
        })
    }

    pub fn read_record(&mut self, index: u64) -> Result<Vec<u8>> {
        let virtual_offset = index * self.record_size;
        let target_vcn = virtual_offset / self.cluster_size;
        let offset_in_cluster = virtual_offset % self.cluster_size;

        let mut current_vcn: u64 = 0;
        let mut target_lcn: Option<u64> = None;

        for run in &self.mft_runlist {
            let run_length = run.length;
            if target_vcn >= current_vcn && target_vcn < current_vcn + run_length {
                let offset_in_run = target_vcn - current_vcn;
                target_lcn = Some(run.start_lcn + offset_in_run);
                break;
            }
            current_vcn += run_length;
        }

        match target_lcn {
            Some(lcn) => {
                let physical_offset = (lcn * self.cluster_size) + offset_in_cluster;
                self.file.seek(SeekFrom::Start(physical_offset))?;
                let mut buffer = vec![0u8; self.record_size as usize];
                self.file.read_exact(&mut buffer)?;
                Ok(buffer)
            },
            None => bail!("Record index {} out of bounds", index),
        }
    }

    pub fn read_data_from_runlist(&mut self, runlist: &[DataRun], max_size: u64) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut bytes_read: u64 = 0;

        for run in runlist {
            if bytes_read >= max_size { break; }
            let physical_offset = run.start_lcn * self.cluster_size;
            let byte_length = run.length * self.cluster_size;
            let remaining = max_size - bytes_read;
            let read_size = std::cmp::min(byte_length, remaining);

            self.file.seek(SeekFrom::Start(physical_offset))?;
            
            let current_len = buffer.len();
            buffer.resize(current_len + read_size as usize, 0);
            self.file.read_exact(&mut buffer[current_len..])?;

            bytes_read += read_size;
        }
        Ok(buffer)
    }

    pub fn list_directory(&mut self, dir_index: u64) -> Result<Vec<IndexEntry>> {
        let record_data = self.read_record(dir_index)
            .context(format!("Failed to read directory record {}", dir_index))?;

        let header = parse_file_record_header(&record_data)?;
        let attributes = parse_attributes(&record_data, &header)?;

        let mut entries = Vec::new();
        let mut current_offset = header.attr_offset as usize;

        for attr in attributes {
            if attr.type_code == 0x90 {
                let content_start = current_offset + 24; 
                let content_end = current_offset + attr.length as usize;
                if content_end <= record_data.len() {
                    let index_root_data = &record_data[content_start..content_end];
                    if let Ok(index_root) = parse_index_root(index_root_data) {
                        let entries_start = 16 + index_root.header.first_entry_offset as usize;
                        if entries_start < index_root_data.len() {
                            if let Ok(parsed) = parse_index_entries(&index_root_data[entries_start..]) {
                                entries.extend(parsed);
                            }
                        }
                    }
                }
            } else if attr.type_code == 0xA0 {
                if attr.non_resident_flag == 1 {
                    let attr_data = &record_data[current_offset..current_offset + attr.length as usize];
                    let nr_header = parse_non_resident_header(attr_data)?;
                    let runlist_offset = nr_header.run_array_offset as usize;
                    let runlist = parse_runlist(&attr_data[runlist_offset..])?;

                    // 디렉토리 크기 제한 (20MB)
                    let index_data = self.read_data_from_runlist(&runlist, 20 * 1024 * 1024)?;
                    let chunks = index_data.chunks_exact(4096);
                    for chunk in chunks {
                        if let Ok(parsed) = parse_index_record(chunk) {
                            entries.extend(parsed);
                        }
                    }
                }
            }
            current_offset += attr.length as usize;
        }
        Ok(entries)
    }

    /// [Step 17 추가] 경로 기반 Inode(MFT Number) 탐색
    /// 예: "Windows\System32\config\SAM" -> 12345
    pub fn get_inode_by_path(&mut self, path: &str) -> Result<u64> {
        let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
        let mut current_inode = 5; // Root Directory

        for part in parts {
            let entries = self.list_directory(current_inode)?;
            let mut found = false;

            for entry in entries {
                // 대소문자 무시 비교 (NTFS 표준)
                if entry.filename.eq_ignore_ascii_case(part) {
                    current_inode = entry.file_reference;
                    found = true;
                    break;
                }
            }

            if !found {
                bail!("Path component not found: {}", part);
            }
        }

        Ok(current_inode)
    }
}