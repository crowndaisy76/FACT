use models::mft::{
    FileRecordHeader, AttributeHeader, NonResidentAttributeHeader, 
    DataRun, IndexEntry
};
use models::FactError;

pub fn parse_file_record_header(data: &[u8]) -> Result<FileRecordHeader, FactError> {
    if data.len() < 48 { 
        return Err(FactError::ParseError { artifact_name: "MFT".into(), details: "Data too small".into() }); 
    }
    Ok(FileRecordHeader {
        signature: String::from_utf8_lossy(&data[0..4]).to_string(),
        usa_offset: u16::from_le_bytes([data[4], data[5]]),
        usa_count: u16::from_le_bytes([data[6], data[7]]),
        lsn: u64::from_le_bytes(data[8..16].try_into().unwrap()),
        sequence_number: u16::from_le_bytes([data[16], data[17]]),
        link_count: u16::from_le_bytes([data[18], data[19]]),
        attr_offset: u16::from_le_bytes([data[20], data[21]]),
        flags: u16::from_le_bytes([data[22], data[23]]),
        bytes_in_use: u32::from_le_bytes(data[24..28].try_into().unwrap()),
        bytes_allocated: u32::from_le_bytes(data[28..32].try_into().unwrap()),
        base_file_record: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        next_attr_id: u16::from_le_bytes([data[40], data[41]]),
    })
}

pub fn parse_attributes(data: &[u8], header: &FileRecordHeader) -> Result<Vec<AttributeHeader>, FactError> {
    let mut attributes = Vec::new();
    let mut current_offset = header.attr_offset as usize;

    while current_offset + 16 <= data.len() {
        let type_code = u32::from_le_bytes(data[current_offset..current_offset+4].try_into().unwrap());
        if type_code == 0xFFFFFFFF || type_code == 0 { break; }

        let length = u32::from_le_bytes(data[current_offset+4..current_offset+8].try_into().unwrap()) as usize;
        if length < 16 || current_offset + length > data.len() { break; }

        attributes.push(AttributeHeader {
            type_code,
            length: length as u32,
            non_resident_flag: data[current_offset+8],
            name_length: data[current_offset+9],
            name_offset: u16::from_le_bytes([data[current_offset+10], data[current_offset+11]]),
            flags: u16::from_le_bytes([data[current_offset+12], data[current_offset+13]]),
            attribute_id: u16::from_le_bytes([data[current_offset+14], data[current_offset+15]]),
            offset: current_offset,
        });
        current_offset += length;
    }
    Ok(attributes)
}

pub fn parse_non_resident_header(data: &[u8]) -> Result<NonResidentAttributeHeader, FactError> {
    if data.len() < 64 { return Err(FactError::ParseError { artifact_name: "NR".into(), details: "Data too short".into() }); }
    Ok(NonResidentAttributeHeader {
        starting_vcn: u64::from_le_bytes(data[16..24].try_into().unwrap()),
        last_vcn: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        run_array_offset: u16::from_le_bytes([data[32], data[33]]),
        compression_unit: u16::from_le_bytes([data[34], data[35]]),
        allocated_size: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        real_size: u64::from_le_bytes(data[48..56].try_into().unwrap()),
        initialized_size: u64::from_le_bytes(data[56..64].try_into().unwrap()),
    })
}

pub fn parse_runlist(data: &[u8]) -> Result<Vec<DataRun>, FactError> {
    let mut runs = Vec::new();
    let mut cursor = 0;
    let mut current_lcn: i64 = 0;
    
    while cursor < data.len() {
        let header = data[cursor];
        cursor += 1;
        if header == 0 { break; }
        
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        if cursor + len_bytes + off_bytes > data.len() || len_bytes > 8 || off_bytes > 8 { break; }
        
        let mut length: u64 = 0;
        for i in 0..len_bytes { length |= (data[cursor+i] as u64) << (i * 8); }
        cursor += len_bytes;
        
        if off_bytes > 0 {
            let mut offset: i64 = 0;
            for i in 0..off_bytes { offset |= (data[cursor+i] as i64) << (i * 8); }
            
            // [Ultimate Fix] 런리스트 음수 점프 버그 완벽 패치 (Sign Extension)
            let shift_bits = 64 - (off_bytes * 8);
            if shift_bits < 64 {
                offset = (offset << shift_bits) >> shift_bits;
            }
            
            current_lcn += offset;
            cursor += off_bytes;
            runs.push(DataRun { start_lcn: current_lcn as u64, length });
        } else {
            runs.push(DataRun { start_lcn: u64::MAX, length });
        }
    }
    Ok(runs)
}

pub fn parse_index_entries(data: &[u8]) -> Result<Vec<IndexEntry>, FactError> {
    let mut entries = Vec::new();
    let mut cursor = 0;
    loop {
        if cursor + 16 > data.len() { break; }
        let length = u16::from_le_bytes([data[cursor+8], data[cursor+9]]) as usize;
        if length < 16 || cursor + length > data.len() { break; }
        
        let flags = data[cursor+12];
        let stream_len = u16::from_le_bytes([data[cursor+10], data[cursor+11]]) as usize;
        
        if (flags & 0x02) == 0 && stream_len > 0 {
            let fn_base = cursor + 16;
            if fn_base + 66 <= data.len() {
                let name_len = data[fn_base + 64] as usize;
                let name_start = fn_base + 66;
                let name_end = name_start + (name_len * 2);
                
                if name_end <= data.len() {
                    let file_ref = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;
                    let u16_vec: Vec<u16> = data[name_start..name_end].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    
                    let file_attrs = u32::from_le_bytes([data[fn_base+56], data[fn_base+57], data[fn_base+58], data[fn_base+59]]);
                    let is_directory = (file_attrs & 0x00000010) != 0;

                    entries.push(IndexEntry { 
                        file_reference: file_ref, length: length as u16, 
                        stream_length: stream_len as u16, flags, 
                        filename: String::from_utf16_lossy(&u16_vec),
                        is_directory 
                    });
                }
            }
        }
        if (flags & 0x02) != 0 { break; }
        cursor += length;
    }
    Ok(entries)
}

pub fn parse_index_record(data: &[u8]) -> Result<Vec<IndexEntry>, FactError> {
    if data.len() < 24 { return Ok(Vec::new()); }
    let signature = &data[0..4];
    if signature != b"INDX" { return Ok(Vec::new()); }
    
    let first_entry_offset = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
    let start = 24 + first_entry_offset;
    
    if start < data.len() { 
        return parse_index_entries(&data[start..]); 
    }
    Ok(Vec::new())
}

pub struct BootSector { pub bytes_per_sector: u16, pub sectors_per_cluster: u8, pub mft_lcn: u64 }
impl BootSector {
    pub fn cluster_size(&self) -> u64 { (self.bytes_per_sector as u64) * (self.sectors_per_cluster as u64) }
    pub fn mft_offset(&self) -> u64 { self.mft_lcn * self.cluster_size() }
}
pub fn parse_boot_sector_manual(data: &[u8]) -> Result<BootSector, FactError> {
    if data.len() < 512 { return Err(FactError::ParseError { artifact_name: "VBR".into(), details: "Too small".into() }); }
    Ok(BootSector { 
        bytes_per_sector: u16::from_le_bytes([data[11], data[12]]), 
        sectors_per_cluster: data[13], 
        mft_lcn: u64::from_le_bytes(data[48..56].try_into().unwrap()) 
    })
}