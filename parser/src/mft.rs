use models::mft::{
    FileRecordHeader, AttributeHeader, NonResidentAttributeHeader, 
    DataRun, IndexRootAttribute, IndexEntry, IndexRecordHeader
};
use models::FactError;
use binrw::BinReaderExt;
use std::io::{Cursor, Read};

pub fn parse_file_record_header(data: &[u8]) -> Result<FileRecordHeader, FactError> {
    let mut reader = Cursor::new(data);
    Ok(reader.read_le().map_err(|e| FactError::ParseError { artifact_name: "MFT Header".into(), details: e.to_string() })?)
}

pub fn parse_attributes(data: &[u8], header: &FileRecordHeader) -> Result<Vec<AttributeHeader>, FactError> {
    let mut attributes = Vec::new();
    let mut current_offset = header.attr_offset as usize;
    loop {
        if current_offset + 4 > data.len() { break; }
        let mut reader = Cursor::new(&data[current_offset..]);
        let attr_header: AttributeHeader = reader.read_le().map_err(|e| FactError::ParseError { artifact_name: "Attr Header".into(), details: e.to_string() })?;
        if attr_header.type_code == 0xFFFFFFFF || attr_header.length == 0 { break; }
        attributes.push(attr_header.clone());
        current_offset += attr_header.length as usize;
    }
    Ok(attributes)
}

pub fn parse_non_resident_header(data: &[u8]) -> Result<NonResidentAttributeHeader, FactError> {
    if data.len() < 16 { return Err(FactError::ParseError { artifact_name: "NR".into(), details: "Too short".into() }); }
    let mut reader = Cursor::new(&data[16..]);
    Ok(reader.read_le().map_err(|e| FactError::ParseError { artifact_name: "NR Header".into(), details: e.to_string() })?)
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
            let shift = (off_bytes * 8) - 1;
            if (offset >> shift) & 1 == 1 { offset |= !((1i64 << (off_bytes * 8)) - 1); }
            current_lcn += offset;
            cursor += off_bytes;
            runs.push(DataRun { start_lcn: current_lcn as u64, length });
        } else {
            runs.push(DataRun { start_lcn: u64::MAX, length });
        }
    }
    Ok(runs)
}

pub fn parse_index_root(data: &[u8]) -> Result<IndexRootAttribute, FactError> {
    let mut reader = Cursor::new(data);
    Ok(reader.read_le().map_err(|e| FactError::ParseError { artifact_name: "Idx Root".into(), details: e.to_string() })?)
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
                    entries.push(IndexEntry { file_reference: file_ref, length: length as u16, stream_length: stream_len as u16, flags, filename: String::from_utf16_lossy(&u16_vec) });
                }
            }
        }
        if (flags & 0x02) != 0 { break; }
        cursor += length;
    }
    Ok(entries)
}

pub fn parse_index_record(data: &[u8]) -> Result<Vec<IndexEntry>, FactError> {
    let mut fixup_data = data.to_vec();
    let mut reader = Cursor::new(&fixup_data);
    let head: IndexRecordHeader = reader.read_le().map_err(|e| FactError::ParseError { artifact_name: "Idx Rec".into(), details: e.to_string() })?;
    if head.signature != "INDX" { return Ok(Vec::new()); }
    apply_usa(&mut fixup_data, head.usa_offset, head.usa_count)?;
    let start = 24 + head.header.first_entry_offset as usize;
    let end = 24 + head.header.total_size_of_entries as usize;
    if start < end && end <= fixup_data.len() { return parse_index_entries(&fixup_data[start..end]); }
    Ok(Vec::new())
}

fn apply_usa(data: &mut [u8], usa_offset: u16, usa_count: u16) -> Result<(), FactError> {
    let start = usa_offset as usize;
    if start + (usa_count as usize * 2) > data.len() { return Ok(()); }
    let seq_num = [data[start], data[start+1]];
    for i in 0..(usa_count as usize - 1) {
        let sector_end = (i + 1) * 512 - 2;
        let fix_idx = start + 2 + (i * 2);
        if sector_end + 2 <= data.len() && data[sector_end] == seq_num[0] && data[sector_end+1] == seq_num[1] {
            data[sector_end] = data[fix_idx];
            data[sector_end+1] = data[fix_idx+1];
        }
    }
    Ok(())
}