use anyhow::Result;
use chrono::{DateTime, Utc};
use models::mft::StandardInformation;

#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub reason_flags: u32,
    pub file_attributes: u32,
}

pub fn parse_usnjrnl_stream(data: &[u8]) -> Result<Vec<UsnRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset + 60 <= data.len() {
        let record_len = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
        
        // 패딩(0)을 만나면 8바이트 정렬 단위로 전진
        if record_len == 0 {
            offset += 8;
            continue;
        }

        if offset + record_len > data.len() {
            break;
        }

        let major_version = u16::from_le_bytes([data[offset+4], data[offset+5]]);
        
        // USN V2 레코드 파싱
        if major_version == 2 {
            let filetime = u64::from_le_bytes(data[offset+32..offset+40].try_into().unwrap());
            let timestamp = StandardInformation::to_datetime(filetime);
            
            let reason_flags = u32::from_le_bytes(data[offset+40..offset+44].try_into().unwrap());
            let file_attributes = u32::from_le_bytes(data[offset+52..offset+56].try_into().unwrap());
            
            let name_len = u16::from_le_bytes([data[offset+56], data[offset+57]]) as usize;
            let name_off = u16::from_le_bytes([data[offset+58], data[offset+59]]) as usize;

            let name_start = offset + name_off;
            let file_name = if name_start + name_len <= offset + record_len {
                let name_bytes = &data[name_start..name_start+name_len];
                let u16_name: Vec<u16> = name_bytes.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&u16_name)
            } else {
                "Unknown".to_string()
            };

            if file_name != "Unknown" {
                records.push(UsnRecord {
                    timestamp,
                    file_name,
                    reason_flags,
                    file_attributes,
                });
            }
        }
        
        offset += record_len;
    }

    Ok(records)
}