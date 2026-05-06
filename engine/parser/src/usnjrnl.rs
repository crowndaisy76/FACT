use anyhow::Result;
use chrono::{DateTime, Utc};
use models::mft::StandardInformation;
use rayon::prelude::*; // 이중 병렬화 도입

#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub reason_flags: u32,
    pub file_attributes: u32,
}

pub fn parse_usnjrnl_stream(data: &[u8]) -> Result<Vec<UsnRecord>> {
    // 1단계: O(N) 순차 탐색으로 레코드의 시작 오프셋과 길이만 빠르게 수집 (Memory-mapped Pointer Array)
    let mut record_offsets = Vec::with_capacity(500_000); // 넉넉하게 사전 할당하여 재할당 방지
    let mut offset = 0;

    while offset + 60 <= data.len() {
        let record_len = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        
        if record_len == 0 {
            offset += 8; // 패딩(0)을 만나면 정렬 단위로 전진
            continue;
        }

        if offset + record_len > data.len() {
            break;
        }

        let major_version = u16::from_le_bytes([data[offset+4], data[offset+5]]);
        if major_version == 2 {
            record_offsets.push((offset, record_len));
        }
        
        offset += record_len;
    }

    // 2단계: 수집된 오프셋들을 Rayon으로 멀티코어 분산 처리 (병목이었던 UTF-16 파싱 및 객체 생성 병렬화)
    let records: Vec<UsnRecord> = record_offsets.into_par_iter().filter_map(|(start, len)| {
        let record_data = &data[start..start+len];
        
        let filetime = u64::from_le_bytes(record_data[32..40].try_into().unwrap());
        let timestamp = StandardInformation::to_datetime(filetime);
        
        let reason_flags = u32::from_le_bytes(record_data[40..44].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(record_data[52..56].try_into().unwrap());
        
        let name_len = u16::from_le_bytes([record_data[56], record_data[57]]) as usize;
        let name_off = u16::from_le_bytes([record_data[58], record_data[59]]) as usize;

        let file_name = if name_off + name_len <= len {
            let name_bytes = &record_data[name_off..name_off+name_len];
            
            // 3단계: [최적화] 대부분의 시스템 파일명은 영문/숫자이므로 빠른 ASCII 파싱 경로(Fast-Path) 적용
            let mut is_ascii = true;
            let mut ascii_str = String::with_capacity(name_len / 2);
            
            for chunk in name_bytes.chunks_exact(2) {
                // 상위 바이트가 0이 아니거나, 제어 문자인 경우 다국어(UTF-16)로 간주
                if chunk[1] != 0 || chunk[0] < 32 || chunk[0] > 126 {
                    is_ascii = false;
                    break;
                }
                ascii_str.push(chunk[0] as char);
            }

            if is_ascii {
                ascii_str // 메모리 복사 및 변환 오버헤드 없이 즉시 반환
            } else {
                // 한글 등 다국어가 포함된 경우에만 무거운 정규 UTF-16 파싱 경로 사용
                let u16_name: Vec<u16> = name_bytes.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&u16_name)
            }
        } else {
            "Unknown".to_string()
        };

        if file_name != "Unknown" {
            Some(UsnRecord { timestamp, file_name, reason_flags, file_attributes })
        } else {
            None
        }
    }).collect();

    Ok(records)
}