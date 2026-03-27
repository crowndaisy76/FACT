use anyhow::Result;
use chrono::{DateTime, Utc};
use models::mft::StandardInformation;

#[derive(Debug, Clone)]
pub struct EvtxRecord {
    pub record_id: u64,
    pub timestamp: DateTime<Utc>,
    // 향후 BinXML 디코딩을 위한 원본 페이로드
    pub raw_data: Vec<u8>, 
}

/// EVTX 바이너리 스트림에서 '**\x00\x00' 시그니처를 스캔하여 레코드를 카빙한다.
pub fn parse_evtx_stream(data: &[u8]) -> Result<Vec<EvtxRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;

    // EVTX 파일 헤더(4096바이트)를 건너뛰고 청크(Chunk) 영역부터 스캔 시작
    if data.len() > 4096 {
        offset = 4096;
    }

    while offset + 24 <= data.len() {
        // [핵심] EVTX Record Magic Number: "**\x00\x00" (0x2A 0x2A 0x00 0x00)
        if data[offset] == 0x2A && data[offset+1] == 0x2A && data[offset+2] == 0x00 && data[offset+3] == 0x00 {
            
            // 레코드 전체 크기 (4 bytes)
            let size = u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap()) as usize;
            if size < 24 || offset + size > data.len() {
                offset += 1;
                continue;
            }

            // 레코드 고유 ID (8 bytes)
            let record_id = u64::from_le_bytes(data[offset+8..offset+16].try_into().unwrap());
            
            // 레코드 생성 시간 (8 bytes, FILETIME 포맷)
            let filetime = u64::from_le_bytes(data[offset+16..offset+24].try_into().unwrap());
            let timestamp = StandardInformation::to_datetime(filetime);

            // 실제 BinXML 페이로드 추출
            let raw_data = data[offset+24..offset+size].to_vec();

            records.push(EvtxRecord {
                record_id,
                timestamp,
                raw_data,
            });

            // 현재 레코드 크기만큼 점프
            offset += size;
        } else {
            // 시그니처가 일치하지 않으면 1바이트씩 전진하며 카빙 (Carving)
            offset += 1;
        }
    }
    
    Ok(records)
}