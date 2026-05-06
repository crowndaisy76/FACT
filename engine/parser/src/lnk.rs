use models::event::{ForensicEvent, ExecutionEvent};
use chrono::{Utc, TimeZone};
use anyhow::Result;

pub fn parse_lnk_carve(data: &[u8], source_name: &str) -> Result<Vec<ForensicEvent>> {
    // 최소 LNK 헤더 사이즈 검증
    if data.len() < 0x4C {
        return Ok(Vec::new());
    }
    
    // binrw 라이브러리 제거 -> 네이티브 Zero-Copy 바이트 배열 직접 접근
    let header_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if header_size != 0x4C {
        return Ok(Vec::new());
    }

    // 0x1C 위치의 FileTime 추출 (커서 이동 없이 직접 접근)
    let creation_time_filetime = u64::from_le_bytes(data[0x1C..0x24].try_into().unwrap());
    
    let secs = (creation_time_filetime / 10_000_000).saturating_sub(11_644_473_600);
    let timestamp = Utc.timestamp_opt(secs as i64, 0).single().unwrap_or_else(Utc::now);

    let filename = source_name.to_lowercase();
    let target_path = format!("Target of {}", filename);

    Ok(vec![ForensicEvent::Execution(ExecutionEvent {
        timestamp,
        process_name: target_path.clone(),
        process_id: 0,          
        parent_process_id: 0,   
        file_path: target_path,
        command_line: String::new(),
        parent_process_name: "explorer.exe".to_string(), 
        run_count: 1,
        referenced_files: Vec::new(),
        source_artifact: format!("LNK ({})", source_name),
    })])
}