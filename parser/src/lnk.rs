use models::event::{ForensicEvent, ExecutionEvent};
use std::io::Cursor;
use binrw::BinReaderExt;
use chrono::{Utc, TimeZone};
use anyhow::Result;

pub fn parse_lnk_carve(data: &[u8], source_name: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    let mut cursor = Cursor::new(data);
    
    if data.len() < 0x4C {
        return Ok(events);
    }
    
    let header_size: u32 = cursor.read_le().unwrap_or(0);
    if header_size != 0x4C {
        return Ok(events);
    }

    cursor.set_position(0x1C);
    let creation_time_filetime: u64 = cursor.read_le().unwrap_or(0);
    
    let secs = (creation_time_filetime / 10_000_000).saturating_sub(11_644_473_600);
    let timestamp = Utc.timestamp_opt(secs as i64, 0).single().unwrap_or_else(Utc::now);

    let filename = source_name.to_lowercase();
    let target_path = format!("Target of {}", filename);

    events.push(ForensicEvent::Execution(ExecutionEvent {
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
    }));

    Ok(events)
}