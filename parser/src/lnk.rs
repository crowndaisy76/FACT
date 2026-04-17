use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, ExecutionEvent};
use std::collections::HashSet;

pub fn parse_lnk_carve(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    let mut extracted = HashSet::new();

    // ASCII 및 UTF-16 모두에서 문자열 추출
    let ascii_str = String::from_utf8_lossy(data).into_owned();
    let u16_data: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let utf16_str: String = std::char::decode_utf16(u16_data).map(|r| r.unwrap_or('\u{FFFD}')).collect();

    for content in &[ascii_str, utf16_str] {
        let mut current_str = String::new();
        for ch in content.chars() {
            if ch.is_ascii_graphic() || ch == ' ' {
                current_str.push(ch);
            } else {
                let lower = current_str.to_lowercase();
                if current_str.len() > 5 && (lower.contains(":\\") || lower.contains(".exe") || lower.contains("powershell")) {
                    extracted.insert(current_str.trim().to_string());
                }
                current_str.clear();
            }
        }
    }

    for path in extracted {
        events.push(ForensicEvent::Execution(ExecutionEvent {
            timestamp: Utc::now(),
            process_name: filename.split('\\').last().unwrap_or(filename).to_string(),
            file_path: filename.to_string(),
            command_line: path,
            parent_process_name: "explorer.exe".to_string(),
            run_count: 1,
            referenced_files: vec![],
            source_artifact: format!("LNK: {}", filename),
        }));
    }
    Ok(events)
}