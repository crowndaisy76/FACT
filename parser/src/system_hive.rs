use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, PersistenceEvent};
use std::collections::HashSet;

pub fn parse_system_services(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    let mut extracted = HashSet::new();

    let u16_data: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let utf16_str: String = std::char::decode_utf16(u16_data).map(|r| r.unwrap_or('\u{FFFD}')).collect();

    let mut current_str = String::new();
    for ch in utf16_str.chars() {
        if ch.is_ascii_graphic() || ch == ' ' || ch == '%' {
            current_str.push(ch);
        } else {
            let lower = current_str.to_lowercase();
            // 기존 서비스 ImagePath 변조 추적
            if current_str.len() > 8 && (lower.contains(":\\") || lower.contains("%systemroot%")) && (lower.contains(".exe") || lower.contains(".sys") || lower.contains(".dll")) {
                extracted.insert(current_str.trim().to_string());
            }
            current_str.clear();
        }
    }

    for path in extracted {
        events.push(ForensicEvent::Persistence(PersistenceEvent {
            timestamp: Utc::now(),
            persistence_type: "Service ImagePath (SYSTEM)".to_string(),
            target_name: "Service".to_string(),
            target_path: path,
            source_artifact: format!("Registry: {}", filename),
        }));
    }
    Ok(events)
}