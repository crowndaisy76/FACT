use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, PersistenceEvent};

pub fn parse_task_xml(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    if data.is_empty() { return Ok(Vec::new()); }

    // 단순 무식하게 XML 문자열 추출 (BOM 처리 포함)
    let xml_str = if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        let u16_data: Vec<u16> = data[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_data)
    } else {
        String::from_utf8_lossy(data).into_owned()
    };

    let mut events = Vec::new();
    
    let command = extract_xml_tag(&xml_str, "Command").unwrap_or_default();
    let arguments = extract_xml_tag(&xml_str, "Arguments").unwrap_or_default();

    if !command.is_empty() {
        let target_path = if arguments.is_empty() {
            command.clone()
        } else {
            format!("{} {}", command, arguments)
        };

        events.push(ForensicEvent::Persistence(PersistenceEvent {
            timestamp: Utc::now(),
            persistence_type: "Scheduled Task (XML)".to_string(),
            target_name: filename.split('\\').last().unwrap_or(filename).to_string(),
            target_path,
            payload: String::new(),
            source_artifact: format!("Task: {}", filename),
        }));
    }

    Ok(events)
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);
    
    let start_idx = xml.find(&start_tag)?;
    let content_start = start_idx + start_tag.len();
    let end_idx = xml[content_start..].find(&end_tag)?;
    
    Some(xml[content_start..content_start + end_idx].trim().to_string())
}