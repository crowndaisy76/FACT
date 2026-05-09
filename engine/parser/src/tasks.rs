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
    
    // 기본 실행 명령 및 인자 파싱
    let command = extract_xml_tag(&xml_str, "Command").unwrap_or_default();
    let arguments = extract_xml_tag(&xml_str, "Arguments").unwrap_or_default();

    // 1. 트리거(Trigger) 시점 문맥 추출
    let mut triggers = Vec::new();
    if xml_str.contains("<LogonTrigger>") { triggers.push("Logon"); }
    if xml_str.contains("<BootTrigger>") { triggers.push("Boot"); }
    if xml_str.contains("<TimeTrigger>") { triggers.push("Time"); }
    if xml_str.contains("<EventTrigger>") { triggers.push("Event"); }
    if xml_str.contains("<RegistrationTrigger>") { triggers.push("Registration"); }
    
    let trigger_str = if triggers.is_empty() {
        "Unknown Trigger".to_string()
    } else {
        triggers.join(", ")
    };

    // 2. 실행 권한(Principal) 문맥 추출
    let user_id = extract_xml_tag(&xml_str, "UserId").unwrap_or_else(|| "Unknown User".to_string());
    let run_level = extract_xml_tag(&xml_str, "RunLevel").unwrap_or_else(|| "Default Level".to_string());

    if !command.is_empty() {
        let target_path = if arguments.is_empty() {
            command.clone()
        } else {
            format!("{} {}", command, arguments)
        };

        // 추출한 권한 문맥을 페이로드 필드에 융합
        let payload_context = format!("[Principal: {} | RunLevel: {}]", user_id, run_level);

        events.push(ForensicEvent::Persistence(PersistenceEvent {
            timestamp: Utc::now(),
            // 분석관이 타임라인에서 즉시 발동 시점을 인지할 수 있도록 타입명에 트리거 명시
            persistence_type: format!("Scheduled Task ({})", trigger_str),
            target_name: filename.split('\\').last().unwrap_or(filename).to_string(),
            target_path,
            payload: payload_context,
            source_artifact: format!("Task: {}", filename),
        }));
    }

    Ok(events)
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);
    
    if let Some(start_idx) = xml.find(&start_tag) {
        let content_start = start_idx + start_tag.len();
        if let Some(end_idx) = xml[content_start..].find(&end_tag) {
            return Some(xml[content_start..content_start + end_idx].trim().to_string());
        }
    }
    None
}