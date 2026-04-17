use anyhow::Result;
use chrono::{Utc, NaiveDateTime};
use evtx::EvtxParser;
use serde_json::Value;
use std::io::Cursor;
use models::event::{ForensicEvent, ExecutionEvent, NetworkEvent, SystemEvent};

pub fn parse_security_evtx_buffer(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let cursor = Cursor::new(data.to_vec());
    let mut parser = EvtxParser::from_read_seek(cursor)?;
    let mut events = Vec::new();

    for record in parser.records_json() {
        if let Ok(r) = record {
            let v: Option<Value> = serde_json::from_str(&r.data).ok();
            if let Some(json_val) = v {
                let event_id = json_val.pointer("/Event/System/EventID").and_then(|id| id.as_u64()).unwrap_or(0) as u32;
                
                // 1. 실행 이벤트 파싱 (EID 4688, Sysmon 1)
                if event_id == 4688 || event_id == 1 {
                    if let Some(event) = extract_execution_data(&json_val, filename) {
                        events.push(event);
                    }
                }
                
                // 2. 네트워크 연결 이벤트 파싱 (WFP EID 5156, Sysmon 3)
                else if event_id == 5156 || event_id == 3 {
                    if let Some(event) = extract_network_data(&json_val, filename, event_id) {
                        events.push(event);
                    }
                }

                // 3. [추가] 방어 회피 및 안티포렌식 이벤트 파싱 (EID 1102, 104, 5001, 1116)
                else if event_id == 1102 || event_id == 104 || event_id == 5001 || event_id == 1116 {
                    if let Some(event) = extract_evasion_data(&json_val, filename, event_id) {
                        events.push(event);
                    }
                }
            }
        }
    }
    Ok(events)
}

fn extract_execution_data(v: &Value, filename: &str) -> Option<ForensicEvent> {
    let timestamp_str = v.pointer("/Event/System/TimeCreated/SystemTime").and_then(|t| t.as_str())?;
    let timestamp = NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S%.fZ")
        .map(|dt| dt.and_utc()).unwrap_or_else(|_| Utc::now());

    let event_data = v.pointer("/Event/EventData")?;
    let process_name = extract_event_data_field(event_data, "NewProcessName")
        .or_else(|| extract_event_data_field(event_data, "Image"))
        .unwrap_or_else(|| "Unknown".to_string());
    
    let command_line = extract_event_data_field(event_data, "CommandLine").unwrap_or_default();
    let parent_process_name = extract_event_data_field(event_data, "ParentProcessName")
        .or_else(|| extract_event_data_field(event_data, "ParentImage"))
        .unwrap_or_default();

    Some(ForensicEvent::Execution(ExecutionEvent {
        timestamp,
        process_name: process_name.clone(),
        file_path: process_name,
        command_line,
        parent_process_name,
        run_count: 1,
        referenced_files: Vec::new(),
        source_artifact: filename.to_string(),
    }))
}

fn extract_network_data(v: &Value, filename: &str, event_id: u32) -> Option<ForensicEvent> {
    let timestamp_str = v.pointer("/Event/System/TimeCreated/SystemTime").and_then(|t| t.as_str())?;
    let timestamp = NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S%.fZ")
        .map(|dt| dt.and_utc()).unwrap_or_else(|_| Utc::now());

    let event_data = v.pointer("/Event/EventData")?;
    
    let process_name = if event_id == 5156 {
        extract_event_data_field(event_data, "Application").unwrap_or_else(|| "Unknown".to_string())
    } else {
        extract_event_data_field(event_data, "Image").unwrap_or_else(|| "Unknown".to_string())
    };

    let source_ip = extract_event_data_field(event_data, "SourceAddress")
        .or_else(|| extract_event_data_field(event_data, "SourceIp"))
        .unwrap_or_else(|| "0.0.0.0".to_string());
        
    let dest_ip = extract_event_data_field(event_data, "DestAddress")
        .or_else(|| extract_event_data_field(event_data, "DestinationIp"))
        .unwrap_or_else(|| "0.0.0.0".to_string());
        
    let source_port = extract_event_data_field(event_data, "SourcePort").unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0);
    let dest_port = extract_event_data_field(event_data, "DestPort")
        .or_else(|| extract_event_data_field(event_data, "DestinationPort"))
        .unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0);
        
    let protocol = extract_event_data_field(event_data, "Protocol").unwrap_or_else(|| "Unknown".to_string());

    if dest_ip == "127.0.0.1" || dest_ip == "::1" || dest_ip == "0.0.0.0" {
        return None;
    }

    Some(ForensicEvent::NetworkActivity(NetworkEvent {
        timestamp,
        process_name,
        source_ip,
        source_port,
        destination_ip: dest_ip,
        destination_port: dest_port,
        protocol,
        source_artifact: format!("{} (EID: {})", filename, event_id),
    }))
}

// [핵심 로직] 안티포렌식 및 방어 회피 탐지 추출
fn extract_evasion_data(v: &Value, filename: &str, event_id: u32) -> Option<ForensicEvent> {
    let timestamp_str = v.pointer("/Event/System/TimeCreated/SystemTime").and_then(|t| t.as_str())?;
    let timestamp = NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S%.fZ")
        .map(|dt| dt.and_utc()).unwrap_or_else(|_| Utc::now());

    let (activity_type, description) = match event_id {
        1102 | 104 => (
            "Audit Log Cleared [CRITICAL]".to_string(),
            "System or Security event log was cleared. Possible anti-forensics activity.".to_string()
        ),
        5001 => (
            "Windows Defender Disabled [CRITICAL]".to_string(),
            "Real-time protection was disabled.".to_string()
        ),
        1116 => (
            "Malware Detection Alert".to_string(),
            "Windows Defender detected malicious activity.".to_string()
        ),
        _ => ("Suspicious System Activity".to_string(), "Unknown evasion tactic.".to_string()),
    };

    Some(ForensicEvent::SystemActivity(SystemEvent {
        timestamp,
        activity_type,
        description,
        source_artifact: format!("{} (EID: {})", filename, event_id),
    }))
}

fn extract_event_data_field(event_data: &Value, field_name: &str) -> Option<String> {
    if let Value::Array(data_array) = event_data {
        for item in data_array {
            if item.get("Name").and_then(|n| n.as_str()) == Some(field_name) {
                return item.get("#text").and_then(|t| t.as_str()).map(|s| s.to_string());
            }
        }
    } else if let Value::Object(data_map) = event_data {
        if let Some(val) = data_map.get(field_name) {
             return val.as_str().map(|s| s.to_string());
        }
    }
    None
}