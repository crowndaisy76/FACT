use evtx::{EvtxParser, ParserSettings};
use models::event::{ForensicEvent, ExecutionEvent, NetworkEvent, SystemEvent};
use std::io::Cursor;
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};
use anyhow::{Result, anyhow};

pub fn parse_security_evtx_buffer(buffer: &[u8], source_name: &str) -> Result<Vec<ForensicEvent>> {
    let cursor = Cursor::new(buffer);
    let mut parser = EvtxParser::from_read_seek(cursor)
        .map_err(|e| anyhow!("EVTX Parse Error: {:?}", e))?
        .with_configuration(ParserSettings::default());

    let mut events = Vec::new();

    for record in parser.records() {
        if let Ok(rec) = record {
            let xml_str = rec.data;
            if let Ok(doc) = Document::parse(&xml_str) {
                let event_id = doc.descendants()
                    .find(|n: &Node| n.has_tag_name("EventID"))
                    .and_then(|n| n.text())
                    .unwrap_or("0");

                let timestamp_str = doc.descendants()
                    .find(|n: &Node| n.has_tag_name("TimeCreated"))
                    .and_then(|n| n.attribute("SystemTime"))
                    .unwrap_or("");
                
                let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let mut process_name = String::new();
                let mut parent_process_name = String::new();
                let mut command_line = String::new();
                
                // PID 파싱용 임시 변수
                let mut process_id_str = String::new();
                let mut parent_process_id_str = String::new();

                for node in doc.descendants().filter(|n: &Node| n.has_tag_name("Data")) {
                    let attr_name = node.attribute("Name").unwrap_or("");
                    let text = node.text().unwrap_or("");

                    match attr_name {
                        "NewProcessName" | "Image" => process_name = text.to_string(),
                        "CommandLine" => command_line = text.to_string(),
                        "ParentProcessName" | "CreatorProcessName" | "ParentImage" => parent_process_name = text.to_string(),
                        "NewProcessId" | "ProcessId" => process_id_str = text.to_string(),
                        "CreatorProcessId" | "ParentProcessId" => parent_process_id_str = text.to_string(),
                        _ => {}
                    }
                }

                // 16진수 PID 문자열(0x...)을 10진수 정수로 안전하게 변환하는 로직
                let parse_pid = |s: &str| -> u32 {
                    let s = s.trim();
                    if s.starts_with("0x") || s.starts_with("0X") {
                        u32::from_str_radix(&s[2..], 16).unwrap_or(0)
                    } else {
                        s.parse().unwrap_or(0)
                    }
                };

                let process_id = parse_pid(&process_id_str);
                let parent_process_id = parse_pid(&parent_process_id_str);

                if event_id == "4688" || event_id == "1" {
                    if !process_name.is_empty() {
                        events.push(ForensicEvent::Execution(ExecutionEvent {
                            timestamp,
                            process_name: process_name.clone(),
                            process_id,
                            parent_process_id,
                            file_path: process_name,
                            command_line,
                            parent_process_name, 
                            run_count: 1,
                            referenced_files: Vec::new(),
                            source_artifact: format!("EVTX ({})", source_name),
                        }));
                    }
                } else if event_id == "3" || event_id == "5156" {
                    let mut dest_ip = String::new();
                    let mut dest_port_str = String::new();
                    
                    for node in doc.descendants().filter(|n: &Node| n.has_tag_name("Data")) {
                        let attr_name = node.attribute("Name").unwrap_or("");
                        let text = node.text().unwrap_or("");
                        
                        match attr_name {
                            "DestinationIp" | "DestAddress" => dest_ip = text.to_string(),
                            "DestinationPort" | "DestPort" => dest_port_str = text.to_string(),
                            "Image" | "Application" => process_name = text.to_string(),
                            _ => {}
                        }
                    }

                    if !dest_ip.is_empty() {
                        let dest_port: u16 = dest_port_str.parse().unwrap_or(0);
                        events.push(ForensicEvent::NetworkActivity(NetworkEvent {
                            timestamp,
                            process_name,
                            source_ip: String::new(),
                            source_port: 0,
                            destination_ip: dest_ip,
                            destination_port: dest_port,
                            protocol: "TCP/UDP".to_string(),
                            source_artifact: format!("EVTX ({})", source_name),
                        }));
                    }
                } else if ["104", "1102", "7045", "4698"].contains(&event_id) {
                     events.push(ForensicEvent::SystemActivity(SystemEvent {
                        timestamp,
                        activity_type: format!("[CRITICAL] Suspicious System Activity ID: {}", event_id),
                        description: xml_str.chars().take(200).collect(),
                        source_artifact: format!("EVTX ({})", source_name),
                    }));
                }
            }
        }
    }
    Ok(events)
}