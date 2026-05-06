use evtx::{EvtxParser, ParserSettings};
use models::event::{ForensicEvent, ExecutionEvent, NetworkEvent, SystemEvent};
use std::io::Cursor;
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};
use anyhow::{Result, anyhow};
use rayon::prelude::*;

// [고도화 포인트] 정규화된 탐지 타겟 ID 배열 (Fast-Path용)
// 오탐을 막기 위해 XML 태그 형식인 ">ID<" 형태로 선언
const TARGET_IDS: &[&str] = &[
    // 프로세스 및 네트워크
    ">4688<", ">1<", ">3<", ">5156<",
    // 로그인 및 권한 (신규 반영)
    ">4624<", ">4625<", ">4672<", ">4768<", ">4769<",
    // 지속성 유지: 서비스 & 예약작업 (신규 반영)
    ">7045<", ">4697<", ">4698<",
    // 방어 회피: 로그 삭제
    ">104<", ">1102<",
    // 스크립트 실행 (신규 반영)
    ">4104<", ">5861<"
];

pub fn parse_security_evtx_buffer(buffer: &[u8], source_name: &str) -> Result<Vec<ForensicEvent>> {
    let cursor = Cursor::new(buffer);
    
    let mut parser = EvtxParser::from_read_seek(cursor)
        .map_err(|e| anyhow!("EVTX Parse Error: {:?}", e))?
        .with_configuration(ParserSettings::default().indent(false));

    let records: Vec<String> = parser.records()
        .filter_map(|r| r.ok().map(|rec| rec.data))
        .collect();

    let events: Vec<ForensicEvent> = records.into_par_iter().filter_map(|xml_str| {
        // [Fast-Path] TARGET_IDS 배열 중 하나라도 포함되어 있는지 고속 스캔
        // 조건문이 40개로 늘어나도 Rust의 내부 최적화로 매우 빠르게 동작함
        if !TARGET_IDS.iter().any(|&id| xml_str.contains(id)) {
            return None;
        }

        let doc = Document::parse(&xml_str).ok()?;
        
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
        let mut dest_ip = String::new();
        let mut process_id_str = String::new();
        let mut target_user = String::new(); // 추가: 로그인한 사용자 계정 파싱용

        for node in doc.descendants().filter(|n: &Node| n.has_tag_name("Data")) {
            let attr_name = node.attribute("Name").unwrap_or("");
            let text = node.text().unwrap_or("");

            match attr_name {
                "NewProcessName" | "Image" => process_name = text.to_string(),
                "CommandLine" => command_line = text.to_string(),
                "ParentProcessName" | "ParentImage" => parent_process_name = text.to_string(),
                "DestinationIp" | "DestAddress" => dest_ip = text.to_string(),
                "NewProcessId" | "ProcessId" => process_id_str = text.to_string(),
                "TargetUserName" | "SubjectUserName" => target_user = text.to_string(), // 사용자 정보 추출
                _ => {}
            }
        }

        let parse_pid = |s: &str| -> u32 {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") { u32::from_str_radix(&s[2..], 16).unwrap_or(0) } else { s.parse().unwrap_or(0) }
        };

        // 1. 실행 이벤트 (4688, 1)
        if event_id == "4688" || event_id == "1" {
            if !process_name.is_empty() {
                return Some(ForensicEvent::Execution(ExecutionEvent {
                    timestamp, process_name: process_name.clone(),
                    process_id: parse_pid(&process_id_str), parent_process_id: 0,
                    file_path: process_name, command_line, parent_process_name, 
                    run_count: 1, referenced_files: Vec::new(), source_artifact: format!("EVTX ({})", source_name),
                }));
            }
        } 
        // 2. 네트워크 이벤트 (3, 5156)
        else if event_id == "3" || event_id == "5156" {
            if !dest_ip.is_empty() {
                return Some(ForensicEvent::NetworkActivity(NetworkEvent {
                    timestamp, process_name, source_ip: String::new(), source_port: 0,
                    destination_ip: dest_ip, destination_port: 0, protocol: "TCP/UDP".to_string(),
                    source_artifact: format!("EVTX ({})", source_name),
                }));
            }
        }
        // 3. 시스템 및 중요 보안 활동 (로그온, 서비스 생성, 로그 삭제, 스크립트 등)
        else if ["4624", "4625", "4672", "7045", "4697", "4698", "104", "1102", "4104"].contains(&event_id) {
            let activity_type = match event_id {
                "4624" => format!("Logon Success ({})", target_user),
                "4625" => format!("Logon Failed ({})", target_user),
                "7045" | "4697" => "New Service Installed".to_string(),
                "4698" => "Scheduled Task Created".to_string(),
                "4104" => "PowerShell Script Block Execution".to_string(),
                _ => format!("[CRITICAL] System Activity ID: {}", event_id)
            };

            return Some(ForensicEvent::SystemActivity(SystemEvent {
                timestamp,
                activity_type,
                // 스크립트 내용이나 상세 정보를 담기 위해 Data 텍스트 일부 보존
                description: xml_str.chars().take(300).collect(),
                source_artifact: format!("EVTX ({})", source_name),
            }));
        }
        
        None
    }).collect();

    Ok(events)
}