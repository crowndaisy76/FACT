use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, LogonEvent, ExecutionEvent, PersistenceEvent, SystemEvent};
use chrono::{DateTime, Utc};
use evtx::EvtxParser;
// [Fix] warning 제거: use serde_json::Value; 삭제

pub struct EvtxAnalyzer;

impl EvtxAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for EvtxAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::EventLogs)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        if !filename.to_lowercase().ends_with(".evtx") {
            return Ok(events);
        }

        let target_logs = [
            "Security.evtx", 
            "System.evtx", 
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "Windows PowerShell.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx"
        ];

        let mut is_target = false;
        for t in target_logs.iter() {
            if filename.eq_ignore_ascii_case(t) {
                is_target = true;
                break;
            }
        }

        if !is_target { return Ok(events); }

        let mut parser = match EvtxParser::from_buffer(data.to_vec()) {
            Ok(p) => p,
            Err(_) => return Ok(events),
        };

        for record_result in parser.records_json_value() {
            if let Ok(record) = record_result {
                let doc = record.data;
                
                let event_id = doc["Event"]["System"]["EventID"].as_u64().unwrap_or(0);
                
                let sys_time_str = doc["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
                    .as_str()
                    .unwrap_or("");
                let timestamp = DateTime::parse_from_rfc3339(sys_time_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let event_data = &doc["Event"]["EventData"];
                let user_data = &doc["Event"]["UserData"];

                match event_id {
                    4624 | 4625 => {
                        let logon_type = event_data["LogonType"].as_str().unwrap_or("0");
                        
                        if logon_type == "3" || logon_type == "10" {
                            let status = if event_id == 4624 { "Success" } else { "Failed" };
                            let account = event_data["TargetUserName"].as_str().unwrap_or("Unknown");
                            let ip = event_data["IpAddress"].as_str().unwrap_or("-");
                            
                            // [Fix] IP가 없거나 Unknown일 경우 None, 아니면 Some()으로 래핑
                            let source_ip = if ip == "-" || ip == "Unknown" { None } else { Some(ip.to_string()) };

                            if !account.ends_with('$') && account != "Unknown" {
                                events.push(ForensicEvent::Logon(LogonEvent {
                                    timestamp,
                                    event_id: event_id as u32,
                                    account_name: account.to_string(),
                                    logon_type: logon_type.parse().unwrap_or(0),
                                    source_ip, // 타입 에러 해결
                                    status: status.to_string(),
                                    source_artifact: filename.to_string(),
                                }));
                            }
                        }
                    },
                    7045 | 4697 => {
                        let service_name = event_data["ServiceName"].as_str().unwrap_or("Unknown");
                        let image_path = event_data["ImagePath"].as_str().unwrap_or("Unknown");
                        events.push(ForensicEvent::Persistence(PersistenceEvent {
                            timestamp,
                            persistence_type: "New Service Installed".to_string(),
                            target_name: service_name.to_string(),
                            target_path: image_path.to_string(),
                            source_artifact: filename.to_string(),
                        }));
                    },
                    106 => { 
                        let task_name = user_data["TaskRegistered"]["TaskName"].as_str().unwrap_or("Unknown");
                        events.push(ForensicEvent::Persistence(PersistenceEvent {
                            timestamp,
                            persistence_type: "Scheduled Task Registered".to_string(),
                            target_name: task_name.to_string(),
                            target_path: "Check Task XML for Payload".to_string(),
                            source_artifact: filename.to_string(),
                        }));
                    },
                    4720 => { 
                        let account = event_data["TargetUserName"].as_str().unwrap_or("Unknown");
                        events.push(ForensicEvent::SystemActivity(SystemEvent {
                            timestamp,
                            activity_type: "Account Created".to_string(),
                            description: format!("New user account created: {}", account),
                            source_artifact: filename.to_string(),
                        }));
                    },
                    4732 => { 
                        let account = event_data["MemberName"].as_str().unwrap_or("Unknown");
                        let group = event_data["TargetUserName"].as_str().unwrap_or("Unknown");
                        events.push(ForensicEvent::SystemActivity(SystemEvent {
                            timestamp,
                            activity_type: "Group Member Added".to_string(),
                            description: format!("Account '{}' added to group '{}'", account, group),
                            source_artifact: filename.to_string(),
                        }));
                    },
                    1102 | 104 => { 
                        events.push(ForensicEvent::SystemActivity(SystemEvent {
                            timestamp,
                            activity_type: "Audit Log Cleared [CRITICAL]".to_string(),
                            description: "Event log was cleared by a user or process".to_string(),
                            source_artifact: filename.to_string(),
                        }));
                    },
                    4688 => { 
                        let proc_name = event_data["NewProcessName"].as_str().unwrap_or("Unknown");
                        let cmd_line = event_data["CommandLine"].as_str().unwrap_or("Hidden");
                        
                        events.push(ForensicEvent::Execution(ExecutionEvent {
                            timestamp,
                            process_name: proc_name.to_string(),
                            file_path: cmd_line.to_string(),
                            run_count: 1,
                            referenced_files: vec![],
                            source_artifact: filename.to_string(),
                        }));
                    },
                    4104 => { 
                        let script = event_data["ScriptBlockText"].as_str().unwrap_or("");
                        if !script.is_empty() {
                            events.push(ForensicEvent::SystemActivity(SystemEvent {
                                timestamp,
                                activity_type: "PowerShell Script Block".to_string(),
                                description: format!("Script executed: {}...", &script.chars().take(100).collect::<String>()),
                                source_artifact: filename.to_string(),
                            }));
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(events)
    }
}