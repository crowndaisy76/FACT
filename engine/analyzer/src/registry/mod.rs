use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, PersistenceEvent, SystemEvent};
use parser::registry::HiveParser;
use chrono::Utc;

pub struct RegistryAnalyzer;

impl RegistryAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for RegistryAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(
            target,
            ArtifactTarget::RegistrySOFTWARE | ArtifactTarget::RegistrySYSTEM | ArtifactTarget::RegistrySAM
        )
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        let parser = match HiveParser::new(data) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Skipping {} (Not a valid hive): {}", filename, e);
                return Ok(events);
            }
        };

        // 1. SOFTWARE 
        if filename.eq_ignore_ascii_case("SOFTWARE") {
            let targets = vec![
                ("Microsoft\\Windows\\CurrentVersion\\Run", "Run Key"),
                ("Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce Key"),
                ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run Key (32-bit)"),
                ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce Key (32-bit)"),
            ];
            for (path, desc) in targets {
                if let Some(key_off) = parser.find_key(path) {
                    let values = parser.get_values(key_off);
                    for val in values {
                        events.push(ForensicEvent::Persistence(PersistenceEvent {
                            timestamp: Utc::now(),
                            persistence_type: desc.to_string(),
                            target_name: val.name,
                            target_path: val.data_string,
                            payload: String::new(), 
                            source_artifact: format!("SOFTWARE\\{}", path),
                        }));
                    }
                } else {
                    tracing::debug!("    [-] Target path not found in Base Hive: {}", path);
                }
            }
        }

        // 2. SYSTEM (ServiceDll 은닉 파훼 및 수동 시작 탐지 고도화)
        if filename.eq_ignore_ascii_case("SYSTEM") {
            if let Some(services_off) = parser.find_key("ControlSet001\\Services") {
                let subkeys = parser.get_subkeys(services_off);
                for sk in subkeys {
                    let service_name = parser.get_key_name(sk);
                    let values = parser.get_values(sk);
                    
                    let mut start_type_val: Option<u32> = None;
                    let mut image_path = String::new();
                    
                    for val in values {
                        if val.name.eq_ignore_ascii_case("Start") {
                            if val.data_raw.len() >= 4 {
                                let st = u32::from_le_bytes(val.data_raw[0..4].try_into().unwrap());
                                start_type_val = Some(st);
                            }
                        }
                        if val.name.eq_ignore_ascii_case("ImagePath") {
                            image_path = val.data_string.clone();
                        }
                    }
                    
                    // Start == 2 (Auto), Start == 3 (Manual/Demand)
                    if let Some(st) = start_type_val {
                        if (st == 2 || st == 3) && !image_path.is_empty() {
                            let mut final_path = image_path.clone();
                            
                            // svchost.exe 등 호스트 프로세스를 사용할 경우 Parameters\\ServiceDll 추출
                            if final_path.to_lowercase().contains("svchost.exe") {
                                let srv_subkeys = parser.get_subkeys(sk);
                                for param_sk in srv_subkeys {
                                    if parser.get_key_name(param_sk).eq_ignore_ascii_case("Parameters") {
                                        let param_values = parser.get_values(param_sk);
                                        for pval in param_values {
                                            if pval.name.eq_ignore_ascii_case("ServiceDll") {
                                                final_path = format!("{} [ServiceDll: {}]", final_path, pval.data_string);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            let persist_type = if st == 2 {
                                "System Service (Auto-Start)"
                            } else {
                                "System Service (Manual-Start)"
                            };
                            
                            events.push(ForensicEvent::Persistence(PersistenceEvent {
                                timestamp: Utc::now(),
                                persistence_type: persist_type.to_string(),
                                target_name: service_name,
                                target_path: final_path,
                                payload: String::new(), 
                                source_artifact: "SYSTEM\\ControlSet001\\Services".to_string(),
                            }));
                        }
                    }
                }
            }
        }

        // 3. SAM 
        if filename.eq_ignore_ascii_case("SAM") {
            if let Some(names_off) = parser.find_key("SAM\\Domains\\Account\\Users\\Names") {
                let subkeys = parser.get_subkeys(names_off);
                for sk in subkeys {
                    let user_name = parser.get_key_name(sk);
                    events.push(ForensicEvent::SystemActivity(SystemEvent {
                        timestamp: Utc::now(),
                        activity_type: "Local User Account".to_string(),
                        description: format!("Found user account: {}", user_name),
                        source_artifact: "SAM\\...\\Users\\Names".to_string(),
                    }));
                }
            }
        }
        Ok(events)
    }
}