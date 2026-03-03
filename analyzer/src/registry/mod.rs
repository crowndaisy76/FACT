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

        // 1. SOFTWARE 하이브 분석: 자동 실행 프로그램 (정석적인 Tree-Walking 수행)
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
                            source_artifact: format!("SOFTWARE\\{}", path),
                        }));
                    }
                } else {
                    tracing::debug!("    [-] Target path not found in Base Hive: {}", path);
                }
            }
        }

        // 2. SYSTEM 하이브 분석: 백그라운드 자동 실행 서비스 (Start=2)
        if filename.eq_ignore_ascii_case("SYSTEM") {
            if let Some(services_off) = parser.find_key("ControlSet001\\Services") {
                let subkeys = parser.get_subkeys(services_off);
                for sk in subkeys {
                    let service_name = parser.get_key_name(sk);
                    let values = parser.get_values(sk);
                    
                    let mut is_auto_start = false;
                    let mut image_path = String::new();

                    for val in values {
                        if val.name.eq_ignore_ascii_case("Start") {
                            if val.data_raw.len() >= 4 {
                                let start_type = u32::from_le_bytes(val.data_raw[0..4].try_into().unwrap());
                                if start_type == 2 { // Auto Start
                                    is_auto_start = true;
                                }
                            }
                        }
                        if val.name.eq_ignore_ascii_case("ImagePath") {
                            image_path = val.data_string.clone();
                        }
                    }

                    if is_auto_start && !image_path.is_empty() {
                        events.push(ForensicEvent::Persistence(PersistenceEvent {
                            timestamp: Utc::now(),
                            persistence_type: "System Service (Auto-Start)".to_string(),
                            target_name: service_name,
                            target_path: image_path,
                            source_artifact: "SYSTEM\\ControlSet001\\Services".to_string(),
                        }));
                    }
                }
            }
        }

        // 3. SAM 하이브 분석: 로컬 사용자 계정
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