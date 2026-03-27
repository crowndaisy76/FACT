use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, PersistenceEvent};
use parser::tasks::parse_task_xml;
use chrono::Utc;

pub struct TasksAnalyzer;

impl TasksAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for TasksAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::ScheduledTasks)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();

        if let Ok(record) = parse_task_xml(data) {
            // 실행 명령어(Command)나 COM 객체(ClassId) 둘 중 하나라도 있으면 유효한 작업으로 간주
            if !record.command.is_empty() || !record.class_id.is_empty() {
                
                let payload = if !record.command.is_empty() {
                    if record.arguments.is_empty() {
                        record.command.clone()
                    } else {
                        format!("{} {}", record.command, record.arguments)
                    }
                } else {
                    format!("COM Handler (ClassId: {})", record.class_id)
                };

                // 숨김 속성 태깅
                let hidden_flag = if record.is_hidden { " [HIDDEN]" } else { "" };

                events.push(ForensicEvent::Persistence(PersistenceEvent {
                    timestamp: Utc::now(), 
                    persistence_type: format!("Scheduled Task{}", hidden_flag),
                    target_name: filename.to_string(), 
                    target_path: payload,              
                    source_artifact: format!("Tasks\\{}", filename),
                }));
            }
        }

        Ok(events)
    }
}