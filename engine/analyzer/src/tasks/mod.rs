use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::ForensicEvent;
use parser::tasks::parse_task_xml;

pub struct TaskAnalyzer;

impl TaskAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for TaskAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::ScheduledTasks)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        // 파서가 이미 ForensicEvent로 변환해주므로, 인자(data, filename)를 맞춰서 그대로 전달받는다.
        if let Ok(mut parsed_events) = parse_task_xml(data, filename) {
            events.append(&mut parsed_events);
        }
        
        Ok(events)
    }
}