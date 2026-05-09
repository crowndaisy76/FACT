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
        
        // 고도화된 파서가 트리거 및 권한 문맥까지 모두 매핑한 ForensicEvent를 반환하므로 그대로 통과시킴
        if let Ok(mut parsed_events) = parse_task_xml(data, filename) {
            events.append(&mut parsed_events);
        }
        
        Ok(events)
    }
}