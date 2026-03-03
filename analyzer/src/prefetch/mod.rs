use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, ExecutionEvent};
use parser::prefetch::parse_prefetch_info;

pub struct PrefetchAnalyzer;

impl PrefetchAnalyzer {
    pub fn new() -> Self {
        Self {}
    }
}

impl ArtifactAnalyzer for PrefetchAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::Prefetch)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();

        match parse_prefetch_info(data) {
            Ok(info) => {
                for timestamp in info.last_run_times {
                    let event = ForensicEvent::Execution(ExecutionEvent {
                        timestamp,
                        process_name: info.executable_name.clone(),
                        file_path: filename.to_string(), 
                        run_count: info.run_count,
                        referenced_files: vec![], 
                        source_artifact: "Prefetch".to_string(),
                    });
                    events.push(event);
                }
            },
            Err(e) => {
                // [Fix] 실패 사유를 명확히 확인하기 위해 warn 레벨로 상향
                tracing::warn!("Failed to parse Prefetch {}: {}", filename, e);
            }
        }

        Ok(events)
    }
}