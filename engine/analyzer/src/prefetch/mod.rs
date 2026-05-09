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
                        process_id: 0,          // 에러 수정
                        parent_process_id: 0,   // 에러 수정
                        file_path: filename.to_string(), 
                        command_line: String::new(), 
                        parent_process_name: String::new(), 
                        run_count: info.run_count,
                        referenced_files: info.referenced_files.clone(), 
                        source_artifact: "Prefetch".to_string(),
                        ioc_hash: None, // [고도화 반영] 컴파일 에러 수정
                    });
                    events.push(event);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to parse Prefetch {}: {}", filename, e);
            }
        }
        Ok(events)
    }
}