use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, ExecutionEvent};
use parser::amcache::parse_amcache_carve;
use chrono::Utc;

pub struct AmcacheAnalyzer;

impl AmcacheAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for AmcacheAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::Amcache)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        if !filename.eq_ignore_ascii_case("Amcache.hve") {
            return Ok(events);
        }

        if let Ok(records) = parse_amcache_carve(data) {
            for rec in records {
                events.push(ForensicEvent::Execution(ExecutionEvent {
                    timestamp: Utc::now(),
                    process_name: rec.file_path.split('\\').last().unwrap_or("Unknown").to_string(),
                    file_path: format!("{} [SHA1: {}]", rec.file_path, rec.sha1),
                    command_line: String::new(), // [추가]
                    parent_process_name: String::new(), // [추가]
                    run_count: 1,
                    referenced_files: vec![],
                    source_artifact: "Amcache.hve".to_string(),
                }));
            }
        }

        Ok(events)
    }
}