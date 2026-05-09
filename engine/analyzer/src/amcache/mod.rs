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
                let proc_name = rec.file_path.split('\\').last().unwrap_or("Unknown").to_string();
                
                events.push(ForensicEvent::Execution(ExecutionEvent {
                    timestamp: Utc::now(), // 또는 rec.timestamp
                    process_name: proc_name,
                    process_id: 0,          
                    parent_process_id: 0,   
                    
                    // 기존의 문자열 래핑을 폐기하고 원본 경로 보존
                    file_path: rec.file_path,
                    command_line: String::new(), 
                    parent_process_name: String::new(), 
                    run_count: 1,
                    referenced_files: vec![],
                    source_artifact: "Amcache.hve".to_string(),
                    
                    // 독립된 ioc_hash 필드에 해시값 맵핑
                    ioc_hash: Some(rec.sha1),
                }));
            }
        }
        Ok(events)
    }
}