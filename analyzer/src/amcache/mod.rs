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
                // 실행 흔적(ExecutionEvent) 객체 재활용
                events.push(ForensicEvent::Execution(ExecutionEvent {
                    timestamp: Utc::now(), // Amcache 카빙 시 타임스탬프는 생략하고 현재 시간 매핑
                    // [Fix] rec.path -> rec.file_path 로 수정
                    process_name: rec.file_path.split('\\').last().unwrap_or("Unknown").to_string(),
                    // [Fix] rec.path -> rec.file_path 로 수정
                    file_path: format!("{} [SHA1: {}]", rec.file_path, rec.sha1),
                    run_count: 1,
                    referenced_files: vec![],
                    source_artifact: "Amcache.hve".to_string(),
                }));
            }
        }

        Ok(events)
    }
}