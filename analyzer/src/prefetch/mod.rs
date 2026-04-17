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
                        command_line: String::new(), // [추가] Prefetch는 커맨드라인을 제공하지 않으므로 빈 문자열
                        parent_process_name: String::new(), // [추가] 부모 프로세스 정보 없음
                        run_count: info.run_count,
                        // [수정] 빈 배열이 아닌, 파서가 추출한 실제 참조 파일 목록을 매핑함
                        referenced_files: info.referenced_files.clone(), 
                        source_artifact: "Prefetch".to_string(),
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