use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::ForensicEvent;
use parser::ntuser::parse_ntuser_run_keys;

pub struct NtUserAnalyzer;

impl NtUserAnalyzer {
    pub fn new() -> Self { Self {} }
}

impl ArtifactAnalyzer for NtUserAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::RegistryNTUSER)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        // Users 폴더 내의 다른 DAT 파일들(예: 웹캐시 등)은 무시하고 NTUSER.DAT만 처리
        if !filename.to_lowercase().contains("ntuser.dat") {
            return Ok(events);
        }

        if let Ok(mut parsed_events) = parse_ntuser_run_keys(data, filename) {
            events.append(&mut parsed_events);
        }
        
        Ok(events)
    }
}