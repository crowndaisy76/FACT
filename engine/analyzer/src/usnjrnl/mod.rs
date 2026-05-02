use crate::ArtifactAnalyzer;
use anyhow::Result;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, FileSystemEvent};
use parser::usnjrnl::parse_usnjrnl_stream;

pub struct UsnJrnlAnalyzer;

impl UsnJrnlAnalyzer {
    pub fn new() -> Self { Self {} }
    
    fn translate_reason(reason_flag: u32) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if reason_flag & 0x00000100 != 0 { reasons.push("File Create"); }
        if reason_flag & 0x00000200 != 0 { reasons.push("File Delete"); }
        if reason_flag & 0x00000002 != 0 { reasons.push("Data Extend"); }
        if reason_flag & 0x00001000 != 0 { reasons.push("Rename Old Name"); }
        if reason_flag & 0x00002000 != 0 { reasons.push("Rename New Name"); }
        if reason_flag & 0x80000000 != 0 { reasons.push("Close"); }
        
        if reasons.is_empty() {
            reasons.push("Other Modification");
        }
        reasons
    }
}

impl ArtifactAnalyzer for UsnJrnlAnalyzer {
    fn can_handle(&self, target: &ArtifactTarget) -> bool {
        matches!(target, ArtifactTarget::UsnJrnl)
    }

    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>> {
        let mut events = Vec::new();
        
        if !filename.eq_ignore_ascii_case("$UsnJrnl") && !filename.eq_ignore_ascii_case("$J") {
            return Ok(events);
        }

        if let Ok(records) = parse_usnjrnl_stream(data) {
            for rec in records {
                let reasons = Self::translate_reason(rec.reason_flags).join(" | ");
                
                if rec.reason_flags & 0x00003300 != 0 { 
                    events.push(ForensicEvent::FileSystemActivity(FileSystemEvent {
                        timestamp: rec.timestamp,
                        file_name: rec.file_name.clone(),
                        file_path: rec.file_name,
                        activity_type: reasons, // 에러 수정
                        is_timestomped: false,
                        source_artifact: "$Extend\\$UsnJrnl".to_string(),
                    }));
                }
            }
        }
        Ok(events)
    }
}