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
        
        // 1. 기존 기본 파일 조작 메타데이터
        if reason_flag & 0x00000100 != 0 { reasons.push("File Create"); }
        if reason_flag & 0x00000200 != 0 { reasons.push("File Delete"); }
        if reason_flag & 0x00001000 != 0 { reasons.push("Rename Old Name"); }
        if reason_flag & 0x00002000 != 0 { reasons.push("Rename New Name"); }
        
        // 2. 랜섬웨어/와이퍼 탐지를 위한 핵심 I/O 패턴 (고도화 추가)
        if reason_flag & 0x00000001 != 0 { reasons.push("Data Overwrite"); }
        if reason_flag & 0x00000004 != 0 { reasons.push("Data Truncation"); }
        if reason_flag & 0x00000002 != 0 { reasons.push("Data Extend"); }
        
        // 3. 상태 확정 플래그
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
                
                // 고도화 마스크: Create(0x100) | Delete(0x200) | RenameOld(0x1000) | RenameNew(0x2000)
                // 추가된 마스크: Overwrite(0x1) | Truncation(0x4)
                // 결과 마스크: 0x3300 | 0x0005 = 0x3305
                let target_mask = 0x00003305;
                
                if rec.reason_flags & target_mask != 0 { 
                    let mut activity = reasons.clone();
                    
                    // Overwrite(0x1) 또는 Truncation(0x4) 플래그 감지 시 위협 경고 태그 강제 결합
                    if rec.reason_flags & 0x00000005 != 0 {
                        activity = format!("{} [SUSPICIOUS I/O: Possible Ransomware/Wiper]", activity);
                    }

                    events.push(ForensicEvent::FileSystemActivity(FileSystemEvent {
                        timestamp: rec.timestamp,
                        file_name: rec.file_name.clone(),
                        file_path: rec.file_name,
                        activity_type: activity,
                        is_timestomped: false,
                        source_artifact: "$Extend\\$UsnJrnl".to_string(),
                    }));
                }
            }
        }
        Ok(events)
    }
}