use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, PersistenceEvent};
use std::collections::HashSet;

// 탐지할 핵심 키워드를 소문자 바이트 배열로 미리 정의
const WMI_TARGET_KEYWORDS: &[&[u8]] = &[
    b"powershell",
    b"cmd.exe",
    b"wscript",
    b"cscript",
    b"mshta",
    b"regsvr32",
    b"rundll32",
];

pub fn parse_wmi_carve(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    let mut extracted = HashSet::new();
    
    let mut i = 0;
    while i < data.len().saturating_sub(20) {
        // UTF-16LE 글자 단위(2바이트)로 영문 소문자 변환하여 고속 비교
        let ch1 = data[i].to_ascii_lowercase();
        let ch2 = data[i+1];
        
        // 영어 알파벳 범위이고, UTF-16LE의 두 번째 바이트가 0일 때 (ASCII 호환)
        if ch1.is_ascii_lowercase() && ch2 == 0 {
            let mut match_found = false;
            
            for &keyword in WMI_TARGET_KEYWORDS {
                let mut is_match = true;
                let mut k_idx = 0;
                let mut data_idx = i;
                
                // 키워드 길이만큼 바이트 슬라이드 검사
                while k_idx < keyword.len() && data_idx + 1 < data.len() {
                    let d_ch = data[data_idx].to_ascii_lowercase();
                    if d_ch != keyword[k_idx] || data[data_idx+1] != 0 {
                        is_match = false;
                        break;
                    }
                    k_idx += 1;
                    data_idx += 2;
                }
                
                if is_match && keyword.len() > 0 {
                    match_found = true;
                    break;
                }
            }
            
            if match_found {
                // 키워드가 발견되면, 앞뒤로 출력 가능한 UTF-16 문자열(Payload)을 추출
                let mut start = i;
                while start >= 2 {
                    let c = data[start - 2];
                    if (!c.is_ascii_graphic() && c != b' ') || data[start - 1] != 0 {
                        break;
                    }
                    start -= 2;
                }
                
                let mut end = i;
                while end + 1 < data.len() {
                    let c = data[end];
                    if (!c.is_ascii_graphic() && c != b' ') || data[end + 1] != 0 {
                        break;
                    }
                    end += 2;
                }
                
                if start < end {
                    let u16_data: Vec<u16> = data[start..end].chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let payload = String::from_utf16_lossy(&u16_data).trim().to_string();
                    
                    if payload.len() > 10 && !extracted.contains(&payload) {
                        extracted.insert(payload.clone());
                    }
                }
                i = end; // 읽은 부분 다음으로 점프
                continue;
            }
        }
        i += 1; // 매칭 실패 시 1바이트씩 전진 (정렬 어긋남 방지)
    }

    for path in extracted {
        events.push(ForensicEvent::Persistence(PersistenceEvent {
            timestamp: Utc::now(),
            persistence_type: "WMI Event Consumer".to_string(),
            target_name: "WMI Object".to_string(),
            target_path: path,
            payload: String::new(),
            source_artifact: format!("WMI: {}", filename),
        }));
    }

    Ok(events)
}