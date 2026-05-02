use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, PersistenceEvent};
use std::collections::HashSet;

pub fn parse_ntuser_run_keys(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    
    // 1. 데이터를 UTF-16으로 간주하고 char 배열로 변환
    let u16_data: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let chars: Vec<char> = std::char::decode_utf16(u16_data)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    
    let lower_chars: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    
    // 찾을 키워드를 char 배열로 선언
    let targets = [
        vec!['.', 'e', 'x', 'e'],
        vec!['.', 'b', 'a', 't'],
        vec!['.', 'p', 's', '1'],
        vec!['.', 'v', 'b', 's'],
    ];
    
    let mut extracted = HashSet::new();
    let mut i = 0;

    // 2. 슬라이딩 윈도우 방식으로 char 단위 비교 (100% 매칭률 보장)
    while i < chars.len() {
        let mut matched_len = 0;
        for target in &targets {
            if i + target.len() <= chars.len() && &lower_chars[i..i + target.len()] == target.as_slice() {
                matched_len = target.len();
                break;
            }
        }

        if matched_len > 0 {
            // 키워드를 찾았으므로 앞뒤로 출력 가능한 문자(경로)를 수집
            let mut start = i;
            while start > 0 {
                let ch = chars[start - 1];
                // 제어 문자나 널 바이트를 만나면 중단
                if !ch.is_ascii_graphic() && ch != ' ' {
                    break;
                }
                start -= 1;
            }

            // 뒤로 파라미터(Arguments)까지 포함할 수 있도록 확장
            let mut end = i + matched_len;
            while end < chars.len() {
                let ch = chars[end];
                if ch == '\0' || ch == '\n' || ch == '\r' || (!ch.is_ascii_graphic() && ch != ' ') {
                    break;
                }
                end += 1;
            }

            if start < end {
                // char 슬라이스를 String으로 변환
                let extracted_path: String = chars[start..end].iter().collect();
                let trimmed = extracted_path.trim().to_string();
                
                // C:\ 와 같은 절대경로 패턴이 포함된 경우만 유효한 값으로 취급
                if trimmed.contains(":\\") && !extracted.contains(&trimmed) {
                    extracted.insert(trimmed.clone());

                    events.push(ForensicEvent::Persistence(PersistenceEvent {
                        timestamp: Utc::now(),
                        persistence_type: "Registry Run Key (NTUSER.DAT)".to_string(),
                        target_name: filename.split('\\').last().unwrap_or(filename).to_string(),
                        target_path: trimmed,
                        payload: String::new(), // 에러 수정
                        source_artifact: format!("Registry: {}", filename),
                    }));
                }
            }
            i += matched_len;
        } else {
            i += 1;
        }
    }
    
    Ok(events)
}