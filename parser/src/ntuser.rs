use anyhow::Result;
use chrono::Utc;
use models::event::{ForensicEvent, PersistenceEvent};
use std::collections::HashSet;

pub fn parse_ntuser_run_keys(data: &[u8], filename: &str) -> Result<Vec<ForensicEvent>> {
    let mut events = Vec::new();
    
    // 1. 바이트 슬라이싱 패닉을 방지하기 위해 데이터를 순수 char 벡터로 변환
    let u16_data: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let chars: Vec<char> = std::char::decode_utf16(u16_data)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    
    let lower_chars: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    
    // 검색할 확장자 타겟을 char 배열로 정의
    let targets = [
        vec!['.', 'e', 'x', 'e'],
        vec!['.', 'b', 'a', 't'],
        vec!['.', 'p', 's', '1'],
        vec!['.', 'v', 'b', 's'],
    ];
    
    let mut extracted = HashSet::new();
    let mut i = 0;

    // 2. 바이트가 아닌 char 인덱스 기반 탐색 (100% 안전)
    while i < chars.len() {
        let mut matched_len = 0;
        for target in &targets {
            if i + target.len() <= chars.len() && &lower_chars[i..i + target.len()] == target.as_slice() {
                matched_len = target.len();
                break;
            }
        }

        if matched_len > 0 {
            // 일치하는 확장자를 찾았으므로 경로의 시작점(뒤로 가기) 찾기
            let mut start = i;
            while start > 0 {
                let ch = chars[start - 1];
                // 경로에 사용될 수 있는 아스키 문자와 공백만 허용
                if !ch.is_ascii_graphic() && ch != ' ' {
                    break;
                }
                start -= 1;
            }

            // 인자(Arguments)를 포함하기 위해 경로의 끝점(앞으로 가기) 찾기
            let mut end = i + matched_len;
            while end < chars.len() {
                let ch = chars[end];
                if ch == '\0' || ch == '\n' || ch == '\r' || (!ch.is_ascii_graphic() && ch != ' ') {
                    break;
                }
                end += 1;
            }

            if start < end {
                // char 벡터를 안전하게 String으로 묶어냄
                let extracted_path: String = chars[start..end].iter().collect();
                let trimmed = extracted_path.trim().to_string();
                
                // C:\ 와 같은 드라이브 문자열이 포함된 정상적인 경로인지 검증
                if trimmed.contains(":\\") && !extracted.contains(&trimmed) {
                    extracted.insert(trimmed.clone());
                    events.push(ForensicEvent::Persistence(PersistenceEvent {
                        timestamp: Utc::now(),
                        persistence_type: "Registry Run Key (NTUSER.DAT)".to_string(),
                        target_name: filename.split('\\').last().unwrap_or(filename).to_string(),
                        target_path: trimmed,
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