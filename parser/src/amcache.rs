use anyhow::Result;

#[derive(Debug, Clone)]
pub struct AmcacheRecord {
    pub file_path: String, // 구조체 필드명
    pub sha1: String,
}

pub fn parse_amcache_carve(data: &[u8]) -> Result<Vec<AmcacheRecord>> {
    let mut records = Vec::new();
    let mut i = 0;

    // 바이너리 버퍼 선형 탐색 (Linear Hex-Scan)
    while i < data.len().saturating_sub(100) {
        // UTF-16LE 기반의 절대 경로 시작점 ("c:\" 또는 "C:\") 탐색
        if (data[i] == b'c' || data[i] == b'C') && data[i+1] == 0 
            && data[i+2] == b':' && data[i+3] == 0 
            && data[i+4] == b'\\' && data[i+5] == 0 
        {
            let mut j = i;
            let mut path_u16 = Vec::new();
            
            // Null 문자를 만날 때까지 UTF-16 문자열 추출
            while j + 1 < data.len() && path_u16.len() < 500 {
                let c = u16::from_le_bytes([data[j], data[j+1]]);
                if c == 0 { break; }
                path_u16.push(c);
                j += 2;
            }
            
            let parsed_path = String::from_utf16_lossy(&path_u16);
            
            // 실행 파일(.exe, .dll, .sys 등)인 경우에만 해시 스캔 시작
            if parsed_path.to_lowercase().ends_with(".exe") || parsed_path.to_lowercase().ends_with(".dll") || parsed_path.to_lowercase().ends_with(".sys") {
                
                // 경로 문자열 근처(앞뒤 2048 바이트)에서 FileId(SHA-1) 값 카빙
                let start_scan = i.saturating_sub(2048);
                let end_scan = std::cmp::min(i + 2048, data.len());
                let mut sha1 = String::from("No Hash Found");
                
                for k in start_scan..end_scan.saturating_sub(88) {
                    // Amcache의 FileId 값은 '0000'으로 시작하는 44자리 문자열 (UTF-16)
                    if data[k] == b'0' && data[k+1] == 0 && data[k+2] == b'0' && data[k+3] == 0 {
                        let mut is_hex = true;
                        let mut hex_str = String::new();
                        
                        for step in 0..44 {
                            let c1 = data[k + step*2];
                            let c2 = data[k + step*2 + 1];
                            if c2 != 0 || (!c1.is_ascii_hexdigit() && c1 != b'0') {
                                is_hex = false;
                                break;
                            }
                            hex_str.push(c1 as char);
                        }
                        
                        if is_hex && hex_str.starts_with("0000") {
                            // 앞의 '0000' 4자리를 떼어내고 40자리 순수 SHA-1 해시만 추출
                            sha1 = hex_str[4..].to_string();
                            break;
                        }
                    }
                }
                
                // [Fix] path -> file_path 로 필드명 일치
                records.push(AmcacheRecord { file_path: parsed_path, sha1 });
            }
            i = j; // 문자열 길이만큼 점프
        } else {
            i += 1;
        }
    }
    
    // [Fix] a.path -> a.file_path 로 수정
    records.sort_by(|a, b| a.file_path.cmp(&b.file_path));
    records.dedup_by(|a, b| a.file_path == b.file_path);
    
    Ok(records)
}