use models::event::{ForensicEvent, ExecutionEvent};
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub struct Preprocessor;

impl Preprocessor {
    pub fn run(mut events: Vec<ForensicEvent>) -> Vec<ForensicEvent> {
        for event in &mut events {
            if let ForensicEvent::Execution(e) = event {
                Self::decode_powershell_enc(e);
            }
        }
        events
    }

    // PowerShell Base64(UTF-16LE) 인코딩 명령어 복호화 로직
    fn decode_powershell_enc(e: &mut ExecutionEvent) {
        let cmd = &e.command_line;
        let lower_cmd = cmd.to_lowercase();
        
        if lower_cmd.contains("-enc") || lower_cmd.contains("-encodedcommand") {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p.to_lowercase().starts_with("-enc")) {
                if pos + 1 < parts.len() {
                    let b64_str = parts[pos + 1];
                    if let Ok(decoded_bytes) = STANDARD.decode(b64_str) {
                        // PowerShell은 기본적으로 UTF-16LE 규격을 사용함
                        let u16_data: Vec<u16> = decoded_bytes
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        
                        if let Ok(decoded_str) = String::from_utf16(&u16_data) {
                            // 원본 로그 뒤에 복호화된 평문을 덧붙여 상관분석기로 넘김
                            e.command_line = format!("{} [DECODED: {}]", cmd, decoded_str);
                        }
                    }
                }
            }
        }
    }
}