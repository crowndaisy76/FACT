use models::event::{ForensicEvent, ExecutionEvent};
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub struct Preprocessor;

impl Preprocessor {
    pub fn run(mut events: Vec<ForensicEvent>) -> Vec<ForensicEvent> {
        for event in &mut events {
            if let ForensicEvent::Execution(e) = event {
                Self::normalize_paths(e);
                Self::decode_powershell_enc(e);
            }
        }
        events
    }

    fn normalize_paths(e: &mut ExecutionEvent) {
        // [고도화] 대소문자 및 슬래시 정규화로 엔티티 일치율 극대화
        e.file_path = e.file_path.to_lowercase().replace("\\\\", "\\");
        e.process_name = e.process_name.to_lowercase();
        e.parent_process_name = e.parent_process_name.to_lowercase();
    }

    fn decode_powershell_enc(e: &mut ExecutionEvent) {
        let cmd = &e.command_line;
        let lower_cmd = cmd.to_lowercase();
        let keywords = ["-encodedcommand", "-enc", "-e "];
        for kw in keywords {
            if let Some(pos) = lower_cmd.find(kw) {
                let after_kw = &cmd[pos + kw.len()..].trim_start();
                let b64_str = after_kw.split_whitespace().next().unwrap_or("");
                if let Ok(decoded_bytes) = STANDARD.decode(b64_str) {
                    let u16_data: Vec<u16> = decoded_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    if let Ok(decoded_str) = String::from_utf16(&u16_data) {
                        e.command_line = format!("{} [DECODED: {}]", cmd, decoded_str);
                        return;
                    }
                }
            }
        }
    }
}