use anyhow::Result;

#[derive(Debug, Clone)]
pub struct TaskRecord {
    pub command: String,
    pub arguments: String,
    pub class_id: String, // [New] COM 핸들러 대응
    pub author: String,
    pub is_hidden: bool,
}

pub fn parse_task_xml(data: &[u8]) -> Result<TaskRecord> {
    // [Fix] UTF-16LE BOM(Byte Order Mark: FF FE) 대응 완벽 디코딩
    let xml_str = if data.starts_with(&[0xFF, 0xFE]) {
        // BOM이 있으면 앞 2바이트를 건너뛰고 파싱
        let u16_data: Vec<u16> = data[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_data)
    } else if data.len() >= 2 && data[1] == 0 {
        // BOM 없는 순수 UTF-16LE
        let u16_data: Vec<u16> = data.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_data)
    } else {
        // UTF-8 Fallback
        String::from_utf8_lossy(data).to_string()
    };

    // 경량화된 XML 태그 추출 클로저
    let extract_tag = |tag: &str| -> String {
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);
        if let Some(start_idx) = xml_str.find(&start_tag) {
            if let Some(end_idx) = xml_str[start_idx..].find(&end_tag) {
                return xml_str[start_idx + start_tag.len()..start_idx + end_idx].trim().to_string();
            }
        }
        String::new()
    };

    let command = extract_tag("Command");
    let arguments = extract_tag("Arguments");
    let class_id = extract_tag("ClassId"); // COM 객체 ID 추출
    let author = extract_tag("Author");
    let hidden_str = extract_tag("Hidden");
    let is_hidden = hidden_str.eq_ignore_ascii_case("true");

    Ok(TaskRecord {
        command,
        arguments,
        class_id,
        author,
        is_hidden,
    })
}