use models::mft::{FileRecordHeader, AttributeHeader}; // <== 여기에 AttributeHeader가 반드시 있어야 합니다.
use models::FactError;
use binrw::BinReaderExt;
use std::io::Cursor;

/// 1024바이트 Raw Data를 MFT File Record Header로 파싱
pub fn parse_file_record_header(data: &[u8]) -> Result<FileRecordHeader, FactError> {
    let mut reader = Cursor::new(data);

    let header: FileRecordHeader = reader.read_le()
        .map_err(|e| FactError::ParseError {
            artifact_name: "MFT Record Header".to_string(),
            details: e.to_string()
        })?;

    Ok(header)
}

/// MFT 레코드 내부의 속성(Attribute) 리스트를 순회하며 파싱한다.
pub fn parse_attributes(data: &[u8], header: &FileRecordHeader) -> Result<Vec<AttributeHeader>, FactError> {
    let mut attributes = Vec::new();
    // 1. 첫 번째 속성의 위치로 커서 이동
    let mut current_offset = header.attr_offset as usize;

    loop {
        // 안전 장치: 데이터 범위를 벗어나면 중단
        if current_offset + 4 > data.len() {
            break;
        }

        // 2. 현재 위치에서 속성 헤더 파싱
        let mut reader = Cursor::new(&data[current_offset..]);
        let attr_header: AttributeHeader = reader.read_le()
            .map_err(|e| FactError::ParseError {
                artifact_name: "Attribute Header".to_string(),
                details: e.to_string()
            })?;

        // 3. 종료 조건 검사 (0xFFFFFFFF)
        if attr_header.type_code == 0xFFFFFFFF {
            break;
        }

        // 4. 리스트에 추가하고 다음 속성 위치로 점프
        // length가 0이면 무한 루프에 빠지므로 에러 처리
        if attr_header.length == 0 {
            return Err(FactError::ParseError {
                artifact_name: "MFT Attribute".to_string(),
                details: "Attribute length is zero (Corrupted Record)".to_string(),
            });
        }

        attributes.push(attr_header.clone());
        current_offset += attr_header.length as usize;
    }

    Ok(attributes)
}