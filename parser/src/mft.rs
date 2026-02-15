use models::mft::{
    FileRecordHeader, AttributeHeader, NonResidentAttributeHeader, 
    DataRun, StandardInformation, FileNameAttribute, 
    IndexRootAttribute, IndexEntry, IndexRecordHeader
};
use models::FactError;
use binrw::BinReaderExt;
use std::io::{Cursor, Read};

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

/// MFT 레코드 내부의 속성(Attribute) 리스트를 순회하며 파싱
pub fn parse_attributes(data: &[u8], header: &FileRecordHeader) -> Result<Vec<AttributeHeader>, FactError> {
    let mut attributes = Vec::new();
    let mut current_offset = header.attr_offset as usize;

    loop {
        if current_offset + 4 > data.len() { break; }

        let mut reader = Cursor::new(&data[current_offset..]);
        let attr_header: AttributeHeader = reader.read_le()
            .map_err(|e| FactError::ParseError {
                artifact_name: "Attribute Header".to_string(),
                details: e.to_string()
            })?;

        if attr_header.type_code == 0xFFFFFFFF { break; }
        if attr_header.length == 0 {
            return Err(FactError::ParseError {
                artifact_name: "MFT Attribute".to_string(),
                details: "Attribute length is zero".to_string(),
            });
        }

        attributes.push(attr_header.clone());
        current_offset += attr_header.length as usize;
    }
    Ok(attributes)
}

/// Non-Resident 속성 헤더 파싱
pub fn parse_non_resident_header(data: &[u8]) -> Result<NonResidentAttributeHeader, FactError> {
    if data.len() < 16 {
        return Err(FactError::ParseError {
            artifact_name: "Non-Resident Header".to_string(),
            details: "Data too short".to_string(),
        });
    }
    let mut reader = Cursor::new(&data[16..]);
    let header: NonResidentAttributeHeader = reader.read_le()
        .map_err(|e| FactError::ParseError {
            artifact_name: "Non-Resident Attribute Header".to_string(),
            details: e.to_string()
        })?;
    Ok(header)
}

/// Runlist 파싱
pub fn parse_runlist(data: &[u8]) -> Result<Vec<DataRun>, FactError> {
    let mut runs = Vec::new();
    let mut cursor = 0;
    let mut current_lcn: i64 = 0;

    while cursor < data.len() {
        let header = data[cursor];
        cursor += 1;
        if header == 0 { break; }

        let len_byte_count = (header & 0x0F) as usize;
        let offset_byte_count = ((header >> 4) & 0x0F) as usize;

        if cursor + len_byte_count + offset_byte_count > data.len() {
            return Err(FactError::ParseError {
                artifact_name: "Runlist".to_string(),
                details: "Runlist out of bounds".to_string(),
            });
        }

        let mut length: u64 = 0;
        for i in 0..len_byte_count {
            length |= (data[cursor + i] as u64) << (i * 8);
        }
        cursor += len_byte_count;

        let mut offset: i64 = 0;
        if offset_byte_count > 0 {
            for i in 0..offset_byte_count {
                offset |= (data[cursor + i] as i64) << (i * 8);
            }
            let sign_bit = 1 << (offset_byte_count * 8 - 1);
            if (offset & sign_bit) != 0 {
                offset |= !((1 << (offset_byte_count * 8)) - 1);
            }
        }
        cursor += offset_byte_count;
        current_lcn += offset;

        runs.push(DataRun {
            start_lcn: current_lcn as u64,
            length,
        });
    }
    Ok(runs)
}

/// $STANDARD_INFORMATION 파싱
pub fn parse_standard_information(data: &[u8]) -> Result<StandardInformation, FactError> {
    let mut reader = Cursor::new(data);
    let info: StandardInformation = reader.read_le()
        .map_err(|e| FactError::ParseError {
            artifact_name: "Standard Information".to_string(),
            details: e.to_string()
        })?;
    Ok(info)
}

/// $FILE_NAME 파싱
pub fn parse_file_name(data: &[u8]) -> Result<FileNameAttribute, FactError> {
    let mut reader = Cursor::new(data);
    
    let mut buf_8 = [0u8; 8];
    reader.read_exact(&mut buf_8).map_err(|e| FactError::ParseError { artifact_name: "FileName".to_string(), details: e.to_string() })?;
    let parent_directory = u64::from_le_bytes(buf_8);

    reader.read_exact(&mut buf_8).unwrap(); let creation_time = u64::from_le_bytes(buf_8);
    reader.read_exact(&mut buf_8).unwrap(); let modification_time = u64::from_le_bytes(buf_8);
    reader.read_exact(&mut buf_8).unwrap(); let mft_modified_time = u64::from_le_bytes(buf_8);
    reader.read_exact(&mut buf_8).unwrap(); let access_time = u64::from_le_bytes(buf_8);

    reader.read_exact(&mut buf_8).unwrap(); let allocated_size = u64::from_le_bytes(buf_8);
    reader.read_exact(&mut buf_8).unwrap(); let real_size = u64::from_le_bytes(buf_8);

    let mut buf_4 = [0u8; 4];
    reader.read_exact(&mut buf_4).unwrap(); let flags = u32::from_le_bytes(buf_4);
    reader.read_exact(&mut buf_4).unwrap(); // Skip

    let mut buf_1 = [0u8; 1];
    reader.read_exact(&mut buf_1).unwrap(); let name_length = buf_1[0];
    reader.read_exact(&mut buf_1).unwrap(); let namespace = buf_1[0];

    let name_bytes_len = (name_length as usize) * 2;
    let mut name_bytes = vec![0u8; name_bytes_len];
    reader.read_exact(&mut name_bytes).map_err(|e| FactError::ParseError { 
        artifact_name: "FileName String".to_string(), 
        details: e.to_string() 
    })?;

    let u16_vec: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let name = String::from_utf16_lossy(&u16_vec);

    Ok(FileNameAttribute {
        parent_directory, creation_time, modification_time, mft_modified_time,
        access_time, allocated_size, real_size, flags, name_length, namespace, name,
    })
}

/// $INDEX_ROOT 파싱
pub fn parse_index_root(data: &[u8]) -> Result<IndexRootAttribute, FactError> {
    let mut reader = Cursor::new(data);
    let root: IndexRootAttribute = reader.read_le()
        .map_err(|e| FactError::ParseError {
            artifact_name: "Index Root".to_string(),
            details: e.to_string()
        })?;
    Ok(root)
}

/// 인덱스 엔트리 리스트 파싱
pub fn parse_index_entries(data: &[u8]) -> Result<Vec<IndexEntry>, FactError> {
    let mut entries = Vec::new();
    let mut cursor = 0;

    loop {
        // 안전 장치: 최소 헤더 크기(16바이트) 체크
        if cursor + 16 > data.len() {
            break;
        }

        // 1. 엔트리 헤더 읽기 (수동 파싱)
        let file_ref_bytes: [u8; 8] = data[cursor..cursor+8].try_into().unwrap();
        let file_reference = u64::from_le_bytes(file_ref_bytes) & 0x0000FFFFFFFFFFFF; 

        let length = u16::from_le_bytes([data[cursor+8], data[cursor+9]]);
        let stream_length = u16::from_le_bytes([data[cursor+10], data[cursor+11]]);
        let flags = data[cursor+12];

        // 2. 종료 조건
        // Last Entry(0x02)는 자식 노드가 있으면 중요하지만, 여기서는 이름 파싱이 목적이므로
        // Stream length가 없으면 패스
        if length == 0 {
            break;
        }

        // 3. 파일 이름 파싱
        let mut filename = String::new();
        if stream_length > 0 {
            let fn_base = cursor + 16;
            if fn_base + 66 <= data.len() {
                let name_len = data[fn_base + 64] as usize;
                let name_start = fn_base + 66;
                let name_end = name_start + (name_len * 2);

                if name_end <= data.len() {
                    let name_bytes = &data[name_start..name_end];
                     let u16_vec: Vec<u16> = name_bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    filename = String::from_utf16_lossy(&u16_vec);
                }
            }
        }

        if !filename.is_empty() {
             entries.push(IndexEntry {
                file_reference,
                length,
                stream_length,
                flags,
                filename,
            });
        } else if flags & 0x02 != 0 {
            // Last Entry라도 루프 종료를 위해 처리가 필요할 수 있음
            // 하지만 리스트 생성 관점에선 무시
        }

        cursor += length as usize;
    }

    Ok(entries)
}

/// [Step 16 추가] 인덱스 레코드(4KB INDX Block) 파싱
pub fn parse_index_record(data: &[u8]) -> Result<Vec<IndexEntry>, FactError> {
    // 1. 데이터 복사 (Fixup을 위해 가변 데이터 필요)
    let mut fixup_data = data.to_vec();
    
    // 2. 헤더 파싱 ("INDX")
    let mut reader = Cursor::new(&fixup_data);
    let record_header: IndexRecordHeader = reader.read_le()
        .map_err(|e| FactError::ParseError {
            artifact_name: "Index Record".to_string(),
            details: e.to_string()
        })?;

    if record_header.signature != "INDX" {
        return Ok(Vec::new());
    }

    // 3. [Fix] USA(Update Sequence Array) 적용
    // 데이터 무결성을 위해 섹터 끝부분을 복구한다.
    apply_usa(&mut fixup_data, record_header.usa_offset, record_header.usa_count)?;

    // 4. 엔트리 파싱 (복구된 데이터 사용)
    let entries_start = 24 + record_header.header.first_entry_offset as usize;
    let entries_end = 24 + record_header.header.total_size_of_entries as usize;

    if entries_start < fixup_data.len() && entries_end <= fixup_data.len() {
        let entries_data = &fixup_data[entries_start..entries_end];
        return parse_index_entries(entries_data);
    }

    Ok(Vec::new())
}

// --- [신규] USA (Fixup) 적용 함수 ---
fn apply_usa(data: &mut [u8], usa_offset: u16, usa_count: u16) -> Result<(), FactError> {
    // USA 구조: [Update Sequence Number(2bytes)] + [Sector Array(2bytes * N)]
    let usa_start = usa_offset as usize;
    let usa_end = usa_start + (usa_count as usize * 2);

    if usa_end > data.len() {
        return Ok(()); // 범위 벗어나면 무시 (혹은 에러)
    }

    // 1. Update Sequence Number 읽기
    let update_seq_num = [data[usa_start], data[usa_start+1]];
    
    // 2. 각 섹터(512바이트) 끝부분 복구
    // usa_count에는 Update Sequence Number 자체도 포함되므로, 실제 섹터 수는 count - 1
    let sector_count = usa_count as usize - 1;
    let sector_size = 512;

    for i in 0..sector_count {
        let sector_end = (i + 1) * sector_size - 2; // 섹터의 마지막 2바이트 위치
        let fixup_idx = usa_start + 2 + (i * 2); // 대체할 원본 값이 있는 USA 배열 위치

        if sector_end + 2 > data.len() || fixup_idx + 2 > data.len() {
            break;
        }

        // 검증: 섹터 끝 값이 Update Sequence Number와 같은지 확인
        if data[sector_end] == update_seq_num[0] && data[sector_end+1] == update_seq_num[1] {
            // 복구: USA 배열에 있는 원본 값으로 덮어씀
            data[sector_end] = data[fixup_idx];
            data[sector_end+1] = data[fixup_idx+1];
        }
    }

    Ok(())
}