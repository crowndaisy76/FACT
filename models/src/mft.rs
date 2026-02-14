use binrw::BinRead;
use std::fmt;

/// NTFS MFT File Record Header (Entry Header)
/// 크기: 표준 1024 bytes (헤더 + 속성 포함)
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct FileRecordHeader {
    // 0x00: "FILE" 시그니처 (4 bytes)
    // 매직 넘버가 "FILE"이면 정상, "BAAD"면 배드 섹터 처리 중 에러 발생을 의미
    #[br(map = |x: [u8; 4]| String::from_utf8_lossy(&x).to_string())]
    pub signature: String, 

    // 0x04: Update Sequence Array (Fixup Array) 오프셋
    pub usa_offset: u16,
    
    // 0x06: Fixup Array 개수
    pub usa_count: u16,

    // 0x08: LogFile Sequence Number ($LogFile 트랜잭션 번호)
    pub lsn: u64,

    // 0x10: Sequence Number (재사용 횟수)
    pub sequence_number: u16,

    // 0x12: Link Count (Hard Link 개수)
    pub link_count: u16,

    // 0x14: First Attribute Offset (첫 번째 속성의 시작 위치)
    pub attr_offset: u16,

    // 0x16: Flags (0x01: In Use, 0x02: Directory)
    pub flags: u16,

    // 0x18: Real Size (실제 사용 중인 크기)
    pub bytes_in_use: u32,

    // 0x1C: Allocated Size (할당된 크기 - 보통 1024)
    pub bytes_allocated: u32,
    
    // 0x20: Base File Record Reference (확장 레코드일 경우 원본 주소)
    pub base_file_record: u64,
    
    // 0x28: Next Attribute ID
    pub next_attr_id: u16,
}

/// NTFS Attribute Common Header (모든 속성의 앞부분)
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct AttributeHeader {
    // 0x00: Attribute Type Code (e.g., 0x10, 0x30, 0x80)
    // 0xFFFFFFFF면 리스트의 끝(End Marker)
    pub type_code: u32,

    // 0x04: Total Length (헤더 + 본문 포함 전체 길이) -> 다음 속성 위치 계산용
    pub length: u32,

    // 0x08: Non-Resident Flag (0x00=Resident, 0x01=Non-Resident)
    // Resident: 데이터가 MFT 안에 있음 (작은 파일)
    // Non-Resident: 데이터가 외부 클러스터에 있음 (큰 파일)
    pub non_resident_flag: u8,

    // 0x09: Name Length (속성 이름 길이, 없으면 0)
    pub name_length: u8,

    // 0x0A: Name Offset (속성 이름 시작 위치)
    pub name_offset: u16,

    // 0x0C: Flags (Compressed, Encrypted, Sparse)
    pub flags: u16,

    // 0x0E: Attribute ID (유니크 식별자)
    pub attribute_id: u16,
}

/// 속성 타입을 보기 좋게 출력하기 위한 Helper
impl fmt::Display for AttributeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.type_code {
            0x10 => "$STANDARD_INFORMATION",
            0x20 => "$ATTRIBUTE_LIST",
            0x30 => "$FILE_NAME",
            0x40 => "$OBJECT_ID",
            0x50 => "$SECURITY_DESCRIPTOR",
            0x60 => "$VOLUME_NAME",
            0x70 => "$VOLUME_INFORMATION",
            0x80 => "$DATA",
            0x90 => "$INDEX_ROOT",
            0xA0 => "$INDEX_ALLOCATION",
            0xB0 => "$BITMAP",
            0xC0 => "$REPARSE_POINT",
            0xFFFFFFFF => "End Marker",
            _ => "Unknown",
        };
        write!(f, "{}({:#X})", name, self.type_code)
    }
}