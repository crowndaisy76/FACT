use binrw::BinRead;
use std::fmt;
use chrono::{DateTime, Utc, TimeZone};

/// NTFS MFT File Record Header
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct FileRecordHeader {
    #[br(map = |x: [u8; 4]| String::from_utf8_lossy(&x).to_string())]
    pub signature: String, 
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub sequence_number: u16,
    pub link_count: u16,
    pub attr_offset: u16,
    pub flags: u16,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_file_record: u64,
    pub next_attr_id: u16,
}

/// NTFS Attribute Common Header
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct AttributeHeader {
    pub type_code: u32,
    pub length: u32,
    pub non_resident_flag: u8,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub attribute_id: u16,
}

/// Non-Resident Attribute Header
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct NonResidentAttributeHeader {
    pub starting_vcn: u64,
    pub last_vcn: u64,
    pub run_array_offset: u16,
    pub compression_unit: u16,
    #[br(pad_before = 4)] 
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_size: u64,
}

/// Runlist Data
#[derive(Debug, Clone)]
pub struct DataRun {
    pub start_lcn: u64,
    pub length: u64,
}

/// $STANDARD_INFORMATION (0x10)
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct StandardInformation {
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modified_time: u64,
    pub access_time: u64,
    pub file_flags: u32,
    pub max_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
}

impl StandardInformation {
    pub fn to_datetime(filetime: u64) -> DateTime<Utc> {
        const EPOCH_DIFFERENCE: i64 = 11_644_473_600;
        let seconds = (filetime / 10_000_000) as i64;
        let nanoseconds = ((filetime % 10_000_000) * 100) as u32;

        if seconds >= EPOCH_DIFFERENCE {
            Utc.timestamp_opt(seconds - EPOCH_DIFFERENCE, nanoseconds).unwrap()
        } else {
            Utc.timestamp_opt(0, 0).unwrap()
        }
    }
}

/// $FILE_NAME (0x30)
#[derive(Debug, Clone)]
pub struct FileNameAttribute {
    pub parent_directory: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modified_time: u64,
    pub access_time: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub name_length: u8,
    pub namespace: u8,
    pub name: String,
}

/// Index Header (Node Header) - Directory Entry 공통 헤더
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct IndexHeader {
    pub first_entry_offset: u32,  // 첫 번째 엔트리 위치
    pub total_size_of_entries: u32, // 전체 엔트리 크기
    pub allocated_size: u32,      // 할당된 크기
    pub flags: u8,                // 0x00=Small(Leaf), 0x01=Large(Node)
    #[br(pad_before = 3)]         // Padding
    pub _padding: (),
}

/// $INDEX_ROOT (0x90) Attribute Header
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct IndexRootAttribute {
    pub attribute_type: u32,      // 보통 0x30 ($FILE_NAME)
    pub collation_rule: u32,
    pub index_allocation_size: u32,
    pub clusters_per_index_record: u8,
    #[br(pad_before = 3)]
    pub header: IndexHeader,      // 내부에 IndexHeader 포함
}

/// Index Entry (디렉토리 내부 파일 정보)
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub file_reference: u64,      // 자식 파일의 MFT 번호
    pub length: u16,              // 엔트리 전체 길이
    pub stream_length: u16,
    pub flags: u8,                // 0x02=Last Entry
    pub filename: String,         // 파일 이름
}

/// [Step 16 추가] Index Record Header ("INDX" 4KB Block Header)
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct IndexRecordHeader {
    #[br(map = |x: [u8; 4]| String::from_utf8_lossy(&x).to_string())]
    pub signature: String, // "INDX"
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub vcn: u64,          // 이 블록의 가상 클러스터 번호
    pub header: IndexHeader, // 내부에 Node Header 포함
}

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