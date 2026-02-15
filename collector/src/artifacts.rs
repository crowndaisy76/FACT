use crate::mft::MftReader;
use anyhow::{Result, Context};
use parser::mft::{parse_file_record_header, parse_attributes, parse_non_resident_header, parse_runlist};

/// 침해사고 분석을 위한 핵심 아티팩트 목록
#[derive(Debug, Clone)]
pub enum ArtifactTarget {
    // 1. Fixed Index Files
    MFT, MFTMirr, LogFile, Volume, AttrDef, RootDirectory, Bitmap, Boot, BadClus, Secure, UpCase, Extend,

    // 2. Path Based Files (Step 17 Unlocked!)
    RegistrySAM,      // Windows\System32\config\SAM
    RegistrySYSTEM,   // Windows\System32\config\SYSTEM
    RegistrySECURITY, // Windows\System32\config\SECURITY
    RegistrySOFTWARE, // Windows\System32\config\SOFTWARE
}

impl ArtifactTarget {
    /// 아티팩트가 고정 인덱스인지, 경로 기반인지 구분
    pub fn get_type(&self) -> TargetType {
        match self {
            Self::MFT | Self::MFTMirr | Self::LogFile | Self::Volume | 
            Self::AttrDef | Self::RootDirectory | Self::Bitmap | Self::Boot | 
            Self::BadClus | Self::Secure | Self::UpCase | Self::Extend => TargetType::Index,
            
            _ => TargetType::Path,
        }
    }

    pub fn get_index(&self) -> Option<u64> {
        match self {
            Self::MFT => Some(0),
            Self::MFTMirr => Some(1),
            Self::LogFile => Some(2),
            Self::Volume => Some(3),
            Self::AttrDef => Some(4),
            Self::RootDirectory => Some(5),
            Self::Bitmap => Some(6),
            Self::Boot => Some(7),
            Self::BadClus => Some(8),
            Self::Secure => Some(9),
            Self::UpCase => Some(10),
            Self::Extend => Some(11),
            _ => None,
        }
    }

    pub fn get_path(&self) -> Option<&str> {
        match self {
            Self::RegistrySAM => Some("Windows\\System32\\config\\SAM"),
            Self::RegistrySYSTEM => Some("Windows\\System32\\config\\SYSTEM"),
            Self::RegistrySECURITY => Some("Windows\\System32\\config\\SECURITY"),
            Self::RegistrySOFTWARE => Some("Windows\\System32\\config\\SOFTWARE"),
            _ => None,
        }
    }
}

pub enum TargetType {
    Index,
    Path,
}

pub struct ForensicCollector {
    reader: MftReader,
}

impl ForensicCollector {
    pub fn new(reader: MftReader) -> Self {
        Self { reader }
    }

    pub fn collect(&mut self, target: ArtifactTarget) -> Result<Vec<u8>> {
        // 1. 타겟에 따른 Inode(MFT Index) 결정
        let index = match target.get_type() {
            TargetType::Index => target.get_index().unwrap(),
            TargetType::Path => {
                let path = target.get_path().unwrap();
                self.reader.get_inode_by_path(path)
                    .context(format!("Failed to resolve path: {}", path))?
            }
        };
        
        // 2. 레코드 읽기
        let record_data = self.reader.read_record(index)
            .context(format!("Failed to read MFT record for index {}", index))?;

        // 3. 데이터 추출 (Resident/Non-Resident)
        let header = parse_file_record_header(&record_data)?;
        let attributes = parse_attributes(&record_data, &header)?;

        let mut current_offset = header.attr_offset as usize;

        for attr in attributes {
            if attr.type_code == 0x80 { // $DATA
                if attr.non_resident_flag == 0 {
                    // Resident
                    let content_start = current_offset + 24; 
                    let content_end = current_offset + attr.length as usize;
                    if content_end <= record_data.len() {
                        return Ok(record_data[content_start..content_end].to_vec());
                    }
                } else {
                    // Non-Resident
                    let attr_data = &record_data[current_offset..current_offset + attr.length as usize];
                    let nr_header = parse_non_resident_header(attr_data)?;
                    let runlist_offset = nr_header.run_array_offset as usize;
                    let runlist = parse_runlist(&attr_data[runlist_offset..])?;

                    // 레지스트리 하이브는 100MB를 넘지 않음. 안전하게 제한.
                    let limit = std::cmp::min(nr_header.real_size, 100 * 1024 * 1024);
                    return self.reader.read_data_from_runlist(&runlist, limit);
                }
            }
            current_offset += attr.length as usize;
        }

        Ok(Vec::new()) 
    }
}