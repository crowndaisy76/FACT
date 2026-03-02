use models::ntfs::BootSector;
use models::FactError;
use binrw::BinReaderExt;
use std::io::Cursor;

/// 512바이트 Raw Data를 입력받아 NTFS BootSector 구조체로 변환한다.
pub fn parse_boot_sector(data: &[u8]) -> Result<BootSector, FactError> {
    let mut reader = Cursor::new(data);
    
    // binrw의 read_le()를 사용해 리틀 엔디안으로 자동 파싱
    let boot_sector: BootSector = reader.read_le()
        .map_err(|e| FactError::ParseError { 
            artifact_name: "NTFS Boot Sector".to_string(), 
            details: e.to_string() 
        })?;

    Ok(boot_sector)
}