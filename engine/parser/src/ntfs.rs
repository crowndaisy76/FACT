use models::ntfs::BootSector; // 경로 수정 (mft -> ntfs)
use models::error::FactError; // FactResult 제거
use binrw::{BinReaderExt, Error as BinrwError};
use std::io::Cursor;

// 반환 타입을 표준 Result와 커스텀 FactError로 명시적 선언
pub fn parse_boot_sector(data: &[u8]) -> Result<BootSector, FactError> {
    if data.len() < 512 {
        return Err(FactError::ParseError {
            artifact_name: "NTFS Boot Sector".to_string(),
            details: "Data too small to be a valid boot sector".to_string(),
        });
    }

    let mut reader = Cursor::new(data);
    
    let boot_sector: BootSector = reader.read_le()
        .map_err(|e: BinrwError| FactError::ParseError {
            artifact_name: "NTFS Boot Sector".to_string(),
            details: e.to_string(),
        })?;

    Ok(boot_sector)
}