use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom};
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use parser::ntfs::parse_boot_sector;
use parser::mft::{parse_file_record_header, parse_attributes};

fn main() -> Result<()> {
    // 1. 로깅 초기화
    tracing_subscriber::fmt::init();
    tracing::info!("FACT Engine Initiated.");

    // 2. 권한 상승
    tracing::info!("Requesting SeBackupPrivilege...");
    enable_privilege(w!("SeBackupPrivilege"))
        .context("Failed to acquire SeBackupPrivilege. Are you running as Administrator?")?;
    tracing::info!("Privilege acquired successfully.");

    // 3. Raw Volume 접근
    let volume_path = w!("\\\\.\\C:"); 
    tracing::info!("Opening Raw Volume: \\\\.\\C:");
    
    let mut file = open_locked_file(volume_path)
        .context("Failed to open Raw Volume.")?;
    
    // 4. VBR 파싱
    let mut vbr_buffer = [0u8; 512];
    file.read_exact(&mut vbr_buffer).context("Failed to read VBR.")?;
    let vbr = parse_boot_sector(&vbr_buffer)
        .context("Failed to parse NTFS Boot Sector.")?;
    
    let mft_offset = vbr.mft_offset();
    tracing::info!("Calculated $MFT Offset: {} bytes", mft_offset);

    // 5. $MFT 위치로 이동 (Seek)
    file.seek(SeekFrom::Start(mft_offset))
        .context("Failed to seek to $MFT position.")?;

    // 6. $MFT의 첫 번째 레코드(Entry 0) 읽기
    let mut mft_buffer = [0u8; 1024];
    file.read_exact(&mut mft_buffer).context("Failed to read MFT Entry 0.")?;

    // 7. 파싱 및 검증
    tracing::info!("Parsing MFT Entry 0 (Self-Reference)...");
    let mft_header = parse_file_record_header(&mft_buffer)
        .context("Failed to parse MFT Record.")?;

    tracing::info!("MFT Entry 0 Analysis:");
    tracing::info!("  - Signature: {}", mft_header.signature);
    tracing::info!("  - Flags: {:#04X} (0x01=InUse, 0x02=Directory)", mft_header.flags);
    tracing::info!("  - Used Size: {} bytes", mft_header.bytes_in_use);
    tracing::info!("  - Allocated Size: {} bytes", mft_header.bytes_allocated);

    if mft_header.signature == "FILE" {
        tracing::info!("SUCCESS: Valid NTFS File Record Found!");

        // [Step 6] 속성(Attribute) 순회 및 출력
        tracing::info!("Parsing Attributes...");
        let attributes = parse_attributes(&mft_buffer, &mft_header)
            .context("Failed to parse MFT attributes.")?;

        for (i, attr) in attributes.iter().enumerate() {
            let residency = if attr.non_resident_flag == 0 { "Resident" } else { "Non-Resident" };
            tracing::info!(
                "  [Attr #{}] Type: {} | Length: {} | Storage: {}", 
                i, attr, attr.length, residency
            );
        }

    } else {
        tracing::error!("CRITICAL: Invalid Signature found. Expected 'FILE', got '{}'", mft_header.signature);
    }

    Ok(())
}