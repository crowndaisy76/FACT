use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use models::mft::StandardInformation;

// Windows 10/11 전용 XPRESS Huffman 압축 해제를 위한 NTDLL Native API 바인딩
#[link(name = "ntdll")]
unsafe extern "system" {
    // 압축 해제에 필요한 WorkSpace(작업 공간) 크기를 커널에 질의
    fn RtlGetCompressionWorkSpaceSize(
        CompressionFormatAndEngine: u16,
        CompressBufferWorkSpaceSize: *mut u32,
        CompressFragmentWorkSpaceSize: *mut u32,
    ) -> i32;

    // WorkSpace 버퍼를 주입받아 최신 XPRESS Huffman 압축 해제 수행
    fn RtlDecompressBufferEx(
        CompressionFormat: u16,
        UncompressedBuffer: *mut u8,
        UncompressedBufferSize: u32,
        CompressedBuffer: *const u8,
        CompressedBufferSize: u32,
        FinalUncompressedSize: *mut u32,
        WorkSpace: *mut u8,
    ) -> i32;
}

#[derive(Debug, Clone)]
pub struct PrefetchInfo {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
}

/// MAM 압축 해제 로직 (Ex 버전 API 및 체크섬 변종 대응)
fn decompress_mam(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 {
        bail!("Data too small for MAM header");
    }

    let mut compression_format = data[3] as u16;
    
    // MS의 숨겨진 변종: 0x84인 경우 CRC32 체크섬(4바이트)이 추가로 붙어있음
    let has_checksum = (compression_format & 0x80) != 0;
    compression_format &= 0x7F; // 0x84 -> 0x04 (COMPRESSION_FORMAT_XPRESS_HUFF) 로 마스킹

    let uncompressed_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
    
    // 체크섬 존재 여부에 따른 압축 데이터 시작 오프셋 계산
    let compressed_data_offset = if has_checksum { 12 } else { 8 };
    if data.len() < compressed_data_offset {
        bail!("Data truncated before compressed payload");
    }

    let mut comp_ws_size = 0u32;
    let mut decomp_ws_size = 0u32;

    // 커널에 WorkSpace 크기 질의
    let status_ws = unsafe {
        RtlGetCompressionWorkSpaceSize(
            compression_format,
            &mut comp_ws_size,
            &mut decomp_ws_size,
        )
    };

    if status_ws < 0 {
        bail!("RtlGetCompressionWorkSpaceSize failed with NTSTATUS: {:#X}", status_ws);
    }

    // 커널이 요구한 크기만큼 WorkSpace 메모리 할당
    let mut workspace = vec![0u8; decomp_ws_size as usize];
    let mut uncompressed_buffer = vec![0u8; uncompressed_size as usize];
    let mut final_size = 0u32;
    
    // 실제 압축 해제 API 호출
    let status = unsafe {
        RtlDecompressBufferEx(
            compression_format,
            uncompressed_buffer.as_mut_ptr(),
            uncompressed_size,
            data[compressed_data_offset..].as_ptr(),
            (data.len() - compressed_data_offset) as u32,
            &mut final_size,
            workspace.as_mut_ptr(),
        )
    };
    
    if status >= 0 { // NT_SUCCESS
        uncompressed_buffer.truncate(final_size as usize);
        Ok(uncompressed_buffer)
    } else {
        bail!("RtlDecompressBufferEx failed with NTSTATUS: {:#X}", status);
    }
}

/// Prefetch 바이너리 구조를 파싱하여 핵심 실행 지표만 추출한다.
pub fn parse_prefetch_info(data: &[u8]) -> Result<PrefetchInfo> {
    if data.len() < 8 {
        bail!("Prefetch data too small");
    }

    let signature = &data[0..4];
    let decompressed_data;
    
    // 데이터가 MAM으로 시작하면 즉시 메모리상에서 압축 해제 처리
    let working_data = if signature.starts_with(b"MAM") {
        decompressed_data = decompress_mam(data)?;
        &decompressed_data
    } else {
        data
    };

    if working_data.len() < 84 {
        bail!("Decompressed Prefetch data too small");
    }

    // Offset 0~3: 윈도우 프리패치 버전
    let version = u32::from_le_bytes(working_data[0..4].try_into().unwrap());
    
    // Offset 4~7: 실제 프리패치 시그니처 (SCCA) 확인
    let sig = &working_data[4..8];
    if sig != b"SCCA" {
        bail!("Invalid decompressed signature: {:?}", String::from_utf8_lossy(sig));
    }

    // 윈도우 버전에 따른 타겟 데이터 절대 오프셋 매핑
    let (times_offset, run_count_offset, num_times) = match version {
        23 => (0x78, 0x90, 1),       // Windows Vista / 7
        26 => (0x80, 0x98, 8),       // Windows 8 / 8.1
        30 | 31 => (0x80, 0xD0, 8),  // Windows 10 / 11
        _ => bail!("Unsupported Prefetch version: {}", version),
    };

    // Executable Name (Offset 16부터 최대 60바이트, UTF16-LE)
    let name_bytes = &working_data[16..76];
    let u16_name: Vec<u16> = name_bytes.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0) 
        .collect();
    let executable_name = String::from_utf16_lossy(&u16_name);

    if working_data.len() < run_count_offset + 4 {
        bail!("Data truncated before run count");
    }

    // Run Count 추출
    let run_count = u32::from_le_bytes(working_data[run_count_offset..run_count_offset+4].try_into().unwrap());

    // Last Run Times 추출
    let mut last_run_times = Vec::new();
    for i in 0..num_times {
        let current_time_offset = times_offset + (i * 8);
        if current_time_offset + 8 <= working_data.len() {
            let filetime = u64::from_le_bytes(working_data[current_time_offset..current_time_offset+8].try_into().unwrap());
            if filetime > 0 {
                last_run_times.push(StandardInformation::to_datetime(filetime));
            }
        }
    }

    Ok(PrefetchInfo {
        executable_name,
        run_count,
        last_run_times,
    })
}