use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use models::mft::StandardInformation;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine: u16, CompressBufferWorkSpaceSize: *mut u32, CompressFragmentWorkSpaceSize: *mut u32) -> i32;
    fn RtlDecompressBufferEx(CompressionFormat: u16, UncompressedBuffer: *mut u8, UncompressedBufferSize: u32, CompressedBuffer: *const u8, CompressedBufferSize: u32, FinalUncompressedSize: *mut u32, WorkSpace: *mut u8) -> i32;
}

#[derive(Debug, Clone)]
pub struct PrefetchInfo {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub referenced_files: Vec<String>,
}

fn decompress_mam(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 { bail!("Data too small"); }
    let mut compression_format = data[3] as u16;
    let has_checksum = (compression_format & 0x80) != 0;
    compression_format &= 0x7F;

    let uncompressed_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let compressed_data_offset = if has_checksum { 12 } else { 8 };
    if data.len() < compressed_data_offset { bail!("Truncated"); }

    let (mut comp_ws_size, mut decomp_ws_size) = (0u32, 0u32);
    let status_ws = unsafe { RtlGetCompressionWorkSpaceSize(compression_format, &mut comp_ws_size, &mut decomp_ws_size) };
    if status_ws < 0 { bail!("NTSTATUS: {:#X}", status_ws); }

    let mut workspace = vec![0u8; decomp_ws_size as usize];
    let mut uncompressed_buffer = vec![0u8; uncompressed_size as usize];
    let mut final_size = 0u32;

    let status = unsafe { RtlDecompressBufferEx(compression_format, uncompressed_buffer.as_mut_ptr(), uncompressed_size, data[compressed_data_offset..].as_ptr(), (data.len() - compressed_data_offset) as u32, &mut final_size, workspace.as_mut_ptr()) };
    if status >= 0 {
        uncompressed_buffer.truncate(final_size as usize);
        Ok(uncompressed_buffer)
    } else { bail!("NTSTATUS: {:#X}", status); }
}

pub fn parse_prefetch_info(data: &[u8]) -> Result<PrefetchInfo> {
    if data.len() < 8 { bail!("Too small"); }
    let decompressed_data;
    let working_data = if data[0..4].starts_with(b"MAM") {
        decompressed_data = decompress_mam(data)?;
        &decompressed_data
    } else { data };

    if working_data.len() < 84 { bail!("Decompressed too small"); }
    let version = u32::from_le_bytes(working_data[0..4].try_into().unwrap());
    if &working_data[4..8] != b"SCCA" { bail!("Invalid signature"); }

    let (times_offset, run_count_offset, num_times) = match version {
        23 => (0x78, 0x90, 1),
        26 => (0x80, 0x98, 8),
        30 | 31 => (0x80, 0xD0, 8),
        _ => bail!("Unsupported version"),
    };

    // [최적화 1] Executable Name 파싱: 불필요한 배열 생성 최소화
    let name_bytes = &working_data[16..76];
    let mut name_end = 0;
    while name_end + 1 < name_bytes.len() && (name_bytes[name_end] != 0 || name_bytes[name_end+1] != 0) {
        name_end += 2;
    }
    let u16_name: Vec<u16> = name_bytes[..name_end].chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let executable_name = String::from_utf16_lossy(&u16_name);
    
    let run_count = u32::from_le_bytes(working_data[run_count_offset..run_count_offset+4].try_into().unwrap());

    let mut last_run_times = Vec::with_capacity(8);
    for i in 0..num_times {
        let offset = times_offset + (i * 8);
        if offset + 8 <= working_data.len() {
            let filetime = u64::from_le_bytes(working_data[offset..offset+8].try_into().unwrap());
            if filetime > 0 { last_run_times.push(StandardInformation::to_datetime(filetime)); }
        }
    }

    // [최적화 2] Referenced Files 파싱: 바이트 단위 슬라이싱 및 ASCII Fast-Path 적용
    let mut referenced_files = Vec::with_capacity(50); // 메모리 재할당 방지용 사전 할당
    let strings_offset = u32::from_le_bytes(working_data[0x64..0x68].try_into().unwrap()) as usize;
    let strings_size = u32::from_le_bytes(working_data[0x68..0x6C].try_into().unwrap()) as usize;

    if strings_offset > 0 && strings_offset + strings_size <= working_data.len() {
        let strings_data = &working_data[strings_offset..strings_offset+strings_size];
        
        let mut start_idx = 0;
        for i in (0..strings_data.len()).step_by(2) {
            // UTF-16 널 터미네이터 (0x00 0x00) 확인
            if i + 1 < strings_data.len() && strings_data[i] == 0 && strings_data[i+1] == 0 {
                if i > start_idx {
                    let slice = &strings_data[start_idx..i];
                    
                    // Windows 프리패치 경로는 대부분 영문이므로 ASCII 고속 변환 시도
                    let mut is_ascii = true;
                    let mut ascii_str = String::with_capacity(slice.len() / 2);
                    
                    for chunk in slice.chunks_exact(2) {
                        if chunk[1] != 0 || chunk[0] < 32 || chunk[0] > 126 {
                            is_ascii = false;
                            break;
                        }
                        ascii_str.push(chunk[0] as char);
                    }

                    if is_ascii {
                        referenced_files.push(ascii_str);
                    } else {
                        // 다국어 경로일 경우에만 무거운 UTF-16 파싱
                        let u16_slice: Vec<u16> = slice.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        referenced_files.push(String::from_utf16_lossy(&u16_slice));
                    }
                }
                start_idx = i + 2; // 다음 문자열 시작점으로 이동
            }
        }
    }

    Ok(PrefetchInfo { executable_name, run_count, last_run_times, referenced_files })
}