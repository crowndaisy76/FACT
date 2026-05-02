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

    let u16_name: Vec<u16> = working_data[16..76].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    let executable_name = String::from_utf16_lossy(&u16_name);
    let run_count = u32::from_le_bytes(working_data[run_count_offset..run_count_offset+4].try_into().unwrap());

    let mut last_run_times = Vec::new();
    for i in 0..num_times {
        let offset = times_offset + (i * 8);
        if offset + 8 <= working_data.len() {
            let filetime = u64::from_le_bytes(working_data[offset..offset+8].try_into().unwrap());
            if filetime > 0 { last_run_times.push(StandardInformation::to_datetime(filetime)); }
        }
    }

    // [핵심 교정] Windows 공통 Filename Strings 섹션 오프셋 강제 파싱 (0x64, 0x68)
    let mut referenced_files = Vec::new();
    let strings_offset = u32::from_le_bytes(working_data[0x64..0x68].try_into().unwrap()) as usize;
    let strings_size = u32::from_le_bytes(working_data[0x68..0x6C].try_into().unwrap()) as usize;

    if strings_offset > 0 && strings_offset + strings_size <= working_data.len() {
        let strings_data = &working_data[strings_offset..strings_offset+strings_size];
        let u16_data: Vec<u16> = strings_data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();

        let mut current_string = String::new();
        for &c in &u16_data {
            if c == 0 {
                if !current_string.is_empty() {
                    referenced_files.push(current_string.clone());
                    current_string.clear();
                }
            } else if let Some(ch) = char::from_u32(c as u32) {
                current_string.push(ch);
            }
        }
    }

    Ok(PrefetchInfo { executable_name, run_count, last_run_times, referenced_files })
}