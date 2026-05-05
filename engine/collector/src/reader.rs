use std::fs::File;
use std::os::windows::io::FromRawHandle;
use windows::core::{Result, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, FILE_ATTRIBUTE_NORMAL,
    FILE_READ_DATA
};

pub fn open_locked_file(file_path: PCWSTR) -> Result<File> {
    unsafe {
        let handle: HANDLE = CreateFileW(
            file_path,
            FILE_READ_DATA.0, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )?;

        Ok(File::from_raw_handle(handle.0 as _))
    }
}