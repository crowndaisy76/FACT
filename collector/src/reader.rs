use std::fs::File;
use std::os::windows::io::FromRawHandle;
use windows::core::{Result, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, FILE_ATTRIBUTE_NORMAL,
    FILE_READ_DATA // <== FILE_GENERIC_READ 대신 이것을 사용한다.
};

/// OS 잠금을 우회하여 파일을 강제로 열어 Rust의 File 객체로 반환한다.
/// (호출 전 반드시 SeBackupPrivilege가 활성화되어 있어야 한다)
pub fn open_locked_file(file_path: PCWSTR) -> Result<File> {
    unsafe {
        // FILE_FLAG_BACKUP_SEMANTICS: OS의 잠금을 무시하는 핵심 플래그
        // FILE_READ_DATA (1): 파일의 '내용'만 읽겠다고 명시한다. (Access Denied 방지)
        let handle: HANDLE = CreateFileW(
            file_path,
            FILE_READ_DATA.0, // <== 수정된 부분: 최소한의 권한만 요청
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )?;

        Ok(File::from_raw_handle(handle.0 as _))
    }
}