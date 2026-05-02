use windows::core::{Result, PCWSTR};
use windows::Win32::Foundation::{HANDLE, CloseHandle, LUID, GetLastError, ERROR_NOT_ALL_ASSIGNED};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, LUID_AND_ATTRIBUTES,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn enable_privilege(privilege_name: PCWSTR) -> Result<()> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut luid)?;

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // API 호출
        AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None)?;

        // [핵심 수정] API가 성공(TRUE)했더라도, 실제로 권한이 부여됐는지 확인해야 함.
        // 만약 관리자 권한이 없는 상태라면 여기서 ERROR_NOT_ALL_ASSIGNED가 리턴됨.
        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            CloseHandle(token)?;
            return Err(windows::core::Error::from(ERROR_NOT_ALL_ASSIGNED));
        }

        CloseHandle(token)?;
    }
    Ok(())
}