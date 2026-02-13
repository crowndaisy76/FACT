use windows::core::{Result, PCWSTR};
use windows::Win32::Foundation::{HANDLE, CloseHandle, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, LUID_AND_ATTRIBUTES,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 지정된 권한(Privilege)을 현재 프로세스 토큰에 강제로 부여한다.
/// 포렌식을 위한 SeBackupPrivilege 및 SeDebugPrivilege 확보에 사용된다.
pub fn enable_privilege(privilege_name: PCWSTR) -> Result<()> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        
        // 1. 현재 프로세스의 토큰을 열어 권한 변경(ADJUST) 및 조회(QUERY) 핸들을 얻는다.
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        // 2. 시스템에서 해당 권한 이름에 매핑되는 고유 식별자(LUID)를 찾는다.
        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut luid)?;

        // 3. 획득한 LUID에 '활성화(SE_PRIVILEGE_ENABLED)' 속성을 부여하여 구조체를 세팅한다.
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // 4. 조작된 토큰 구조체를 현재 프로세스에 덮어씌운다.
        AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None)?;

        // 5. 메모리 누수를 막기 위해 핸들을 닫는다.
        CloseHandle(token)?;
    }
    Ok(())
}