#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactTarget {
    MFT,
    Prefetch,
    EventLogs,
    ScheduledTasks,
    Amcache,
    RegistrySOFTWARE,
    RegistrySYSTEM,
    RegistrySAM,
    RegistryNTUSER,
    UsnJrnl,
    RecycleBin,
    USBLog,
    LNK, // 신규 추가
    WMI, // 신규 추가
}

#[derive(Debug, Clone)]
pub enum TargetType {
    SingleFile { path: &'static str },
    Directory { path: &'static str, extension: Option<&'static str>, recursive: bool },
}

impl ArtifactTarget {
    pub fn get_details(&self) -> Vec<TargetType> {
        match self {
            Self::MFT => vec![TargetType::SingleFile { path: "$MFT" }],
            Self::Prefetch => vec![TargetType::Directory { path: "Windows\\Prefetch", extension: Some("pf"), recursive: false }],
            Self::EventLogs => vec![TargetType::Directory { path: "Windows\\System32\\winevt\\Logs", extension: Some("evtx"), recursive: false }],
            Self::ScheduledTasks => vec![TargetType::Directory { path: "Windows\\System32\\Tasks", extension: None, recursive: true }],
            Self::Amcache => vec![TargetType::SingleFile { path: "Windows\\AppCompat\\Programs\\Amcache.hve" }],
            Self::RegistrySOFTWARE => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SOFTWARE" }],
            Self::RegistrySYSTEM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SYSTEM" }],
            Self::RegistrySAM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SAM" }],
            Self::RegistryNTUSER => vec![TargetType::Directory { path: "Users", extension: Some("DAT"), recursive: true }],
            Self::UsnJrnl => vec![TargetType::SingleFile { path: "$Extend\\$UsnJrnl:$J" }],
            Self::RecycleBin => vec![TargetType::Directory { path: "$Recycle.Bin", extension: None, recursive: true }],
            Self::USBLog => vec![TargetType::SingleFile { path: "Windows\\inf\\setupapi.dev.log" }],
            // [신규] 모든 사용자의 바탕화면, 다운로드, 최근 실행 폴더의 바로가기 파일 수집
            Self::LNK => vec![TargetType::Directory { path: "Users", extension: Some("lnk"), recursive: true }],
            // [신규] WMI 리포지토리 수집
            Self::WMI => vec![TargetType::SingleFile { path: "Windows\\System32\\wbem\\Repository\\OBJECTS.DATA" }],
        }
    }
}