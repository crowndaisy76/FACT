#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactTarget {
    MFT, LogFile, Amcache,
    RegistrySAM, RegistrySECURITY, RegistrySOFTWARE, RegistrySYSTEM,
    Prefetch, EventLogs, ScheduledTasks, RecycleBin, USBLog
}

pub enum TargetType {
    SingleFile { path: &'static str },
    Directory { path: &'static str, extension: Option<&'static str>, recursive: bool },
}

impl ArtifactTarget {
    pub fn get_details(&self) -> Vec<TargetType> {
        match self {
            Self::MFT => vec![TargetType::SingleFile { path: "$MFT" }],
            Self::LogFile => vec![TargetType::SingleFile { path: "$LogFile" }],
            Self::RegistrySAM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SAM" }],
            Self::RegistrySECURITY => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SECURITY" }],
            Self::RegistrySOFTWARE => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SOFTWARE" }],
            Self::RegistrySYSTEM => vec![TargetType::SingleFile { path: "Windows\\System32\\config\\SYSTEM" }],
            Self::Amcache => vec![TargetType::SingleFile { path: "Windows\\AppCompat\\Programs\\Amcache.hve" }],
            Self::Prefetch => vec![TargetType::Directory { path: "Windows\\Prefetch", extension: Some("pf"), recursive: false }],
            Self::EventLogs => vec![TargetType::Directory { path: "Windows\\System32\\winevt\\Logs", extension: Some("evtx"), recursive: false }],
            Self::USBLog => vec![TargetType::SingleFile { path: "Windows\\inf\\setupapi.dev.log" }],
            Self::ScheduledTasks => vec![TargetType::Directory { path: "Windows\\System32\\Tasks", extension: None, recursive: true }],
            Self::RecycleBin => vec![TargetType::Directory { path: "$Recycle.Bin", extension: None, recursive: true }],
        }
    }
}