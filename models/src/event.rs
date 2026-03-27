use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub file_path: String,
    pub run_count: u32,
    pub referenced_files: Vec<String>,
    pub source_artifact: String,
}

#[derive(Debug, Clone)]
pub struct PersistenceEvent {
    pub timestamp: DateTime<Utc>,
    pub persistence_type: String,
    pub target_name: String,
    pub target_path: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone)]
pub struct LogonEvent {
    pub timestamp: DateTime<Utc>,
    pub event_id: u32,
    pub account_name: String,
    pub logon_type: u32,
    pub source_ip: Option<String>,
    pub status: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone)]
pub struct SystemEvent {
    pub timestamp: DateTime<Utc>,
    pub activity_type: String,
    pub description: String,
    pub source_artifact: String,
}

// [New] 파일 생성, 수정, 삭제 이벤트를 담는 구조체
#[derive(Debug, Clone)]
pub struct FileSystemEvent {
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub reason: String,
    pub is_dir: bool,
    pub source_artifact: String,
}

#[derive(Debug, Clone)]
pub enum ForensicEvent {
    Execution(ExecutionEvent),
    Persistence(PersistenceEvent),
    Logon(LogonEvent),
    SystemActivity(SystemEvent),
    FileSystemActivity(FileSystemEvent), // [New]
}