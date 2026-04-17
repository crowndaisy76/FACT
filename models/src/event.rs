use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub file_path: String,
    pub command_line: String,
    pub parent_process_name: String,
    pub run_count: u32,
    pub referenced_files: Vec<String>,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEvent {
    pub timestamp: DateTime<Utc>,
    pub persistence_type: String,
    pub target_name: String,
    pub target_path: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonEvent {
    pub timestamp: DateTime<Utc>,
    pub event_id: u32,
    pub account_name: String,
    pub logon_type: u32,
    pub source_ip: Option<String>,
    pub status: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub timestamp: DateTime<Utc>,
    pub activity_type: String,
    pub description: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemEvent {
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub reason: String,
    pub is_dir: bool,
    // [추가] 타임스톰핑 탐지를 위한 정밀 시간 기록 필드
    pub si_mtime: Option<DateTime<Utc>>, 
    pub fn_mtime: Option<DateTime<Utc>>, 
    pub is_timestomped: bool,            
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForensicEvent {
    Execution(ExecutionEvent),
    NetworkActivity(NetworkEvent),
    Persistence(PersistenceEvent),
    Logon(LogonEvent),
    SystemActivity(SystemEvent),
    FileSystemActivity(FileSystemEvent),
}