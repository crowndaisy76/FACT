use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForensicEvent {
    Execution(ExecutionEvent),
    FileSystemActivity(FileSystemEvent),
    Persistence(PersistenceEvent),
    NetworkActivity(NetworkEvent),
    Logon(LogonEvent),
    SystemActivity(SystemEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub process_id: u32,             // Step 4: 프로세스 ID 추가
    pub parent_process_id: u32,      // Step 4: 부모 프로세스 ID 추가
    pub file_path: String,
    pub command_line: String,
    pub parent_process_name: String,
    pub run_count: u32,
    pub referenced_files: Vec<String>,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemEvent {
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub file_path: String,
    pub activity_type: String, 
    pub is_timestomped: bool,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEvent {
    pub timestamp: DateTime<Utc>,
    pub persistence_type: String, 
    pub target_name: String,         // 파서 호환성을 위한 필드
    pub target_path: String,
    pub payload: String,
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
pub struct LogonEvent {
    pub timestamp: DateTime<Utc>,
    pub user_name: String,
    pub logon_type: u32,
    pub source_ip: String,
    pub source_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub timestamp: DateTime<Utc>,
    pub activity_type: String,
    pub description: String,
    pub source_artifact: String,
}