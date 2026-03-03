use chrono::{DateTime, Utc};

/// 침해사고 대응(IR) 관점에서 정규화된 포렌식 이벤트 모델
#[derive(Debug, Clone)]
pub enum ForensicEvent {
    /// 악성코드 및 프로그램 실행 흔적 (Prefetch, Amcache 등)
    Execution(ExecutionEvent),
    /// 자가 실행 및 백도어 지속성 유지 흔적 (Registry Run keys, Scheduled Tasks 등)
    Persistence(PersistenceEvent),
    /// 계정 로그인 및 측면 이동 흔적 (EventLog 4624, 4625 등)
    Logon(LogonEvent),
    /// 기타 시스템 주요 변경 사항
    SystemActivity(SystemEvent),
}

#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub file_path: String,
    pub run_count: u32,
    pub referenced_files: Vec<String>, // 로드된 DLL 등
    pub source_artifact: String,       // 예: "Prefetch"
}

#[derive(Debug, Clone)]
pub struct PersistenceEvent {
    pub timestamp: DateTime<Utc>,
    pub persistence_type: String,      // 예: "Registry Run Key", "Scheduled Task"
    pub target_name: String,           // 레지스트리 값 이름 또는 태스크 이름
    pub target_path: String,           // 자동 실행되는 페이로드 경로
    pub source_artifact: String,       
}

#[derive(Debug, Clone)]
pub struct LogonEvent {
    pub timestamp: DateTime<Utc>,
    pub event_id: u32,
    pub account_name: String,
    pub logon_type: u32,
    pub source_ip: Option<String>,
    pub source_artifact: String,
}

#[derive(Debug, Clone)]
pub struct SystemEvent {
    pub timestamp: DateTime<Utc>,
    pub activity_type: String,
    pub description: String,
    pub source_artifact: String,
}

// 타임라인 정렬을 위한 타임스탬프 추출 인터페이스
impl ForensicEvent {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::Execution(e) => e.timestamp,
            Self::Persistence(e) => e.timestamp,
            Self::Logon(e) => e.timestamp,
            Self::SystemActivity(e) => e.timestamp,
        }
    }
}