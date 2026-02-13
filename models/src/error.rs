use thiserror::Error;

/// FACT 프로젝트 전반에서 사용되는 통합 에러 타입
#[derive(Error, Debug)]
pub enum FactError {
    #[error("I/O Error occurred: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parsing failed for artifact '{artifact_name}': {details}")]
    ParseError { artifact_name: String, details: String },
    
    #[error("Permission denied: Requires Administrator/SYSTEM privileges to access physical drive or memory")]
    PermissionDenied,
    
    #[error("Unsupported artifact format or corrupted data: {0}")]
    UnsupportedFormat(String),
    
    #[error("Database Error: {0}")]
    DatabaseError(String),
}