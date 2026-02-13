use chrono::{DateTime, Utc};
use crate::error::FactError;

/// 모든 포렌식 아티팩트 파서가 반드시 구현해야 하는 표준 인터페이스
pub trait Artifact {
    /// 아티팩트의 고유 분류명 반환 (예: "Prefetch", "USN_Journal")
    fn name(&self) -> &str;
    
    /// 아티팩트에서 추출된 핵심 타임스탬프 (UTC 기준)
    /// (Timeline 정렬의 기준값이 됨)
    fn timestamp(&self) -> DateTime<Utc>;
    
    /// 프로세스 ID (PID) 매핑이 가능한 경우 반환
    /// (메모리, 네트워크 이벤트 등에서 논리적 상관관계 추론 시 사용)
    fn pid(&self) -> Option<u32>;
    
    /// 분석된 결과를 STIX 2.1 JSON 규격의 문자열로 변환
    fn to_stix(&self) -> Result<String, FactError>;
}