pub mod prefetch;
pub mod registry;
pub mod evtx;
pub mod usnjrnl;
pub mod amcache;
pub mod tasks;
pub mod ntuser;
pub mod preprocess; // [추가] 전처리기 모듈
pub mod correlation;
pub mod stix;

use anyhow::Result;
use models::event::ForensicEvent;
use models::artifact::ArtifactTarget;
use prefetch::PrefetchAnalyzer;
use registry::RegistryAnalyzer;
use evtx::EvtxAnalyzer;
use usnjrnl::UsnJrnlAnalyzer;
use amcache::AmcacheAnalyzer;
use tasks::TaskAnalyzer;
use ntuser::NtUserAnalyzer;

pub use preprocess::Preprocessor; // [추가]
pub use correlation::{CorrelationEngine, TimelineEntry};
pub use stix::StixBuilder;

pub trait ArtifactAnalyzer {
    fn analyze(&self, filename: &str, data: &[u8]) -> Result<Vec<ForensicEvent>>;
    fn can_handle(&self, target: &ArtifactTarget) -> bool;
}

pub struct AnalysisEngine {
    analyzers: Vec<Box<dyn ArtifactAnalyzer>>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        let mut analyzers: Vec<Box<dyn ArtifactAnalyzer>> = Vec::new();
        analyzers.push(Box::new(PrefetchAnalyzer::new()));
        analyzers.push(Box::new(RegistryAnalyzer::new()));
        analyzers.push(Box::new(EvtxAnalyzer::new()));
        analyzers.push(Box::new(UsnJrnlAnalyzer::new()));
        analyzers.push(Box::new(AmcacheAnalyzer::new()));
        analyzers.push(Box::new(TaskAnalyzer::new()));
        analyzers.push(Box::new(NtUserAnalyzer::new()));
        Self { analyzers }
    }

    pub fn process_stream(&self, target: &ArtifactTarget, filename: &str, data: &[u8]) -> Vec<ForensicEvent> {
        let mut results = Vec::new();
        for analyzer in &self.analyzers {
            if analyzer.can_handle(target) {
                if let Ok(mut events) = analyzer.analyze(filename, data) {
                    results.append(&mut events);
                }
            }
        }
        results
    }
}