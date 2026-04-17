pub mod prefetch;
pub mod registry;
pub mod evtx;
pub mod usnjrnl;
pub mod amcache;
pub mod tasks;
pub mod correlation;
pub mod stix; // [New] STIX 모듈 추가

use anyhow::Result;
use models::event::ForensicEvent;
use models::artifact::ArtifactTarget;
use prefetch::PrefetchAnalyzer;
use registry::RegistryAnalyzer;
use evtx::EvtxAnalyzer;
use usnjrnl::UsnJrnlAnalyzer;
use amcache::AmcacheAnalyzer;
use tasks::TasksAnalyzer;

pub use correlation::{CorrelationEngine, TimelineEntry};
pub use stix::StixBuilder; // [New] StixBuilder 외부 노출

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
        analyzers.push(Box::new(TasksAnalyzer::new()));
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