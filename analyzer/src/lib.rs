pub mod prefetch;
pub mod registry;

use anyhow::Result;
use models::event::ForensicEvent;
use models::artifact::ArtifactTarget;
use prefetch::PrefetchAnalyzer;
use registry::RegistryAnalyzer;

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