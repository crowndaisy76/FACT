use anyhow::{Context, Result};
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use collector::mft::MftReader;
use collector::filesystem::NtfsFileSystem;
use collector::artifacts::ForensicCollector;
use models::artifact::ArtifactTarget;
use analyzer::{AnalysisEngine, CorrelationEngine, StixBuilder};
use tracing_subscriber::EnvFilter;
use std::fs::File;
use std::io::Write;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info,evtx=warn"))
        .init();

    tracing::info!("FACT Engine v5 Initiated - Context-Aware Pipeline Active.");

    enable_privilege(w!("SeBackupPrivilege"))?;
    let volume_path = w!("\\\\.\\C:"); 
    let file = open_locked_file(volume_path)?;
    
    let mut mft_reader = MftReader::bootstrap(file).context("Failed to bootstrap MFT Engine")?;
    let fs = NtfsFileSystem::new(&mut mft_reader);
    let mut collector = ForensicCollector::new(fs);
    
    let analyzer = AnalysisEngine::new();
    let mut correlator = CorrelationEngine::new();

    let targets = vec![
        ArtifactTarget::MFT,
        ArtifactTarget::Prefetch,
        ArtifactTarget::ScheduledTasks,
        ArtifactTarget::EventLogs,
        ArtifactTarget::RegistrySOFTWARE,
    ];

    for target in targets {
        tracing::info!("Processing: {:?}", target);
        let _ = collector.collect_to_memory_stream(&target, |filename, data| {
            let events = analyzer.process_stream(&target, filename, data);
            correlator.ingest(events);
        });
    }

    tracing::info!("Building Graph & Analyzing Sequences...");
    correlator.analyze_multi_hop_causality();
    correlator.build_campaigns();

    let stix_bundle = StixBuilder::generate_bundle(
        &correlator.get_filtered_timeline(), 
        correlator.get_relationships(), 
        correlator.get_campaigns()
    );

    let mut file = File::create("fact_stix_export.json")?;
    file.write_all(serde_json::to_string_pretty(&stix_bundle)?.as_bytes())?;

    tracing::info!("STIX 2.1 Export Complete. Analysis Success.");
    Ok(())
}