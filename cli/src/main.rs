use anyhow::{Context, Result};
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use collector::mft::MftReader;
use collector::filesystem::NtfsFileSystem;
use collector::artifacts::ForensicCollector;
use models::artifact::ArtifactTarget;
use models::event::{ForensicEvent, ExecutionEvent};
use analyzer::AnalysisEngine;
use analyzer::Preprocessor;
use chrono::Utc;
use tracing_subscriber::EnvFilter;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::new("info,evtx=warn")).init();
    tracing::info!("FACT Engine v5 - Final Correlation & STIX Generation");

    enable_privilege(w!("SeBackupPrivilege")).context("Failed to enable SeBackupPrivilege")?;
    
    let volume_path = w!("\\\\.\\C:");
    let file = open_locked_file(volume_path).context("Failed to open C: volume")?;
    
    let mut mft_reader = MftReader::bootstrap(file).context("Failed to bootstrap MFT Engine")?;
    let fs = NtfsFileSystem::new(&mut mft_reader);
    let mut collector = ForensicCollector::new(fs);
    let analyzer = AnalysisEngine::new();

    let targets = vec![
        ArtifactTarget::Prefetch, ArtifactTarget::EventLogs, ArtifactTarget::ScheduledTasks,
        ArtifactTarget::Amcache, ArtifactTarget::RegistrySOFTWARE, ArtifactTarget::RegistryNTUSER,
        ArtifactTarget::RegistrySYSTEM, ArtifactTarget::LNK, ArtifactTarget::WMI,
        ArtifactTarget::UsnJrnl, ArtifactTarget::MFT,
    ];

    let mut all_raw_events = Vec::new();

    for target in targets {
        tracing::info!("Processing: {:?}", target);
        let _ = collector.collect_to_memory_stream(&target, |filename, data| {
            match target {
                ArtifactTarget::Prefetch => {
                    if let Ok(info) = parser::prefetch::parse_prefetch_info(data) {
                        all_raw_events.push(ForensicEvent::Execution(ExecutionEvent {
                            timestamp: info.last_run_times.first().copied().unwrap_or_else(Utc::now),
                            process_name: info.executable_name, file_path: filename.to_string(),
                            command_line: String::new(), parent_process_name: String::new(),
                            run_count: info.run_count, referenced_files: info.referenced_files,
                            source_artifact: format!("Prefetch ({})", filename),
                        }));
                    }
                },
                ArtifactTarget::EventLogs => {
                    if let Ok(mut events) = parser::evtx::parse_security_evtx_buffer(data, &filename) {
                        all_raw_events.append(&mut events);
                    }
                },
                ArtifactTarget::ScheduledTasks => {
                    if let Ok(mut events) = parser::tasks::parse_task_xml(data, &filename) {
                        all_raw_events.append(&mut events);
                    }
                },
                ArtifactTarget::Amcache => {
                    if let Ok(records) = parser::amcache::parse_amcache_carve(data) {
                        for rec in records {
                            all_raw_events.push(ForensicEvent::Execution(ExecutionEvent {
                                timestamp: Utc::now(),
                                process_name: rec.file_path.split('\\').last().unwrap_or("Unknown").to_string(),
                                file_path: format!("{} [SHA1: {}]", rec.file_path, rec.sha1),
                                command_line: String::new(), parent_process_name: String::new(),
                                run_count: 1, referenced_files: vec![],
                                source_artifact: "Amcache.hve".to_string(),
                            }));
                        }
                    }
                },
                ArtifactTarget::LNK => {
                    if let Ok(mut events) = parser::lnk::parse_lnk_carve(data, &filename) {
                        all_raw_events.append(&mut events);
                    }
                },
                ArtifactTarget::WMI => {
                    if let Ok(mut events) = parser::wmi::parse_wmi_carve(data, &filename) {
                        all_raw_events.append(&mut events);
                    }
                },
                ArtifactTarget::RegistrySYSTEM => {
                    if let Ok(mut events) = parser::system_hive::parse_system_services(data, &filename) {
                        all_raw_events.append(&mut events);
                    }
                    let mut events = analyzer.process_stream(&target, filename, data);
                    all_raw_events.append(&mut events);
                },
                _ => {
                    let mut events = analyzer.process_stream(&target, filename, data);
                    all_raw_events.append(&mut events);
                }
            }
        });
    }

    tracing::info!("Running Preprocessor...");
    let filtered_events = Preprocessor::run(all_raw_events);
    
    tracing::info!("Starting Correlation Engine...");
    let mut engine = analyzer::correlation::CorrelationEngine::new();
    
    // 중복 제거 후 단 한 번만 데이터 주입
    engine.ingest(filtered_events);
    
    // Step 2 & Step 3 실행
    engine.analyze_multi_hop_causality();
    engine.build_campaigns();

    let final_timeline = engine.get_filtered_timeline();
    let campaigns = engine.get_campaigns();

    tracing::info!("Step 3 Complete: Detected {} Threat Campaigns containing {} events.", campaigns.len(), final_timeline.len());

    let results_dir = Path::new("Results");
    if !results_dir.exists() { fs::create_dir_all(results_dir).context("Failed to create Results directory")?; }

    let stix_bundle = analyzer::stix::StixBuilder::generate_bundle(
        &final_timeline,
        engine.get_relationships(),
        campaigns
    );

    let mut stix_file = File::create("Results\\final_threat_report.json").context("Failed to create JSON file")?;
    stix_file.write_all(serde_json::to_string_pretty(&stix_bundle)?.as_bytes()).context("Failed to write JSON")?;

    tracing::info!("STIX 2.1 Threat Report saved to Results/final_threat_report.json");
    Ok(())
}