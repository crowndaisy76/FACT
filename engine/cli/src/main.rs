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
use analyzer::preprocess::Preprocessor;
use chrono::Utc;
use tracing_subscriber::EnvFilter;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use rayon::prelude::*;

macro_rules! measure_perf {
    ($task_name:expr, $block:block) => {{
        let start = Instant::now();
        let result = $block;
        let elapsed = start.elapsed();
        tracing::info!("[PERF_METRIC] [{}] 소요 시간: {}.{:06} sec", 
            $task_name, elapsed.as_secs(), elapsed.subsec_micros());
        result
    }};
}

fn main() -> Result<()> {
    let total_start = Instant::now();
    tracing_subscriber::fmt().with_env_filter(EnvFilter::new("info,evtx=error")).init();
    tracing::info!("FACT Engine (Parallel Architecture)");

    measure_perf!("Init_Privilege_And_Volume", {
        let p_name = w!("SeBackupPrivilege");
        unsafe { enable_privilege(std::mem::transmute(p_name)) }.context("Failed to enable SeBackupPrivilege")?;
    });
    
    let v_path = w!("\\\\.\\C:");
    let file = unsafe { open_locked_file(std::mem::transmute(v_path)) }.context("Failed to open C: volume")?;
    
    let master_mft = measure_perf!("Phase_1_MFT_Bootstrap", {
        MftReader::bootstrap(file).context("Failed to bootstrap MFT")?
    });

    let targets = vec![
        ArtifactTarget::Prefetch, ArtifactTarget::EventLogs, ArtifactTarget::ScheduledTasks,
        ArtifactTarget::Amcache, ArtifactTarget::RegistrySOFTWARE, ArtifactTarget::RegistryNTUSER,
        ArtifactTarget::RegistrySYSTEM, ArtifactTarget::LNK, ArtifactTarget::WMI,
        ArtifactTarget::UsnJrnl, ArtifactTarget::MFT,
    ];

    let all_raw_events: Vec<ForensicEvent> = measure_perf!("Phase_2_Parallel_Collection", {
        targets.into_par_iter().flat_map(|target| {
            // [고도화 추가] 개별 스레드의 처리 시간을 측정하기 위한 타이머 시작
            let thread_start = Instant::now();
            let mut thread_events = Vec::new();
            let t_mft = master_mft.clone_reader().expect("Clone fail");
            let mut collector = ForensicCollector::new(NtfsFileSystem::new(t_mft));
            let analyzer = AnalysisEngine::new();
            
            tracing::info!("Thread started for: {:?}", target);
            
            let collect_res = collector.collect_to_memory_stream(&target, |filename, data| {
                match target {
                    ArtifactTarget::Prefetch => {
                        if let Ok(info) = parser::prefetch::parse_prefetch_info(data) {
                            thread_events.push(ForensicEvent::Execution(ExecutionEvent {
                                timestamp: info.last_run_times.first().copied().unwrap_or_else(Utc::now),
                                process_name: info.executable_name, process_id: 0, parent_process_id: 0,
                                file_path: filename.to_string(), command_line: String::new(), 
                                parent_process_name: String::new(), run_count: info.run_count, 
                                referenced_files: info.referenced_files, source_artifact: format!("Prefetch ({})", filename),
                            }));
                        }
                    },
                    ArtifactTarget::EventLogs => {
                        if let Ok(mut evs) = parser::evtx::parse_security_evtx_buffer(data, filename) { thread_events.append(&mut evs); }
                    },
                    ArtifactTarget::ScheduledTasks => {
                        if let Ok(mut evs) = parser::tasks::parse_task_xml(data, filename) { thread_events.append(&mut evs); }
                    },
                    ArtifactTarget::Amcache => {
                        if let Ok(recs) = parser::amcache::parse_amcache_carve(data) {
                            for r in recs {
                                thread_events.push(ForensicEvent::Execution(ExecutionEvent {
                                    timestamp: Utc::now(), process_name: r.file_path.split('\\').last().unwrap_or("Unknown").to_string(),
                                    process_id: 0, parent_process_id: 0, file_path: format!("{} [SHA1: {}]", r.file_path, r.sha1),
                                    command_line: String::new(), parent_process_name: String::new(), run_count: 1, 
                                    referenced_files: vec![], source_artifact: "Amcache.hve".to_string(),
                                }));
                            }
                        }
                    },
                    ArtifactTarget::LNK => {
                        if let Ok(mut evs) = parser::lnk::parse_lnk_carve(data, filename) { thread_events.append(&mut evs); }
                    },
                    ArtifactTarget::WMI => {
                        if let Ok(mut evs) = parser::wmi::parse_wmi_carve(data, filename) { thread_events.append(&mut evs); }
                    },
                    ArtifactTarget::RegistrySYSTEM => {
                        if let Ok(mut evs) = parser::system_hive::parse_system_services(data, filename) { thread_events.append(&mut evs); }
                        thread_events.append(&mut analyzer.process_stream(&target, filename, data));
                    },
                    _ => { thread_events.append(&mut analyzer.process_stream(&target, filename, data)); }
                }
            });
            
            if let Err(e) = collect_res { tracing::error!("  [!] Thread Error for {:?}: {}", target, e); }
            
            // [고도화 추가] 스레드 처리가 완전히 끝난 시점에 소요 시간 로깅
            let elapsed = thread_start.elapsed();
            tracing::info!("[PERF_METRIC] [Thread_{:?}] 소요 시간: {}.{:06} sec", target, elapsed.as_secs(), elapsed.subsec_micros());

            thread_events
        }).collect()
    });

    let filtered_events = measure_perf!("Phase_3_Preprocessing", { Preprocessor::run(all_raw_events) });
    let mut correlation_engine = analyzer::correlation::CorrelationEngine::new();
    let (timeline, mut campaigns) = measure_perf!("Phase_4_Correlation", {
        correlation_engine.ingest(filtered_events);
        correlation_engine.analyze_multi_hop_causality();
        correlation_engine.build_campaigns();
        (correlation_engine.get_filtered_timeline(), correlation_engine.get_campaigns().clone())
    });

    measure_perf!("Phase_5_Intelligence", { analyzer::intelligence::ThreatIntelligence::enrich(&mut campaigns); });
    tracing::info!("Intelligence Step Complete: Detected {} Campaigns.", campaigns.len());

    let res_dir = Path::new("..").join("Results");
    if !res_dir.exists() { fs::create_dir_all(&res_dir)?; }

    measure_perf!("Phase_6_Export", {
        let bundle = analyzer::stix::StixBuilder::generate_bundle(&timeline, correlation_engine.get_relationships(), &campaigns);
        let mut f = File::create(res_dir.join("final_threat_report.json"))?;
        f.write_all(serde_json::to_string_pretty(&bundle)?.as_bytes())?;
    });

    tracing::info!("Total Time: {} sec", total_start.elapsed().as_secs_f64());
    Ok(())
}