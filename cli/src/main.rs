use anyhow::{Context, Result};
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use collector::mft::MftReader;
use collector::filesystem::NtfsFileSystem;
use collector::artifacts::ForensicCollector;
use models::artifact::ArtifactTarget;
use analyzer::AnalysisEngine;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info,evtx=warn"))
        .init();

    tracing::info!("FACT Engine Initiated - In-Memory Analysis Pipeline Active.");

    enable_privilege(w!("SeBackupPrivilege"))?;
    let volume_path = w!("\\\\.\\C:"); 
    let file = open_locked_file(volume_path)?;
    
    tracing::info!("Bootstrapping MFT Reader...");
    let mut mft_reader = MftReader::bootstrap(file).context("Failed to bootstrap MFT Engine")?;
    let fs = NtfsFileSystem::new(&mut mft_reader);
    let mut collector = ForensicCollector::new(fs);
    
    let analyzer = AnalysisEngine::new();
    tracing::info!("Analysis Engine is ready.");

    let targets = vec![
        ArtifactTarget::ScheduledTasks, // [Step 9 Target ON]
    ];

    for target in targets {
        tracing::info!("================================================");
        tracing::info!("Streaming & Analyzing: {:?}", target);
        tracing::info!("================================================");
        
        let mut total_events = 0;
        
        let result = collector.collect_to_memory_stream(&target, |filename, data| {
            let events = analyzer.process_stream(&target, filename, data);
            
            for event in &events {
                match event {
                    models::event::ForensicEvent::Execution(e) => {
                        println!("[EXECUTION] {} | Process: {} | Cmd/Path: {}", 
                            e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), e.process_name, e.file_path);
                    },
                    models::event::ForensicEvent::Persistence(p) => {
                        // 추출된 XML 페이로드가 이곳에서 출력됩니다.
                        println!("[PERSISTENCE] {} | Type: {} | Name: {} | Payload: {}", 
                            p.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), p.persistence_type, p.target_name, p.target_path);
                    },
                    models::event::ForensicEvent::Logon(l) => {
                        println!("[LOGON] {} | EventID: {} | Status: {} | Type: {} | Account: {} | IP: {}", 
                            l.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), l.event_id, l.status, l.logon_type, l.account_name, l.source_ip.as_deref().unwrap_or("N/A"));
                    },
                    models::event::ForensicEvent::SystemActivity(s) => {
                        println!("[SYSTEM] {} | Type: {} | Desc: {} | Source: {}", 
                            s.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), s.activity_type, s.description, s.source_artifact);
                    },
                    models::event::ForensicEvent::FileSystemActivity(f) => {
                        let f_type = if f.is_dir { "DIR " } else { "FILE" };
                        println!("[FILE_SYSTEM] {} | [{}] {} | Action: {}", 
                            f.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), f_type, f.file_name, f.reason);
                    },
                }
            }
            total_events += events.len();
        });

        match result {
            Ok((count, total_size)) => {
                tracing::info!(
                    "  -> Final Result: Streamed {} files ({} bytes), Generated {} Intelligence Events",
                    count, total_size, total_events
                );
            },
            Err(e) => {
                tracing::error!("  -> Fatal Error processing {:?}: {}", target, e);
            }
        }
    }

    Ok(())
}