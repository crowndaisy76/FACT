use anyhow::{Context, Result};
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use collector::mft::MftReader;
use collector::filesystem::NtfsFileSystem;
use collector::artifacts::{ForensicCollector, ArtifactTarget};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("FACT Engine Initiated - Architecture Decoupled.");

    enable_privilege(w!("SeBackupPrivilege"))?;
    
    let volume_path = w!("\\\\.\\C:"); 
    let file = open_locked_file(volume_path)?;
    
    tracing::info!("Bootstrapping MFT Reader...");
    let mut mft_reader = MftReader::bootstrap(file)
        .context("Failed to bootstrap MFT Engine")?;
    
    let fs = NtfsFileSystem::new(&mut mft_reader);
    let mut collector = ForensicCollector::new(fs);
    
    tracing::info!("Forensic Collector is ready.");

    let targets = vec![
        ArtifactTarget::RegistrySAM,
        ArtifactTarget::RegistrySECURITY,
        ArtifactTarget::RegistrySOFTWARE,
        ArtifactTarget::RegistrySYSTEM,
        ArtifactTarget::Amcache,
        ArtifactTarget::Prefetch,
        ArtifactTarget::EventLogs,
        ArtifactTarget::ScheduledTasks,
    ];

    for target in targets {
        tracing::info!("================================================");
        tracing::info!("Streaming Artifact: {:?}", target);
        tracing::info!("================================================");
        
        match collector.collect_to_memory_stream(&target) {
            Ok((count, total_size)) => {
                if count > 0 {
                    tracing::info!(
                        "  -> Final Result: Virtually Streamed {} files, Total Size: {} bytes",
                        count, total_size
                    );
                } else {
                    tracing::warn!("  -> Artifact located but no valid data files were processed.");
                }
            },
            Err(e) => {
                tracing::error!("  -> Fatal Error streaming {:?}: {}", target, e);
            }
        }
    }

    Ok(())
}