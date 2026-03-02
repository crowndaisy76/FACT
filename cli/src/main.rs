use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use windows::core::w;
use collector::privilege::enable_privilege;
use collector::reader::open_locked_file;
use collector::mft::MftReader;
use collector::artifacts::{ForensicCollector, ArtifactTarget};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("FACT Engine Initiated: Full IR Collection Mode (Aligned with Igloo IR Guide)");

    enable_privilege(w!("SeBackupPrivilege"))?;
    let volume_path = w!("\\\\.\\C:"); 
    let file = open_locked_file(volume_path)?;
    
    tracing::info!("Bootstrapping MFT Reader...");
    let mut mft_reader = MftReader::bootstrap(file).context("Failed to bootstrap MFT Engine")?;
    let mut collector = ForensicCollector::new(mft_reader);
    tracing::info!("Forensic Collector is ready.");

    let targets = vec![
        ArtifactTarget::MFT,
        ArtifactTarget::LogFile,
        ArtifactTarget::RegistrySAM,
        ArtifactTarget::RegistrySECURITY,
        ArtifactTarget::RegistrySOFTWARE,
        ArtifactTarget::RegistrySYSTEM,
        ArtifactTarget::Amcache,
        ArtifactTarget::Prefetch,
        ArtifactTarget::EventLogs,
        ArtifactTarget::USBLog,
        ArtifactTarget::ScheduledTasks,
        ArtifactTarget::RecycleBin,
    ];

    let base_dir = "output_artifacts";
    if !Path::new(base_dir).exists() { fs::create_dir(base_dir)?; }

    for target in targets {
        tracing::info!("========================================");
        tracing::info!("🚀 Collecting: {:?}", target);
        match collector.collect(&target) {
            Ok(files) => {
                if files.is_empty() { tracing::warn!("  -> No files discovered."); continue; }
                let dir_path = Path::new(base_dir).join(format!("{:?}", target));
                if !dir_path.exists() { fs::create_dir(&dir_path)?; }
                let mut bytes: u64 = 0;
                let count = files.len();
                for f in files {
                    let path = dir_path.join(&f.name);
                    if let Ok(mut out) = File::create(&path) {
                        let _ = out.write_all(&f.data);
                        bytes += f.data.len() as u64;
                    }
                }
                tracing::info!("✅ Done: {:?} | Count: {} | Total: {} bytes", target, count, bytes);
            },
            Err(e) => tracing::error!("❌ Failed: {:?}", e),
        }
    }

    tracing::info!("IR Collection Task Finished Successfully!");
    Ok(())
}