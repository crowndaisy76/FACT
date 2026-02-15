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
    tracing::info!("FACT Engine Initiated.");

    enable_privilege(w!("SeBackupPrivilege"))?;
    
    let volume_path = w!("\\\\.\\C:"); 
    let file = open_locked_file(volume_path)?;
    
    tracing::info!("Bootstrapping MFT Reader...");
    let mut mft_reader = MftReader::bootstrap(file)
        .context("Failed to bootstrap MFT Engine")?;
    
    let mut collector = ForensicCollector::new(mft_reader);
    tracing::info!("Forensic Collector is ready.");

    // 수집 대상
    let targets = vec![
        ArtifactTarget::LogFile,      
        ArtifactTarget::RegistrySAM,
        ArtifactTarget::RegistrySYSTEM,
    ];

    let output_dir = "output_artifacts";
    if !Path::new(output_dir).exists() {
        fs::create_dir(output_dir)?;
    }

    for target in targets {
        tracing::info!("Collecting Artifact: {:?}", target);
        
        match collector.collect(target.clone()) {
            Ok(data) => {
                let filename = format!("{:?}.bin", target);
                let path = Path::new(output_dir).join(filename);
                let mut outfile = File::create(&path)?;
                outfile.write_all(&data)?;
                tracing::info!("  -> Success! Saved {} bytes to {:?}", data.len(), path);
            },
            Err(e) => {
                tracing::error!("  -> Failed to collect {:?}: {}", target, e);
                // [Debug] 경로 탐색 실패 시 힌트 제공
                // 만약 RegistrySAM 실패라면, Windows 폴더가 있는지 Root를 뒤져본다.
                // forensic_collector는 mft_reader의 소유권을 가져갔으므로 여기서 직접 reader 접근은 어렵지만,
                // 에러 메시지를 통해 상황 파악 가능.
            }
        }
    }

    Ok(())
}