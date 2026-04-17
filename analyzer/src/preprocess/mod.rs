use models::event::ForensicEvent;

pub struct Preprocessor;

impl Preprocessor {
    pub fn run(events: Vec<ForensicEvent>) -> Vec<ForensicEvent> {
        let mut processed = Vec::new();
        
        for mut event in events {
            if Self::is_noise(&event) {
                continue;
            }
            
            Self::detect_anomalies(&mut event);
            
            processed.push(event);
        }
        
        processed
    }

    fn is_noise(event: &ForensicEvent) -> bool {
        match event {
            ForensicEvent::Execution(e) => {
                let name = e.process_name.to_lowercase();
                
                // 1. 윈도우 정상 백그라운드 프로세스 화이트리스트
                let noise_procs = [
                    "tiworker.exe", "searchindexer.exe", "compattelrunner.exe", 
                    "backgroundtaskhost.exe", "mscorsvw.exe", "ngentask.exe",
                    "devicecensus.exe", "sppsvc.exe", "onedrive.exe", "dllhost.exe",
                    "taskhostw.exe", "conhost.exe", "wuaucltcore.exe", "runtimebroker.exe",
                    "smartscreen.exe", "ctfmon.exe", "audiodg.exe"
                ];
                
                if noise_procs.contains(&name.as_str()) {
                    return true;
                }
                
                if name == "svchost.exe" && !e.command_line.to_lowercase().contains("bypass") {
                    return true;
                }
            },
            ForensicEvent::FileSystemActivity(f) => {
                let name = f.file_name.to_lowercase();
                
                // 2. 임시 파일 및 캐시 파일 확장자 무시
                if name.ends_with(".tmp") || name.ends_with(".cache") || 
                   name.ends_with(".etl") || name.ends_with(".wer") ||
                   name.ends_with(".db") || name.ends_with(".db-wal") || 
                   name.ends_with(".db-shm") || name.ends_with(".pf") ||
                   name.ends_with(".mum") || name.ends_with(".cat") ||
                   name.ends_with(".mui") || name.ends_with(".dat") ||
                   name.ends_with(".log") || name.ends_with(".chk") ||
                   name.ends_with(".ttf") || name.ends_with(".json") {
                    return true;
                }

                // 3. 파일명에 물결표(~)가 들어간 백업/임시 파일 무시
                if name.starts_with('~') || name.contains("~rf") || name.contains("~df") {
                    return true;
                }

                // 4. MFT/USN에서 올라오는 특정 노이즈 문자열 무시
                if name.contains("network persistent state") || name.contains("metrics.csv") || name.starts_with("ntuser") {
                    return true;
                }
            },
            _ => {}
        }
        false
    }

    fn detect_anomalies(event: &mut ForensicEvent) {
        if let ForensicEvent::FileSystemActivity(f) = event {
            if let (Some(si), Some(fn_time)) = (f.si_mtime, f.fn_mtime) {
                let diff_seconds = fn_time.signed_duration_since(si).num_seconds();
                
                if diff_seconds > 3600 {
                    f.is_timestomped = true;
                    f.reason = format!("{} [CRITICAL: TIMESTOMPING DETECTED! SI-FN Delta: {}s]", f.reason, diff_seconds);
                }
            }
        }
    }
}