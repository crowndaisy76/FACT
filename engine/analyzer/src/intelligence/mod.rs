use crate::correlation::ThreatCampaign;

pub struct ThreatIntelligence;

impl ThreatIntelligence {
    pub fn enrich(campaigns: &mut Vec<ThreatCampaign>) {
        for camp in campaigns.iter_mut() {
            let mut tactics = Vec::new();

            for seq in &camp.sequences {
                let seq_lower = seq.to_lowercase();
                
                // 1. Initial Access & Execution
                if seq_lower.contains("lnk") { 
                    tactics.push("T1566.002: Spearphishing Link".to_string()); 
                }
                if seq_lower.contains("powershell") || seq_lower.contains("pwsh") || seq_lower.contains("-enc") { 
                    tactics.push("T1059.001: PowerShell".to_string()); 
                }
                if seq_lower.contains("cmd.exe") { 
                    tactics.push("T1059.003: Windows Command Shell".to_string()); 
                }

                // 2. Persistence
                if seq_lower.contains("persist: registry run key") || seq_lower.contains("ntuser.dat") { 
                    tactics.push("T1547.001: Registry Run Keys / Startup Folder".to_string()); 
                }
                if seq_lower.contains("persist: service") || seq_lower.contains("system service") { 
                    tactics.push("T1543.003: Windows Service".to_string()); 
                }
                if seq_lower.contains("persist: scheduled task") { 
                    tactics.push("T1053.005: Scheduled Task".to_string()); 
                }
                if seq_lower.contains("wmi event consumer") {
                    tactics.push("T1546.003: WMI Event Subscription".to_string());
                }

                // 3. Defense Evasion / Privilege Escalation
                if seq_lower.contains("lsass.exe") {
                    tactics.push("T1003.001: OS Credential Dumping: LSASS Memory".to_string());
                }
            }

            tactics.sort();
            tactics.dedup();
            camp.mitre_tactics = tactics;

            // 전술 태그가 1개 이상 부여된 경우 이름을 구체적으로 변경한다.
            if !camp.mitre_tactics.is_empty() {
                camp.name = format!("Contextualized Threat Chain (Score: {})", camp.total_score);
            }
        }
    }
}