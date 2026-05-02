use models::event::ForensicEvent;
use chrono::{DateTime, Utc, Duration};
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Serialize, Deserialize};

pub trait ForensicEventExt {
    fn is_lnk_source(&self) -> bool;
}

impl ForensicEventExt for ForensicEvent {
    fn is_lnk_source(&self) -> bool {
        match self {
            ForensicEvent::Execution(e) => e.source_artifact.starts_with("LNK"),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRelationship {
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: String,
    pub time_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub summary: String,
    pub original_event: ForensicEvent,
    pub score: i32,
    pub entities: Vec<String>,
    pub matched_ttps: Vec<String>, // Step 8: 매칭된 TTP 추가
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    pub id: String,
    pub name: String,
    pub total_score: i32,
    pub sequences: Vec<String>,
    pub associated_entities: Vec<String>,
    pub confidence: f32,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
}

// Step 8: Sigma 스타일의 룰 구조체
struct DetectionRule {
    name: &'static str,
    score: i32,
    ttp: &'static str,
    eval: Box<dyn Fn(&str, &str, &str) -> bool>, // (process_name, parent_name, command_line)
}

pub struct CorrelationEngine {
    pub events: Vec<TimelineEntry>,
    pub relationships: Vec<EventRelationship>,
    pub campaigns: Vec<ThreatCampaign>,
    pub entity_index: HashMap<String, Vec<String>>, 
    pub global_pid_cache: HashMap<u32, String>,
    rules: Vec<DetectionRule>, // Step 8: 룰 엔진 내장
}

impl CorrelationEngine {
    pub fn new() -> Self {
        let rules = vec![
            // 1. Suspicious PowerShell Execution (e.g., Encoded or Hidden)
            DetectionRule {
                name: "Suspicious PowerShell Command",
                score: 80,
                ttp: "T1059.001",
                eval: Box::new(|proc, _, cmd| {
                    (proc == "powershell.exe" || proc == "pwsh.exe") &&
                    (cmd.contains("-enc") || cmd.contains("hidden") || cmd.contains("bypass") || cmd.contains("downloadstring"))
                }),
            },
            // 2. Suspicious Parent for Shells (e.g., Word spawning CMD)
            DetectionRule {
                name: "Suspicious Parent Process for Shell",
                score: 100,
                ttp: "T1059",
                eval: Box::new(|proc, parent, _| {
                    let shells = ["cmd.exe", "powershell.exe", "pwsh.exe"];
                    let susp_parents = ["winword.exe", "excel.exe", "powerpnt.exe", "mshta.exe", "wscript.exe", "cscript.exe"];
                    shells.contains(&proc) && susp_parents.contains(&parent)
                }),
            },
            // 3. LSASS Memory Access (Credential Dumping)
            DetectionRule {
                name: "LSASS Memory Access/Dump",
                score: 150,
                ttp: "T1003.001",
                eval: Box::new(|proc, parent, cmd| {
                    proc == "lsass.exe" && parent != "wininit.exe" && !parent.is_empty() 
                    || cmd.contains("comsvcs.dll") // comsvcs.dll, MiniDump
                }),
            },
            // 4. Suspicious Svchost Execution (Masquerading or Injection)
            DetectionRule {
                name: "Suspicious Svchost Execution",
                score: 120,
                ttp: "T1036.005",
                eval: Box::new(|proc, parent, cmd| {
                    proc == "svchost.exe" && parent != "services.exe" && !parent.is_empty()
                    || (proc == "svchost.exe" && !cmd.contains("-k")) // svchost는 보통 -k 인자와 함께 실행됨
                }),
            },
             // 5. System Binary Proxy Execution (Rundll32, Regsvr32)
            DetectionRule {
                name: "Suspicious Proxy Execution",
                score: 60,
                ttp: "T1218",
                eval: Box::new(|proc, _, cmd| {
                    (proc == "rundll32.exe" || proc == "regsvr32.exe") &&
                    (cmd.contains("javascript:") || cmd.contains("vbscript:") || cmd.contains("http"))
                }),
            }
        ];

        Self { 
            events: Vec::new(), 
            relationships: Vec::new(), 
            campaigns: Vec::new(),
            entity_index: HashMap::new(),
            global_pid_cache: HashMap::new(),
            rules,
        }
    }

    pub fn ingest(&mut self, mut raw_events: Vec<ForensicEvent>) {
        raw_events.sort_by_key(|e| self.extract_timestamp(e));

        for event in &raw_events {
            if let ForensicEvent::Execution(e) = event {
                if e.process_id != 0 && !e.process_name.is_empty() {
                    let filename = e.process_name.split('\\').last().unwrap_or(&e.process_name).to_lowercase();
                    self.global_pid_cache.insert(e.process_id, filename);
                }
            }
        }

        for event in &mut raw_events {
            if let ForensicEvent::Execution(e) = event {
                let current_parent = e.parent_process_name.trim();
                if (current_parent.is_empty() || current_parent == ")") && e.parent_process_id != 0 {
                    if let Some(cached_name) = self.global_pid_cache.get(&e.parent_process_id) {
                         // 노이즈 필터링은 제거하고, 정확한 룰 매칭으로 승부한다.
                        e.parent_process_name = cached_name.clone();
                    }
                }
            }
        }

        let mut counter = 0;
        for event in raw_events {
            let (score, category, summary, entities, matched_ttps) = self.extract_context_and_score(&event);
            if score == 0 && entities.is_empty() { continue; }

            counter += 1;
            let entry_id = format!("evt-{}", counter);
            
            for entity in &entities {
                self.entity_index.entry(entity.clone()).or_insert_with(Vec::new).push(entry_id.clone());
            }

            self.events.push(TimelineEntry {
                id: entry_id, timestamp: self.extract_timestamp(&event),
                category, summary, original_event: event, score, entities, matched_ttps,
            });
        }
        self.events.sort_by_key(|e| e.timestamp);
    }

    fn extract_timestamp(&self, event: &ForensicEvent) -> DateTime<Utc> {
        match event {
            ForensicEvent::Execution(e) => e.timestamp,
            ForensicEvent::NetworkActivity(n) => n.timestamp,
            ForensicEvent::Persistence(p) => p.timestamp,
            ForensicEvent::Logon(l) => l.timestamp,
            ForensicEvent::SystemActivity(s) => s.timestamp,
            ForensicEvent::FileSystemActivity(f) => f.timestamp,
        }
    }

    fn extract_context_and_score(&self, event: &ForensicEvent) -> (i32, String, String, Vec<String>, Vec<String>) {
        let mut score = 0;
        let mut entities = Vec::new();
        let mut matched_ttps = Vec::new();

        match event {
            ForensicEvent::Execution(e) => {
                let filename = e.process_name.split('\\').last().unwrap_or(&e.process_name).to_lowercase();
                let parent_name = e.parent_process_name.split('\\').last().unwrap_or(&e.parent_process_name).to_lowercase();
                let cmd_lower = e.command_line.to_lowercase();

                if !filename.is_empty() { entities.push(filename.clone()); }

                // Step 8: Sigma 기반 룰 엔진 평가
                for rule in &self.rules {
                    if (rule.eval)(&filename, &parent_name, &cmd_lower) {
                        score += rule.score;
                        matched_ttps.push(rule.ttp.to_string());
                    }
                }

                // 엔티티 추출 (실행 파일 추출)
                for token in cmd_lower.split_whitespace() {
                    let clean_token = token.trim_matches(|c| c == '\'' || c == '"' || c == '\\' || c == ']' || c == '[');
                    if clean_token.ends_with(".exe") || clean_token.ends_with(".ps1") || clean_token.ends_with(".dll") {
                        let extracted = clean_token.split('\\').last().unwrap_or(clean_token).to_string();
                        if !extracted.is_empty() { entities.push(extracted); }
                    }
                }

                if e.source_artifact.starts_with("LNK") { 
                    score += 40; 
                    entities.push("lnk_execution".into()); 
                    matched_ttps.push("T1566.002".to_string()); 
                }
                
                if score == 0 { score += 5; } // Base score

                matched_ttps.dedup();
                (score, "Execution".into(), format!("Run: {} (Parent: {})", filename, parent_name), entities, matched_ttps)
            },
            ForensicEvent::FileSystemActivity(f) => {
                let filename = f.file_name.split('\\').last().unwrap_or(&f.file_name).to_lowercase();
                if !filename.is_empty() { entities.push(filename.clone()); }
                if f.is_timestomped { 
                    score += 80; 
                    matched_ttps.push("T1070.006".to_string()); // Timestomp
                }
                if filename.ends_with(".ps1") || filename.ends_with(".vbs") || filename.ends_with(".bat") || filename.ends_with(".exe") || filename.ends_with(".dll") { score += 10; }
                (score, "FileSystem".into(), format!("File: {}", filename), entities, matched_ttps)
            },
            ForensicEvent::Persistence(p) => {
                let target_path_lower = p.target_path.to_lowercase();
                if let Some(idx) = target_path_lower.find(".exe") {
                    let ext = target_path_lower[..idx+4].split('\\').last().unwrap_or("").to_string();
                    if !ext.is_empty() { entities.push(ext); }
                } else if let Some(idx) = target_path_lower.find(".ps1") {
                    let ext = target_path_lower[..idx+4].split('\\').last().unwrap_or("").to_string();
                    if !ext.is_empty() { entities.push(ext); }
                }
                if p.persistence_type.contains("WMI Event") { score += 70; matched_ttps.push("T1546.003".into()); }
                if p.persistence_type.contains("SYSTEM") { score += 60; matched_ttps.push("T1543.003".into()); }
                if p.persistence_type.contains("NTUSER") { score += 50; matched_ttps.push("T1547.001".into()); }
                if p.persistence_type.contains("Task") { score += 30; matched_ttps.push("T1053.005".into()); }
                (score, "Persistence".into(), format!("Persist: {}", p.persistence_type), entities, matched_ttps)
            },
            ForensicEvent::NetworkActivity(n) => {
                entities.push(n.destination_ip.clone());
                let proc_name = n.process_name.split('\\').last().unwrap_or(&n.process_name).to_lowercase();
                if !proc_name.is_empty() && proc_name != "unknown" { entities.push(proc_name); }
                score += 20;
                (score, "Network".into(), format!("Connect: {}:{}", n.destination_ip, n.destination_port), entities, matched_ttps)
            },
            ForensicEvent::SystemActivity(s) => {
                if s.activity_type.contains("[CRITICAL]") { 
                    score += 90; 
                    if s.description.contains("cleared") { matched_ttps.push("T1070.001".into()); } // Clear Windows Event Logs
                }
                (score, "System".into(), s.activity_type.clone(), entities, matched_ttps)
            },
            _ => (0, "Other".into(), "Unknown".into(), entities, matched_ttps)
        }
    }

    pub fn analyze_multi_hop_causality(&mut self) {
        let mut rels = Vec::new();
        let default_window = Duration::minutes(30).num_seconds(); 

        let mut id_to_event = HashMap::new();
        for e in &self.events {
            id_to_event.insert(e.id.clone(), e);
        }

        for i in 0..self.events.len() {
            let src = &self.events[i];
            
            for entity in &src.entities {
                if let Some(related_ids) = self.entity_index.get(entity) {
                    if related_ids.len() > 50 { continue; } 

                    for target_id in related_ids {
                        if target_id == &src.id { continue; }
                        
                        let tgt = match id_to_event.get(target_id) {
                            Some(e) => *e,
                            None => continue,
                        };

                        let delta = (tgt.timestamp - src.timestamp).num_seconds().abs();
                        if delta > default_window { continue; }

                        let mut rel_type = String::new();
                        let mut linked = false;

                        if src.category == "Execution" && tgt.category == "Execution" {
                            if let (ForensicEvent::Execution(s_exec), ForensicEvent::Execution(t_exec)) = (&src.original_event, &tgt.original_event) {
                                let s_proc = s_exec.process_name.split('\\').last().unwrap_or("").to_lowercase();
                                let t_parent = t_exec.parent_process_name.split('\\').last().unwrap_or("").to_lowercase();
                                let t_proc = t_exec.process_name.split('\\').last().unwrap_or("").to_lowercase();
                                let s_parent = s_exec.parent_process_name.split('\\').last().unwrap_or("").to_lowercase();
                                
                                let s_proc_valid = !s_proc.is_empty();
                                let t_parent_valid = !t_parent.is_empty() && t_parent != ")";
                                let t_proc_valid = !t_proc.is_empty();
                                let s_parent_valid = !s_parent.is_empty() && s_parent != ")";

                                if s_proc_valid && t_parent_valid && s_proc == t_parent && src.timestamp <= tgt.timestamp {
                                    rel_type = "spawned_process".into(); linked = true;
                                } else if t_proc_valid && s_parent_valid && t_proc == s_parent && tgt.timestamp <= src.timestamp {
                                    rel_type = "spawned_process".into(); linked = true;
                                } 
                            }
                        }

                        if !linked {
                            if src.category == "FileSystem" && tgt.category == "Execution" && src.timestamp <= tgt.timestamp {
                                rel_type = "dropped_and_executed".into(); linked = true;
                            } else if src.category == "Execution" && tgt.category == "FileSystem" && src.timestamp <= tgt.timestamp {
                                rel_type = "executed_and_dropped".into(); linked = true; 
                            } else if src.category == "Execution" && tgt.category == "Persistence" && src.timestamp <= tgt.timestamp {
                                rel_type = "established_persistence".into(); linked = true;
                            } else if src.category == "Execution" && src.original_event.is_lnk_source() && src.timestamp <= tgt.timestamp {
                                rel_type = "initial_access_launcher".into(); linked = true;
                            } else if src.category == "Execution" && tgt.category == "Network" && src.timestamp <= tgt.timestamp && delta < 300 {
                                rel_type = "c2_communication".into(); linked = true;
                            }
                        }

                        if linked {
                            rels.push(EventRelationship {
                                source_id: src.id.clone(), target_id: tgt.id.clone(),
                                relationship_type: rel_type, time_delta: delta,
                            });
                        }
                    }
                }
            }
        }
        
        let mut unique_rels = HashSet::new();
        self.relationships = rels.into_iter()
            .filter(|r| unique_rels.insert((r.source_id.clone(), r.target_id.clone(), r.relationship_type.clone())))
            .collect();
    }

    pub fn build_campaigns(&mut self) {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for rel in &self.relationships {
            adj.entry(rel.source_id.clone()).or_insert_with(Vec::new).push(rel.target_id.clone());
            adj.entry(rel.target_id.clone()).or_insert_with(Vec::new).push(rel.source_id.clone());
        }

        let mut visited = HashSet::new();
        let mut campaigns = Vec::new();
        let mut campaign_count = 1;

        let mut id_to_event = HashMap::new();
        for e in &self.events {
            id_to_event.insert(e.id.clone(), e);
        }

        for entry in &self.events {
            if visited.contains(&entry.id) || entry.score < 10 { continue; }

            let mut cluster_ids = Vec::new();
            let mut stack = VecDeque::new();
            stack.push_back(entry.id.clone());
            visited.insert(entry.id.clone());

            while let Some(node_id) = stack.pop_back() {
                cluster_ids.push(node_id.clone());
                if let Some(neighbors) = adj.get(&node_id) {
                    for neighbor in neighbors {
                        if !visited.contains(neighbor) {
                            visited.insert(neighbor.clone());
                            stack.push_back(neighbor.clone());
                        }
                    }
                }
            }

            if cluster_ids.len() > 1 {
                let mut total_score = 0;
                let mut sequences = Vec::new();
                let mut all_ttps = Vec::new();

                for id in &cluster_ids {
                    if let Some(e) = id_to_event.get(id) {
                        total_score += e.score;
                        sequences.push(e.summary.clone());
                        all_ttps.extend(e.matched_ttps.clone());
                    }
                }

                if total_score >= 50 {
                    sequences.sort();
                    sequences.dedup();
                    all_ttps.sort();
                    all_ttps.dedup();

                    campaigns.push(ThreatCampaign {
                        id: format!("campaign-fact-{}", campaign_count),
                        name: format!("Threat Chain (Score: {})", total_score),
                        total_score,
                        sequences,
                        associated_entities: cluster_ids,
                        confidence: (total_score as f32 / 300.0).min(1.0),
                        mitre_tactics: all_ttps, // 매칭된 TTP 바로 할당
                    });
                    campaign_count += 1;
                }
            }
        }
        self.campaigns = campaigns;
    }

    pub fn get_relationships(&self) -> &Vec<EventRelationship> { &self.relationships }
    pub fn get_campaigns(&self) -> &Vec<ThreatCampaign> { &self.campaigns }
    
    pub fn get_filtered_timeline(&self) -> Vec<TimelineEntry> {
        let mut valid_ids = HashSet::new();
        for c in &self.campaigns { 
            for id in &c.associated_entities { valid_ids.insert(id.clone()); } 
        }
        self.events.iter().filter(|e| valid_ids.contains(&e.id)).cloned().collect()
    }
}