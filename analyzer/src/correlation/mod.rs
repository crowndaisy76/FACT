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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    pub id: String,
    pub name: String,
    pub total_score: i32,
    pub sequences: Vec<String>,
    pub associated_entities: Vec<String>,
    pub confidence: f32,
}

pub struct CorrelationEngine {
    pub events: Vec<TimelineEntry>,
    pub relationships: Vec<EventRelationship>,
    pub campaigns: Vec<ThreatCampaign>,
    pub entity_index: HashMap<String, Vec<String>>, 
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self { 
            events: Vec::new(), 
            relationships: Vec::new(), 
            campaigns: Vec::new(),
            entity_index: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, raw_events: Vec<ForensicEvent>) {
        let mut counter = 0;
        for event in raw_events {
            let (score, category, summary, entities) = self.extract_context_and_score(&event);
            if score == 0 && entities.is_empty() { continue; }

            counter += 1;
            let entry_id = format!("evt-{}", counter);
            
            for entity in &entities {
                self.entity_index.entry(entity.clone()).or_insert_with(Vec::new).push(entry_id.clone());
            }

            self.events.push(TimelineEntry {
                id: entry_id, timestamp: self.extract_timestamp(&event),
                category, summary, original_event: event, score, entities,
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

    fn extract_context_and_score(&self, event: &ForensicEvent) -> (i32, String, String, Vec<String>) {
        let mut score = 0;
        let mut entities = Vec::new();

        match event {
            ForensicEvent::Execution(e) => {
                let filename = e.process_name.split('\\').last().unwrap_or(&e.process_name).to_lowercase();
                if !filename.is_empty() && filename != "unknown" { entities.push(filename.clone()); }
                let cmd_lower = e.command_line.to_lowercase();
                if e.source_artifact.starts_with("LNK") { score += 40; entities.push("lnk_execution".into()); }
                if cmd_lower.contains("-enc") || cmd_lower.contains("hidden") || cmd_lower.contains("bypass") || cmd_lower.contains("download") { score += 50; }
                if score == 0 { score += 5; }
                (score, "Execution".into(), format!("Run: {}", filename), entities)
            },
            ForensicEvent::FileSystemActivity(f) => {
                let filename = f.file_name.split('\\').last().unwrap_or(&f.file_name).to_lowercase();
                if !filename.is_empty() { entities.push(filename.clone()); }
                if f.is_timestomped { score += 80; }
                if filename.ends_with(".ps1") || filename.ends_with(".vbs") || filename.ends_with(".bat") || filename.ends_with(".exe") || filename.ends_with(".dll") { score += 10; }
                (score, "FileSystem".into(), format!("File: {}", filename), entities)
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
                if p.persistence_type.contains("WMI Event") { score += 70; }
                if p.persistence_type.contains("SYSTEM") { score += 60; }
                if p.persistence_type.contains("NTUSER") { score += 50; }
                if p.persistence_type.contains("Task") { score += 30; }
                (score, "Persistence".into(), format!("Persist: {}", p.persistence_type), entities)
            },
            ForensicEvent::NetworkActivity(n) => {
                entities.push(n.destination_ip.clone());
                let proc_name = n.process_name.split('\\').last().unwrap_or(&n.process_name).to_lowercase();
                if !proc_name.is_empty() && proc_name != "unknown" { entities.push(proc_name); }
                score += 20;
                (score, "Network".into(), format!("Connect: {}:{}", n.destination_ip, n.destination_port), entities)
            },
            ForensicEvent::SystemActivity(s) => {
                if s.activity_type.contains("[CRITICAL]") { score += 90; }
                (score, "System".into(), s.activity_type.clone(), entities)
            },
            _ => (0, "Other".into(), "Unknown".into(), entities)
        }
    }

    pub fn analyze_multi_hop_causality(&mut self) {
        let mut rels = Vec::new();
        let cluster_window = Duration::minutes(30).num_seconds(); 

        let mut id_to_event = HashMap::new();
        for e in &self.events {
            id_to_event.insert(e.id.clone(), e);
        }

        for i in 0..self.events.len() {
            let src = &self.events[i];
            
            for entity in &src.entities {
                if let Some(related_ids) = self.entity_index.get(entity) {
                    if related_ids.len() > 500 { continue; }

                    for target_id in related_ids {
                        if target_id == &src.id { continue; }
                        
                        let tgt = match id_to_event.get(target_id) {
                            Some(e) => *e,
                            None => continue,
                        };

                        let delta = (tgt.timestamp - src.timestamp).num_seconds().abs();
                        if delta > cluster_window { continue; }

                        let mut rel_type = "related_to".to_string();
                        let mut linked = false;

                        if src.category == "FileSystem" && tgt.category == "Execution" && src.timestamp <= tgt.timestamp {
                            rel_type = "dropped_and_executed".into(); linked = true;
                        } else if src.category == "Execution" && tgt.category == "Persistence" && src.timestamp <= tgt.timestamp {
                            rel_type = "established_persistence".into(); linked = true;
                        } else if src.category == "Execution" && src.original_event.is_lnk_source() && src.timestamp <= tgt.timestamp {
                             rel_type = "initial_access_launcher".into(); linked = true;
                        } else if src.category == "Execution" && tgt.category == "Network" && src.timestamp <= tgt.timestamp && delta < 300 {
                            rel_type = "c2_communication".into(); linked = true;
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

    // [핵심] Step 3: 그래프 탐색 및 위협 캠페인 클러스터링 로직
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
            // 기본 점수가 낮거나 이미 탐색된 노드는 건너뛴다
            if visited.contains(&entry.id) || entry.score < 10 { continue; }

            let mut cluster_ids = Vec::new();
            let mut stack = VecDeque::new();
            stack.push_back(entry.id.clone());
            visited.insert(entry.id.clone());

            // DFS 그래프 탐색
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

            // 연결된 노드가 2개 이상인 경우에만 캠페인화 고려
            if cluster_ids.len() > 1 {
                let mut total_score = 0;
                let mut sequences = Vec::new();
                for id in &cluster_ids {
                    if let Some(e) = id_to_event.get(id) {
                        total_score += e.score;
                        sequences.push(e.summary.clone());
                    }
                }

                // 총 위협 점수가 50점을 넘는 서브그래프만 공격 캠페인으로 확정
                if total_score >= 50 {
                    sequences.sort();
                    sequences.dedup();

                    campaigns.push(ThreatCampaign {
                        id: format!("campaign-fact-{}", campaign_count),
                        name: format!("Threat Chain (Score: {})", total_score),
                        total_score,
                        sequences,
                        associated_entities: cluster_ids,
                        confidence: (total_score as f32 / 300.0).min(1.0),
                    });
                    campaign_count += 1;
                }
            }
        }
        self.campaigns = campaigns;
    }

    pub fn get_relationships(&self) -> &Vec<EventRelationship> { &self.relationships }
    pub fn get_campaigns(&self) -> &Vec<ThreatCampaign> { &self.campaigns }
    
    // 캠페인에 소속된 이벤트만 필터링하여 반환
    pub fn get_filtered_timeline(&self) -> Vec<TimelineEntry> {
        let mut valid_ids = HashSet::new();
        for c in &self.campaigns { 
            for id in &c.associated_entities { valid_ids.insert(id.clone()); } 
        }
        self.events.iter().filter(|e| valid_ids.contains(&e.id)).cloned().collect()
    }
}