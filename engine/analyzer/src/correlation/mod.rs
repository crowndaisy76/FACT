use models::event::ForensicEvent;
use chrono::{DateTime, Utc, Duration};
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Serialize, Deserialize};

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
    pub matched_ttps: Vec<String>,
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

struct DetectionRule {
    name: &'static str,
    score: i32,
    ttp: &'static str,
    eval: Box<dyn Fn(&ForensicEvent) -> bool>,
}

pub struct CorrelationEngine {
    pub events: Vec<TimelineEntry>,
    pub relationships: Vec<EventRelationship>,
    pub campaigns: Vec<ThreatCampaign>,
    pub entity_index: HashMap<String, Vec<String>>, 
    pub global_pid_cache: HashMap<u32, String>,
    rules: Vec<DetectionRule>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        let rules = vec![
            DetectionRule { name: "Suspicious PowerShell", score: 80, ttp: "T1059.001", eval: Box::new(|e| if let ForensicEvent::Execution(ex) = e { ex.command_line.to_lowercase().contains("-enc") } else { false }) },
            DetectionRule { name: "Ransomware/Wiper Pattern", score: 150, ttp: "T1486", eval: Box::new(|e| if let ForensicEvent::FileSystemActivity(fs) = e { fs.activity_type.contains("SUSPICIOUS I/O") } else { false }) },
            DetectionRule { name: "Suspicious Svchost", score: 120, ttp: "T1036.005", eval: Box::new(|e| if let ForensicEvent::Execution(ex) = e { ex.process_name.contains("svchost.exe") && !ex.parent_process_name.contains("services.exe") } else { false }) }
        ];
        Self { events: Vec::new(), relationships: Vec::new(), campaigns: Vec::new(), entity_index: HashMap::new(), global_pid_cache: HashMap::new(), rules }
    }

    pub fn ingest(&mut self, mut raw_events: Vec<ForensicEvent>) {
        raw_events.sort_by_key(|e| match e { ForensicEvent::Execution(ex) => ex.timestamp, ForensicEvent::FileSystemActivity(fs) => fs.timestamp, ForensicEvent::Persistence(p) => p.timestamp, ForensicEvent::NetworkActivity(n) => n.timestamp, ForensicEvent::Logon(l) => l.timestamp, ForensicEvent::SystemActivity(s) => s.timestamp });
        
        let mut counter = 0;
        for event in raw_events {
            let (score, category, summary, entities, matched_ttps) = self.extract_context_and_score(&event);
            if score == 0 && entities.is_empty() { continue; }
            counter += 1;
            let entry_id = format!("evt-{}", counter);
            for entity in &entities { self.entity_index.entry(entity.clone()).or_insert_with(Vec::new).push(entry_id.clone()); }
            self.events.push(TimelineEntry { id: entry_id, timestamp: self.extract_timestamp(&event), category, summary, original_event: event, score, entities, matched_ttps });
        }
    }

    fn extract_timestamp(&self, event: &ForensicEvent) -> DateTime<Utc> {
        match event { ForensicEvent::Execution(e) => e.timestamp, ForensicEvent::FileSystemActivity(f) => f.timestamp, ForensicEvent::Persistence(p) => p.timestamp, ForensicEvent::NetworkActivity(n) => n.timestamp, ForensicEvent::Logon(l) => l.timestamp, ForensicEvent::SystemActivity(s) => s.timestamp }
    }

    fn extract_context_and_score(&self, event: &ForensicEvent) -> (i32, String, String, Vec<String>, Vec<String>) {
        let mut score = 5; let mut entities = Vec::new(); let mut matched_ttps = Vec::new();
        for rule in &self.rules { if (rule.eval)(event) { score += rule.score; matched_ttps.push(rule.ttp.to_string()); } }

        match event {
            ForensicEvent::Execution(e) => {
                let name = e.process_name.split('\\').last().unwrap_or(&e.process_name).to_lowercase();
                entities.push(name.clone());
                if let Some(hash) = &e.ioc_hash { entities.push(hash.clone()); } // [고도화] Amcache/Prefetch 해시 강결합
                (score, "Execution".into(), format!("Run: {}", name), entities, matched_ttps)
            },
            ForensicEvent::FileSystemActivity(f) => {
                let name = f.file_name.to_lowercase(); entities.push(name.clone());
                (score, "FileSystem".into(), format!("File: {}", name), entities, matched_ttps)
            },
            ForensicEvent::Persistence(p) => {
                entities.push(p.target_name.to_lowercase());
                (score + 50, "Persistence".into(), format!("Persist: {}", p.persistence_type), entities, matched_ttps)
            },
            _ => (score, "Other".into(), "System Event".into(), entities, matched_ttps)
        }
    }

    pub fn analyze_multi_hop_causality(&mut self) {
        // [성능 최적화] O(1) 조회를 위한 ID-이벤트 인덱스 맵 생성
        let event_map: HashMap<String, &TimelineEntry> = self.events.iter().map(|e| (e.id.clone(), e)).collect();
        let mut rels = Vec::new();
        let window = Duration::minutes(60).num_seconds();

        for src in &self.events {
            for entity in &src.entities {
                if let Some(related_ids) = self.entity_index.get(entity) {
                    // [고도화] 과도한 노이즈(예: cmd.exe)로 인한 성능 저하 방지 캡 확대
                    if related_ids.len() > 200 { continue; }

                    for target_id in related_ids {
                        if target_id == &src.id { continue; }
                        
                        // [최적화 핵심] find() 대신 인덱스 맵 사용하여 속도 극대화
                        if let Some(tgt) = event_map.get(target_id) {
                            let delta = (tgt.timestamp - src.timestamp).num_seconds().abs();
                            if delta <= window {
                                let mut rel_type = "contextual_link".to_string();
                                let mut linked = false;

                                // [고도화] 정규화된 해시 기반 강결합
                                if let (ForensicEvent::Execution(s), ForensicEvent::Execution(t)) = (&src.original_event, &tgt.original_event) {
                                    if s.ioc_hash.is_some() && s.ioc_hash == t.ioc_hash { rel_type = "identical_binary".into(); linked = true; }
                                }
                                
                                // [고도화] PID/PPID 인과관계 (EVTX 연동)
                                if !linked {
                                    if let (ForensicEvent::Execution(s), ForensicEvent::Execution(t)) = (&src.original_event, &tgt.original_event) {
                                        let s_name = s.process_name.split('\\').last().unwrap_or("").to_lowercase();
                                        let t_parent = t.parent_process_name.split('\\').last().unwrap_or("").to_lowercase();
                                        if !s_name.is_empty() && s_name == t_parent { rel_type = "spawned_process".into(); linked = true; }
                                    }
                                }

                                if linked { rels.push(EventRelationship { source_id: src.id.clone(), target_id: tgt.id.clone(), relationship_type: rel_type, time_delta: delta }); }
                            }
                        }
                    }
                }
            }
        }
        self.relationships = rels;
    }

    pub fn build_campaigns(&mut self) {
        let event_map: HashMap<String, &TimelineEntry> = self.events.iter().map(|e| (e.id.clone(), e)).collect();
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for rel in &self.relationships {
            adj.entry(rel.source_id.clone()).or_insert_with(Vec::new).push(rel.target_id.clone());
            adj.entry(rel.target_id.clone()).or_insert_with(Vec::new).push(rel.source_id.clone());
        }

        let mut visited = HashSet::new();
        let mut count = 1; let mut campaigns = Vec::new();

        for entry in &self.events {
            if visited.contains(&entry.id) || entry.score < 20 { continue; }
            let mut cluster = Vec::new(); let mut q = VecDeque::new();
            q.push_back(entry.id.clone()); visited.insert(entry.id.clone());

            while let Some(id) = q.pop_front() {
                cluster.push(id.clone());
                if let Some(ns) = adj.get(&id) { for n in ns { if !visited.contains(n) { visited.insert(n.clone()); q.push_back(n.clone()); } } }
            }

            if cluster.len() >= 2 {
                // [최적화] 점수 합산 로직도 맵 조회로 변경
                let total_score: i32 = cluster.iter().filter_map(|id| event_map.get(id)).map(|e| e.score).sum();
                if total_score >= 50 {
                    campaigns.push(ThreatCampaign { id: format!("campaign-{}", count), name: format!("Threat Chain (Score: {})", total_score), total_score, sequences: cluster.iter().filter_map(|id| event_map.get(id)).map(|e| e.summary.clone()).collect(), associated_entities: cluster, confidence: 0.8, mitre_tactics: Vec::new() });
                    count += 1;
                }
            }
        }
        self.campaigns = campaigns;
    }
    
    pub fn get_filtered_timeline(&self) -> Vec<TimelineEntry> { self.events.clone() }
    pub fn get_relationships(&self) -> &Vec<EventRelationship> { &self.relationships }
    pub fn get_campaigns(&self) -> &Vec<ThreatCampaign> { &self.campaigns }
}