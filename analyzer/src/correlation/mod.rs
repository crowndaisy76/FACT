use models::event::ForensicEvent;
use chrono::{DateTime, Utc, Duration};
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BehaviorTemplate {
    CompleteKillChain,     // 파일 생성 -> 실행 -> 지속성 순서 보장
    FilelessAnomaly,       // 파일 생성 기록 부재 + 생애 최초 실행
    GlobalRareAnomaly,     // 시스템 전역 기준 생애 최초 실행
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessIdentity {
    pub guid: String,
    pub path: String,
    pub cmdline: String,
    pub entropy: f32, 
}

#[derive(Debug, Clone)]
pub struct EventRelationship {
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: String,
    pub time_delta: i64,
}

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub summary: String,
    pub original_event: ForensicEvent,
    pub identity: ProcessIdentity,
    pub parent_guid: Option<String>,
    pub is_rare_globally: bool,
    pub score: i32,
}

#[derive(Debug, Clone)]
pub struct ThreatCampaign {
    pub id: String,
    pub name: String,
    pub total_score: i32,
    pub sequences: Vec<String>,
    pub graph_depth: usize,
    pub associated_entities: Vec<String>,
    pub attack_patterns: Vec<String>,
    pub confidence: f32,
}

pub struct CorrelationEngine {
    events: Vec<TimelineEntry>,
    relationships: Vec<EventRelationship>,
    campaigns: Vec<ThreatCampaign>,
    global_execution_freq: HashMap<String, u32>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self { 
            events: Vec::new(), 
            relationships: Vec::new(), 
            campaigns: Vec::new(),
            global_execution_freq: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, raw_events: Vec<ForensicEvent>) {
        for event in &raw_events {
            if let ForensicEvent::Execution(e) = event {
                *self.global_execution_freq.entry(e.file_path.to_lowercase()).or_insert(0) += 1;
            }
        }

        for event in raw_events {
            let (identity, score, timestamp, category, summary, is_rare) = self.extract_global_context(&event);
            
            self.events.push(TimelineEntry {
                id: format!("observed-data--{}", Uuid::new_v4()),
                timestamp,
                category,
                summary,
                original_event: event,
                identity,
                parent_guid: None, 
                is_rare_globally: is_rare,
                score,
            });
        }
        
        self.events.sort_by_key(|e| e.timestamp);
    }

    fn calculate_entropy(s: &str) -> f32 {
        if s.is_empty() { return 0.0; }
        let mut frequencies = [0usize; 256];
        for b in s.as_bytes() { frequencies[*b as usize] += 1; }
        let len = s.len() as f32;
        frequencies.iter().filter(|&&f| f > 0).map(|&f| {
            let p = f as f32 / len;
            -p * p.log2()
        }).sum()
    }

    fn extract_directory(path: &str) -> String {
        if let Some(last_slash) = path.rfind('\\') {
            path[..last_slash].to_string()
        } else {
            String::new()
        }
    }

    fn extract_global_context(&self, event: &ForensicEvent) -> (ProcessIdentity, i32, DateTime<Utc>, String, String, bool) {
        let mut score = 0;
        let mut is_rare = false;

        let (timestamp, category, summary, identity) = match event {
            ForensicEvent::Execution(e) => {
                let path = e.file_path.to_lowercase();
                let name = e.process_name.to_lowercase();
                let freq = self.global_execution_freq.get(&path).unwrap_or(&0);
                
                if *freq == 1 { 
                    is_rare = true; 
                    score += 40; 
                }

                let identity = ProcessIdentity {
                    guid: format!("{}-{}", name, e.timestamp.timestamp_nanos_opt().unwrap_or(0)),
                    path, 
                    cmdline: String::new(), 
                    entropy: 0.0,
                };
                
                (e.timestamp, "Execution".to_string(), format!("Run: {}", name), identity)
            },
            ForensicEvent::Persistence(p) => {
                let name = p.target_name.to_lowercase();
                if p.persistence_type.to_lowercase().contains("hidden") { score += 30; }
                let identity = ProcessIdentity { guid: format!("ps-{}", name), path: p.target_path.clone(), cmdline: "".into(), entropy: 0.0 };
                (p.timestamp, "Persistence".to_string(), format!("Persistence: {}", name), identity)
            },
            ForensicEvent::FileSystemActivity(f) => {
                let name = f.file_name.split('\\').last().unwrap_or(&f.file_name).to_lowercase();
                let identity = ProcessIdentity { guid: "fs".into(), path: f.file_name.clone(), cmdline: "".into(), entropy: 0.0 };
                (f.timestamp, "FileSystem".to_string(), format!("File: {}", name), identity)
            },
            _ => {
                let identity = ProcessIdentity { guid: "other".into(), path: "".into(), cmdline: "".into(), entropy: 0.0 };
                (Utc::now(), "Other".to_string(), "Other Event".into(), identity)
            }
        };

        (identity, score, timestamp, category, summary, is_rare)
    }

    pub fn analyze_multi_hop_causality(&mut self) {
        let mut rels = Vec::new();
        let cluster_window = Duration::minutes(5);

        for i in 0..self.events.len() {
            for j in (i + 1)..self.events.len() {
                let src = &self.events[i];
                let tgt = &self.events[j];
                let delta = (tgt.timestamp - src.timestamp).num_seconds().abs();
                
                if delta > cluster_window.num_seconds() { continue; }

                let mut linked = false;

                if src.category == "Execution" {
                    if let ForensicEvent::Execution(e) = &src.original_event {
                        let tgt_path = &tgt.identity.path;
                        if !tgt_path.is_empty() && e.referenced_files.iter().any(|p| p.to_lowercase().contains(tgt_path)) {
                            rels.push(EventRelationship {
                                source_id: src.id.clone(),
                                target_id: tgt.id.clone(),
                                relationship_type: "loaded_resource".into(),
                                time_delta: delta,
                            });
                            linked = true;
                        }
                    }
                }

                if !linked {
                    let src_dir = Self::extract_directory(&src.identity.path);
                    let tgt_dir = Self::extract_directory(&tgt.identity.path);
                    
                    if !src_dir.is_empty() && src_dir == tgt_dir && src_dir.len() > 3 {
                        rels.push(EventRelationship {
                            source_id: src.id.clone(),
                            target_id: tgt.id.clone(),
                            relationship_type: "shared_directory".into(),
                            time_delta: delta,
                        });
                    }
                }
            }
        }
        self.relationships = rels;
    }

    pub fn build_campaigns(&mut self) {
        let mut adj: HashMap<String, Vec<EventRelationship>> = HashMap::new();
        for rel in &self.relationships {
            adj.entry(rel.source_id.clone()).or_insert_with(Vec::new).push(rel.clone());
            adj.entry(rel.target_id.clone()).or_insert_with(Vec::new).push(EventRelationship {
                source_id: rel.target_id.clone(), target_id: rel.source_id.clone(),
                relationship_type: rel.relationship_type.clone(), time_delta: rel.time_delta,
            });
        }

        let mut visited = HashSet::new();
        let mut campaigns = Vec::new();

        for entry in &self.events {
            if visited.contains(&entry.id) { continue; }

            let mut cluster = Vec::new();
            let mut stack = VecDeque::new();
            let mut cluster_events = Vec::new();
            
            stack.push_back(entry.id.clone());
            visited.insert(entry.id.clone());

            while let Some(node_id) = stack.pop_back() {
                cluster.push(node_id.clone());
                if let Some(e) = self.events.iter().find(|x| x.id == node_id) {
                    cluster_events.push(e.clone());
                    if let Some(rels) = adj.get(&node_id) {
                        for rel in rels {
                            if !visited.contains(&rel.target_id) {
                                visited.insert(rel.target_id.clone());
                                stack.push_back(rel.target_id.clone());
                            }
                        }
                    }
                }
            }

            cluster_events.sort_by_key(|e| e.timestamp);
            
            let mut total_score: i32 = cluster_events.iter().map(|e| e.score).sum();
            let mut detected_templates = Vec::new();

            let has_rare = cluster_events.iter().any(|e| e.is_rare_globally);
            let has_execution = cluster_events.iter().any(|e| e.category == "Execution");
            let has_file_drop = cluster_events.iter().any(|e| e.category == "FileSystem");
            let has_persist = cluster_events.iter().any(|e| e.category == "Persistence");

            if has_file_drop && has_execution && has_persist {
                let drop_time = cluster_events.iter().find(|e| e.category == "FileSystem").unwrap().timestamp;
                let exec_time = cluster_events.iter().find(|e| e.category == "Execution").unwrap().timestamp;
                let persist_time = cluster_events.iter().find(|e| e.category == "Persistence").unwrap().timestamp;

                if drop_time <= exec_time && exec_time <= persist_time {
                    detected_templates.push(format!("{:?}", BehaviorTemplate::CompleteKillChain));
                    total_score += 100;
                }
            }

            if has_execution && has_rare && !has_file_drop {
                detected_templates.push(format!("{:?}", BehaviorTemplate::FilelessAnomaly));
                total_score += 80;
            }

            if has_rare {
                detected_templates.push(format!("{:?}", BehaviorTemplate::GlobalRareAnomaly));
            }

            if total_score >= 80 || !detected_templates.is_empty() {
                let template_name = if detected_templates.contains(&format!("{:?}", BehaviorTemplate::CompleteKillChain)) {
                    "Confirmed Kill-Chain (Drop -> Exec -> Persist)".to_string()
                } else {
                    format!("High Confidence Threat Chain (Score: {})", total_score)
                };

                campaigns.push(ThreatCampaign {
                    id: format!("campaign--{}", Uuid::new_v4()),
                    name: template_name,
                    total_score,
                    sequences: detected_templates,
                    graph_depth: cluster.len(),
                    associated_entities: cluster,
                    attack_patterns: vec!["T1059".into(), "T1547".into()],
                    confidence: if total_score > 100 { 0.99 } else { 0.85 },
                });
            }
        }
        self.campaigns = campaigns;

        let mut valid_ids = HashSet::new();
        for c in &self.campaigns { 
            for id in &c.associated_entities { valid_ids.insert(id.clone()); } 
        }
        self.relationships.retain(|r| valid_ids.contains(&r.source_id) && valid_ids.contains(&r.target_id));
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