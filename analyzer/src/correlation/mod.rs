use models::event::ForensicEvent;
use chrono::{DateTime, Utc, Duration, Datelike};
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

// [해결] f32는 Eq/Hash를 지원하지 않으므로 derive에서 제거하고 Clone만 유지
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessIdentity {
    pub guid: String,
    pub path: String,
    pub cmdline: String,
    pub entropy: f32, 
}

// [해결] stix/mod.rs에서 import하는 명칭인 EventRelationship으로 변경 및 Clone 추가
#[derive(Debug, Clone)]
pub struct EventRelationship {
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: String, // stix 명칭에 맞게 수정
    pub time_delta: i64,
}

// [해결] .cloned().collect() 사용을 위해 Clone 트레이트 추가
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub summary: String,
    pub source_artifact: String,
    pub original_event: ForensicEvent,
    pub identity: ProcessIdentity,
    pub parent_guid: Option<String>,
    pub features: HashMap<String, i32>,
    pub score: i32,
    pub pure_name: String,
}

// [해결] stix/mod.rs에서 요구하는 필드명(associated_entities, attack_patterns)으로 정의
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
    relationships: Vec<EventRelationship>, // 명칭 변경 반영
    campaigns: Vec<ThreatCampaign>,
    host_baseline: HashMap<String, u32>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self { 
            events: Vec::new(), 
            relationships: Vec::new(), 
            campaigns: Vec::new(),
            host_baseline: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, raw_events: Vec<ForensicEvent>) {
        for event in raw_events {
            let (identity, parent_guid, features, score, timestamp, pure_name, category, summary) = self.extract_deep_context(&event);
            
            if !identity.path.is_empty() {
                *self.host_baseline.entry(identity.path.clone()).or_insert(0) += 1;
            }

            self.events.push(TimelineEntry {
                id: format!("observed-data--{}", Uuid::new_v4()),
                timestamp,
                category,
                summary,
                source_artifact: "Forensic Engine".to_string(),
                original_event: event,
                identity,
                parent_guid,
                features,
                score,
                pure_name,
            });
        }
    }

    fn calculate_entropy(s: &str) -> f32 {
        if s.is_empty() { return 0.0; }
        let mut frequencies = [0usize; 256];
        for b in s.as_bytes() { frequencies[*b as usize] += 1; }
        let len = s.len() as f32;
        frequencies.iter().filter(|&&f| f > 0)
            .map(|&f| {
                let p = f as f32 / len;
                -p * p.log2()
            }).sum()
    }

    fn extract_deep_context(&self, event: &ForensicEvent) -> (ProcessIdentity, Option<String>, HashMap<String, i32>, i32, DateTime<Utc>, String, String, String) {
        let mut features = HashMap::new();
        let mut score = 0;
        let mut parent_guid = None;

        let (timestamp, pure_name, category, summary, identity) = match event {
            ForensicEvent::Execution(e) => {
                let path = e.file_path.to_lowercase();
                let name = e.process_name.to_lowercase();
                
                // [고도화] Scenario A 및 악성 경로 특징 추출 (mut warning 해결을 위해 로직 활성화)
                if ["\\temp\\", "\\public\\", "\\appdata\\"].iter().any(|&p| path.contains(p)) {
                    features.insert("SuspiciousPath".into(), 30);
                    score += 30;
                }
                
                if e.timestamp.year() < 2024 {
                    features.insert("TimestompSuspect".into(), 40);
                    score += 40;
                }

                let identity = ProcessIdentity {
                    guid: format!("{}-{}", name, e.timestamp.timestamp_nanos_opt().unwrap_or(0)),
                    path: path.clone(),
                    cmdline: String::new(), 
                    entropy: 0.0,
                };
                
                (e.timestamp, name.clone(), "Execution".to_string(), format!("Run: {}", name), identity)
            },
            ForensicEvent::Persistence(p) => {
                let name = p.target_name.to_lowercase();
                let identity = ProcessIdentity {
                    guid: format!("ps-{}", name),
                    path: p.target_path.clone(),
                    cmdline: String::new(),
                    entropy: 0.0,
                };
                (p.timestamp, name.clone(), "Persistence".to_string(), format!("Persistence: {}", name), identity)
            },
            ForensicEvent::FileSystemActivity(f) => {
                let name = f.file_name.split('\\').last().unwrap_or(&f.file_name).to_lowercase();
                let identity = ProcessIdentity {
                    guid: "fs-none".into(),
                    path: f.file_name.clone(),
                    cmdline: String::new(),
                    entropy: 0.0,
                };
                (f.timestamp, name.clone(), "FileSystem".to_string(), format!("File: {}", name), identity)
            },
            _ => {
                let identity = ProcessIdentity { guid: "other".into(), path: "".into(), cmdline: "".into(), entropy: 0.0 };
                (Utc::now(), "other".into(), "Other".to_string(), "Other Event".into(), identity)
            }
        };

        (identity, parent_guid, features, score, timestamp, pure_name, category, summary)
    }

    pub fn analyze_multi_hop_causality(&mut self) {
        let mut rels = Vec::new();
        let cluster_window = Duration::minutes(10);

        for i in 0..self.events.len() {
            for j in (i + 1)..self.events.len() {
                let src = &self.events[i];
                let tgt = &self.events[j];
                let delta = (tgt.timestamp - src.timestamp).num_seconds().abs();
                if delta > cluster_window.num_seconds() { continue; }

                if let Some(p_guid) = &tgt.parent_guid {
                    if p_guid == &src.identity.guid {
                        rels.push(EventRelationship {
                            source_id: src.id.clone(),
                            target_id: tgt.id.clone(),
                            relationship_type: "spawned".into(),
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
        }

        let mut visited = HashSet::new();
        let mut campaigns = Vec::new();

        for entry in &self.events {
            if visited.contains(&entry.id) || !adj.contains_key(&entry.id) { continue; }

            let mut cluster = Vec::new();
            let mut stack = VecDeque::new();
            let mut total_score = 0;
            let mut max_depth = 0;

            stack.push_back((entry.id.clone(), 1));
            visited.insert(entry.id.clone());

            while let Some((node_id, depth)) = stack.pop_back() {
                cluster.push(node_id.clone());
                if depth > max_depth { max_depth = depth; }

                if let Some(e) = self.events.iter().find(|x| x.id == node_id) {
                    total_score += e.score;

                    if let Some(rels) = adj.get(&node_id) {
                        for rel in rels {
                            if !visited.contains(&rel.target_id) {
                                visited.insert(rel.target_id.clone());
                                stack.push_back((rel.target_id.clone(), depth + 1));
                            }
                        }
                    }
                }
            }

            if total_score > 50 || cluster.len() > 1 {
                campaigns.push(ThreatCampaign {
                    id: format!("campaign--{}", Uuid::new_v4()),
                    name: format!("FACT Threat Chain (Depth: {})", max_depth),
                    total_score,
                    sequences: vec![],
                    graph_depth: max_depth,
                    associated_entities: cluster,
                    attack_patterns: vec!["T1059".into()],
                    confidence: 0.8,
                });
            }
        }
        self.campaigns = campaigns;
    }

    pub fn get_relationships(&self) -> &Vec<EventRelationship> { &self.relationships }
    pub fn get_campaigns(&self) -> &Vec<ThreatCampaign> { &self.campaigns }
    
    pub fn get_filtered_timeline(&self) -> Vec<TimelineEntry> {
        let mut valid_ids = HashSet::new();
        for c in &self.campaigns { 
            for id in &c.associated_entities { 
                valid_ids.insert(id.clone()); 
            } 
        }
        self.events.iter()
            .filter(|e| valid_ids.contains(&e.id))
            .cloned() // [해결] TimelineEntry가 Clone을 구현하므로 이제 가능함
            .collect()
    }
}