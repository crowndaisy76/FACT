use crate::correlation::{TimelineEntry, EventRelationship, ThreatCampaign};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

pub struct StixBuilder;

impl StixBuilder {
    pub fn generate_bundle(
        events: &[TimelineEntry],
        relationships: &[EventRelationship],
        campaigns: &[ThreatCampaign]
    ) -> StixBundle {
        let mut objects = Vec::new();
        
        let mut linked_node_ids = HashSet::new();
        for rel in relationships {
            linked_node_ids.insert(rel.source_id.clone());
            linked_node_ids.insert(rel.target_id.clone());
        }

        for camp in campaigns {
            let mut desc = format!("Total Score: {}, Confidence: {:.2}", camp.total_score, camp.confidence);
            if !camp.mitre_tactics.is_empty() {
                desc = format!("{}\nMITRE TTPs: {}", desc, camp.mitre_tactics.join(", "));
            }

            let camp_obj = serde_json::json!({
                "type": "campaign",
                "spec_version": "2.1",
                "id": camp.id,
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "name": camp.name,
                "description": desc,
            });
            objects.push(camp_obj);
            
            for entity_id in &camp.associated_entities {
                linked_node_ids.insert(entity_id.clone());
            }
        }

        for event in events {
            let is_linked = linked_node_ids.contains(&event.id);
            let is_orphan = event.summary.contains("(Parent: )") || event.summary.contains("(Parent: unknown)");
            
            let has_ttp = !event.matched_ttps.is_empty();

            if is_linked || event.score > 40 || has_ttp || !is_orphan {
                let obj = serde_json::json!({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    // [수정 핵심] 무작위 UUID가 아닌, 상관분석 엔진의 event.id를 직접 사용한다.
                    "id": format!("attack-pattern--{}", event.id), 
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "name": event.summary,
                });
                objects.push(obj);
            }
        }

        for rel in relationships {
            let rel_obj = serde_json::json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": format!("relationship--{}", Uuid::new_v4()),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "relationship_type": rel.relationship_type,
                // 관계 객체도 마찬가지로 엔진의 ID 포맷을 따른다.
                "source_ref": format!("attack-pattern--{}", rel.source_id),
                "target_ref": format!("attack-pattern--{}", rel.target_id),
            });
            objects.push(rel_obj);
        }

        for camp in campaigns {
            for entry_id in &camp.associated_entities {
                let camp_rel = serde_json::json!({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": format!("relationship--{}", Uuid::new_v4()),
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "relationship_type": "uses",
                    "source_ref": camp.id,
                    "target_ref": format!("attack-pattern--{}", entry_id), 
                });
                objects.push(camp_rel);
            }
        }

        StixBundle {
            bundle_type: "bundle".to_string(),
            id: format!("bundle--{}", Uuid::new_v4()),
            objects,
        }
    }
}