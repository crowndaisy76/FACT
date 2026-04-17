use crate::correlation::{TimelineEntry, EventRelationship, ThreatCampaign};
use serde_json::{json, Value};
use chrono::Utc;
use uuid::Uuid;

pub struct StixBuilder;

impl StixBuilder {
    pub fn generate_bundle(
        events: &[TimelineEntry],
        relationships: &[EventRelationship],
        campaigns: &[ThreatCampaign]
    ) -> Value {
        let mut objects = Vec::new();

        // 1. 캠페인 및 공격 패턴 (Sequences) 객체 생성
        for campaign in campaigns {
            objects.push(json!({
                "type": "campaign",
                "spec_version": "2.1",
                "id": &campaign.id,
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "name": &campaign.name,
                "description": format!("Total Score: {}, Confidence: {:.2}", campaign.total_score, campaign.confidence),
            }));
            
            // 변경된 필드(sequences)를 STIX attack-pattern 객체로 맵핑
            for seq in &campaign.sequences {
                let ap_id = format!("attack-pattern--{}", Uuid::new_v4());
                objects.push(json!({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": &ap_id,
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "name": seq,
                }));
                
                objects.push(json!({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": format!("relationship--{}", Uuid::new_v4()),
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "relationship_type": "uses",
                    "source_ref": &campaign.id,
                    "target_ref": ap_id,
                }));
            }
        }

        // 2. 개별 관측 데이터 (Observed Data) 객체 생성
        for event in events {
            objects.push(json!({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": &event.id,
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "first_observed": event.timestamp.to_rfc3339(),
                "last_observed": event.timestamp.to_rfc3339(),
                "number_observed": 1,
                "description": format!("[{}] {}", event.category, event.summary),
            }));
        }

        // 3. 인과관계 (Relationship) 객체 생성
        for rel in relationships {
            objects.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": format!("relationship--{}", Uuid::new_v4()),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "relationship_type": &rel.relationship_type,
                "source_ref": &rel.source_id,
                "target_ref": &rel.target_id,
            }));
        }

        // 최종 STIX Bundle 조립
        json!({
            "type": "bundle",
            "id": format!("bundle--{}", Uuid::new_v4()),
            "objects": objects
        })
    }
}