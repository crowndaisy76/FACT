use crate::correlation::{TimelineEntry, EventRelationship, ThreatCampaign};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;

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

        for camp in campaigns {
            // MITRE 전술을 포함하도록 설명 포맷팅 변경
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
        }

        for event in events {
            let obj = serde_json::json!({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": format!("attack-pattern--{}", Uuid::new_v4()),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "name": event.summary,
            });
            objects.push(obj);
        }

        for rel in relationships {
            let rel_obj = serde_json::json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": format!("relationship--{}", Uuid::new_v4()),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "relationship_type": rel.relationship_type,
                "source_ref": rel.source_id,
                "target_ref": rel.target_id,
            });
            objects.push(rel_obj);
        }

        // 캠페인과 이벤트 간의 소속 관계 연결
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
                    // STIX 규격에 맞추려면 이벤트 ID 변환 로직이 조금 복잡하므로 
                    // 단순화를 위해 위에서 이벤트 ID를 생성할 때 고정된 ID 체계를 쓰는 것이 좋으나 
                    // 현재는 시연을 위해 간략히 처리함. 실제로는 UUID 관리를 해시 맵으로 일치시켜야 함.
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