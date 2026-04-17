use crate::correlation::{TimelineEntry, EventRelationship, ThreatCampaign};
use chrono::Utc;
use models::event::ForensicEvent;
use serde_json::{json, Value};
use uuid::Uuid;

pub struct StixBuilder;

impl StixBuilder {
    pub fn generate_bundle(
        timeline: &[TimelineEntry], 
        relationships: &[EventRelationship],
        campaigns: &[ThreatCampaign]
    ) -> Value {
        let mut objects = Vec::new();

        let identity_id = format!("identity--{}", Uuid::new_v4());
        let identity = json!({
            "type": "identity",
            "id": identity_id.clone(),
            "created": Utc::now().to_rfc3339(),
            "modified": Utc::now().to_rfc3339(),
            "name": "FACT Engine",
            "identity_class": "system"
        });
        objects.push(identity);

        // 1. Observed Data 생성 (spec_version 2.0 호환)
        for entry in timeline {
            let observables = Self::map_to_observables(&entry.original_event);
            let observed_data = json!({
                "type": "observed-data",
                "id": entry.id.clone(),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "first_observed": entry.timestamp.to_rfc3339(),
                "last_observed": entry.timestamp.to_rfc3339(),
                "number_observed": 1,
                "objects": observables,
                "created_by_ref": identity_id
            });
            objects.push(observed_data);
        }

        // 2. Relationship 생성
        for rel in relationships {
            let relationship_data = json!({
                "type": "relationship",
                "id": format!("relationship--{}", Uuid::new_v4()),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "relationship_type": rel.relationship_type,
                "source_ref": rel.source_id,
                "target_ref": rel.target_id,
                "created_by_ref": identity_id
            });
            objects.push(relationship_data);
        }

        // 3. Campaign 및 Attack-Pattern 생성
        for campaign in campaigns {
            let campaign_id = campaign.id.clone();
            objects.push(json!({
                "type": "campaign",
                "id": campaign_id.clone(),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "name": campaign.name,
                "created_by_ref": identity_id
            }));

            for entity_id in &campaign.associated_entities {
                objects.push(json!({
                    "type": "relationship",
                    "id": format!("relationship--{}", Uuid::new_v4()),
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "relationship_type": "related-to",
                    "source_ref": entity_id,
                    "target_ref": campaign_id.clone(),
                    "created_by_ref": identity_id
                }));
            }

            for ttp in &campaign.attack_patterns {
                let ap_id = format!("attack-pattern--{}", Uuid::new_v4());
                objects.push(json!({
                    "type": "attack-pattern",
                    "id": ap_id.clone(),
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "name": ttp,
                    "created_by_ref": identity_id
                }));

                objects.push(json!({
                    "type": "relationship",
                    "id": format!("relationship--{}", Uuid::new_v4()),
                    "created": Utc::now().to_rfc3339(),
                    "modified": Utc::now().to_rfc3339(),
                    "relationship_type": "uses",
                    "source_ref": campaign_id.clone(),
                    "target_ref": ap_id,
                    "created_by_ref": identity_id
                }));
            }
        }

        json!({
            "type": "bundle",
            "id": format!("bundle--{}", Uuid::new_v4()),
            "objects": objects
        })
    }

    fn map_to_observables(event: &ForensicEvent) -> Value {
        match event {
            ForensicEvent::Execution(e) => {
                json!({
                    "0": {
                        "type": "process",
                        "name": e.process_name,
                        "command_line": e.file_path,
                        // [Fix] 하이픈(-)을 언더스코어(_)로 변경
                        "x_fact_execution_metrics": {
                            "run_count": e.run_count,
                            "source": e.source_artifact
                        }
                    }
                })
            },
            ForensicEvent::Persistence(p) => {
                json!({
                    "0": {
                        "type": "process",
                        "name": p.target_name,
                        "command_line": p.target_path,
                        "x_fact_persistence": {
                            "mechanism": p.persistence_type,
                            "source": p.source_artifact
                        }
                    }
                })
            },
            ForensicEvent::Logon(l) => {
                json!({
                    "0": {
                        "type": "user-account",
                        "account_login": l.account_name,
                        "x_fact_logon": {
                            "logon_type": l.logon_type,
                            "status": l.status
                        }
                    }
                })
            },
            ForensicEvent::FileSystemActivity(f) => {
                let file_type = if f.is_dir { "directory" } else { "file" };
                json!({
                    "0": {
                        "type": file_type,
                        "name": f.file_name,
                        "x_fact_fs_activity": {
                            "action": f.reason,
                            "source": f.source_artifact
                        }
                    }
                })
            },
            ForensicEvent::SystemActivity(s) => {
                json!({
                    "0": {
                        "type": "x_fact_system_event",
                        "activity_type": s.activity_type,
                        "description": s.description
                    }
                })
            }
        }
    }
}