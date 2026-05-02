import json
import os

def load_stix_data(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return None

def extract_threat_narrative(stix_data):
    objects = stix_data.get('objects', [])
    
    campaigns = {}
    attack_patterns = {}
    relationships = []
    
    for obj in objects:
        obj_type = obj.get('type')
        obj_id = obj.get('id')
        
        if obj_type == 'campaign':
            campaigns[obj_id] = obj
        elif obj_type == 'attack-pattern':
            attack_patterns[obj_id] = obj
        elif obj_type == 'relationship':
            relationships.append(obj)
            
    narrative_parts = []
    narrative_parts.append("### Threat Intelligence Report (FACT Engine) ###\n")
    
    for camp_id, camp in campaigns.items():
        # Score가 낮은 노이즈 캠페인은 아예 무시 (점수 100점 이상만 컨텍스트에 포함)
        desc = camp.get('description', '')
        score = 0
        if "Total Score:" in desc:
            try:
                score = int(desc.split('Total Score: ')[1].split(',')[0])
            except:
                pass
                
        if score < 100:
            continue
            
        name = camp.get('name', 'Unknown Campaign')
        narrative_parts.append(f"==== Campaign: {name} ====")
        narrative_parts.append(f"Description:\n{desc}")
        
        camp_entities = []
        for rel in relationships:
            if rel.get('source_ref') == camp_id and rel.get('target_ref') in attack_patterns:
                camp_entities.append(rel.get('target_ref'))
                
        if not camp_entities:
            narrative_parts.append("Associated Events: None found.\n")
            continue
            
        narrative_parts.append("\nExecution Timeline & Relationships (Only valid chains):")
        
        unique_relations = set()
        
        for entity_id in camp_entities:
            ap_name = attack_patterns[entity_id].get('name', 'Unknown Event')
            
            for rel in relationships:
                if rel.get('source_ref') == entity_id:
                    target_id = rel.get('target_ref')
                    rel_type = rel.get('relationship_type')
                    if target_id in attack_patterns:
                        target_name = attack_patterns[target_id].get('name')
                        
                        # [핵심] 노이즈 필터링: (Parent: ) 가 포함된 불완전한 노드는 텍스트 변환에서 제외!
                        if "(Parent: )" in ap_name or "(Parent: )" in target_name:
                            continue
                            
                        # 자가 참조(Self-loop) 제외
                        if ap_name == target_name:
                            continue
                            
                        unique_relations.add(f"  - 부모 프로세스 [{ap_name}] 가 자식 프로세스 [{target_name}] 를 실행했습니다.")
        
        if not unique_relations:
            narrative_parts.append("  - No valid process chains found (Orphan nodes only).")
        else:
            for rel_str in sorted(unique_relations):
                narrative_parts.append(rel_str)
                        
        narrative_parts.append("\n")

    return "\n".join(narrative_parts)

if __name__ == "__main__":
    stix_file = "../Results/final_threat_report.json" # 경로 확인!
    data = load_stix_data(stix_file)
    if data:
        narrative = extract_threat_narrative(data)
        with open("rag_context.txt", "w", encoding='utf-8') as f:
            f.write(narrative)
        print("[+] Successfully parsed STIX and generated Deduplicated & Filtered RAG context.")