//! Attack Graph Builder 
//! The "Brain" that connects isolated events into a cohesive attack storyline. 
//! This feeds both the GNN model and the Dashboard visualization. 
use crate::events::enrichment::EnrichedNetworkEvent; 
use crate::state::process::ProcessInfo; // (نفترض وجوده) 
use dashmap::DashMap; 
use std::collections::HashSet; 
use std::sync::Arc; 
use tracing::debug; 

/// عقدة في رسم الهجوم (Process, File, or IP) 
#[derive(Debug, Clone, PartialEq, Eq, Hash)] 
pub enum GraphNode { 
    Process { pid: u32, name: String, path: String }, 
    File { path: String, hash: String }, 
    IpAddress { ip: String, is_malicious: bool }, 
} 

/// حافة تمثل العلاقة بين عقدتين
#[derive(Debug, Clone)] 
pub struct GraphEdge { 
    pub source: GraphNode, 
    pub target: GraphNode, 
    pub action: String, // e.g., "executed", "connected_to", "modified" 
    pub timestamp_ns: u64, 
} 

/// مدير رسم الهجوم النشط
pub struct AttackGraphBuilder { 
    /// تخزين العقد النشطة حاليا في النظام
    active_nodes: Arc<DashMap<GraphNode, u64>>, // Node -> Last Seen Timestamp 
    /// تخزين الحوادث (الهجمات) المكتشفة
    active_incidents: Arc<DashMap<String, Vec<GraphEdge>>>, // Incident ID -> Edges 
} 

impl AttackGraphBuilder { 
    pub fn new() -> Self { 
        Self { 
            active_nodes: Arc::new(DashMap::new()), 
            active_incidents: Arc::new(DashMap::new()), 
        } 
    } 

    /// معالجة حدث شبكي جديد وربطه بسياقه
    pub fn process_network_event(&self, event: &EnrichedNetworkEvent) -> Option<Vec<GraphEdge>> { 
        let now = std::time::SystemTime::now() 
            .duration_since(std::time::UNIX_EPOCH) 
            .unwrap() 
            .as_nanos() as u64; 

        // 1. تعريف العقد
        let proc_node = GraphNode::Process { 
            pid: event.raw.pid, 
            name: event.process_name.clone(), 
            path: event.process_path.clone(), 
        }; 

        let ip_node = GraphNode::IpAddress { 
            ip: event.raw.dst_ip4.to_string(), 
            is_malicious: event.is_malicious_ip, 
        }; 

        // 2. تحديث حالة النشاط
        self.active_nodes.insert(proc_node.clone(), now); 
        self.active_nodes.insert(ip_node.clone(), now); 

        // 3. إنشاء الحافة (العلاقة)
        let edge = GraphEdge { 
            source: proc_node, 
            target: ip_node, 
            action: "network_connect".to_string(), 
            timestamp_ns: event.raw.timestamp_ns, 
        }; 

        // 4. إذا كان هناك مؤشر اختراق نبدأ "حادث" جديد (Incident)
        if event.is_malicious_ip || event.context_tags.iter().any(|t| t.contains("malware")) { 
            let incident_id = format!("INC-{}-{}", event.raw.pid, now); 
            let mut incidents = self.active_incidents.entry(incident_id).or_insert_with(Vec::new); 
            incidents.push(edge.clone()); 

            debug!(" New Attack Graph Incident initiated: {} nodes, {} edges", 
                self.active_nodes.len(), incidents.len()); 

            // إرجاع الحافة لتغذية نموذج GNN فورا
            Some(vec![edge]) 
        } else { 
            None 
        } 
    } 

    /// تنظيف العقد القديمة لمنع تسرب الذاكرة (مهمة خلفية)
    pub fn cleanup_stale_nodes(&self, ttl_ns: u64) { 
        let now = std::time::SystemTime::now() 
            .duration_since(std::time::UNIX_EPOCH) 
            .unwrap() 
            .as_nanos() as u64; 

        self.active_nodes.retain(|_node, last_seen| { 
            now - *last_seen < ttl_ns 
        }); 
    } 
}
