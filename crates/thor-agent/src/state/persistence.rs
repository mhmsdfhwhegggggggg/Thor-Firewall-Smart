use anyhow::Result;
use sled::Db;
use tracing::info;

pub struct StateManager {
    db: Db,
}

impl StateManager {
    pub fn new(db_path: &str) -> Result<Self> {
        // Open or create embedded DB
        let config = sled::Config::default()
            .path(db_path)
            .cache_capacity(100 * 1024 * 1024) // 100MB Cache
            .mode(sled::Mode::HighThroughput);
            
        let db = config.open()?;
        info!("✅ State Persistence initialized at: {}", db_path);
        Ok(Self { db })
    }

    /// Save state of a critical incident (Checkpoint)
    pub fn save_incident_state(&self, incident_id: &str, state_json: &[u8]) -> Result<()> {
        let tree = self.db.open_tree("active_incidents")?;
        tree.insert(incident_id, state_json)?;
        tree.flush()?; // sync to disk immediately
        Ok(())
    }

    /// Restore context upon agent restart (Crash Recovery)
    pub fn recover_active_incidents(&self) -> Result<Vec<Vec<u8>>> {
        let tree = self.db.open_tree("active_incidents")?;
        let mut incidents = Vec::new();
        
        for item in tree.iter() {
            let (_key, value) = item?;
            incidents.push(value.to_vec());
        }
        
        info!("🔄 Recovered {} active incidents from persistent state", incidents.len());
        Ok(incidents)
    }
}
