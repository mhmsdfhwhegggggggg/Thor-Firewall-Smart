//! IOC persistent store — sync Bloom+DashMap cache from/to PostgreSQL.

use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn};

use crate::db::ThorDb;
use crate::state::ioc::{IocEntry, IocType};

pub async fn bulk_persist(db: &ThorDb, iocs: &[IocEntry], source: &str) -> Result<usize> {
    if iocs.is_empty() { return Ok(0); }
    let mut count = 0usize;
    // Batch in groups of 1000
    for chunk in iocs.chunks(1000) {
        let values:       Vec<&str> = chunk.iter().map(|i| i.value.as_str()).collect();
        let ioc_types:    Vec<String> = chunk.iter().map(|i| format!("{:?}", i.ioc_type).to_lowercase()).collect();
        let threat_levels: Vec<&str> = chunk.iter().map(|i| i.threat_level.as_str()).collect();
        let sources:      Vec<&str> = chunk.iter().map(|_| source).collect();

        let r = sqlx::query!(
            r#"
            INSERT INTO ioc_entries (value, ioc_type, threat_level, source, last_seen)
            SELECT v, t::ioc_type, tl, s, NOW()
            FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[]) AS x(v, t, tl, s)
            ON CONFLICT (value, ioc_type) DO UPDATE SET
                hit_count = ioc_entries.hit_count + 1,
                last_seen = NOW(),
                source    = EXCLUDED.source
            "#,
            &values as &[&str],
            &ioc_types as &[String],
            &threat_levels as &[&str],
            &sources as &[&str],
        )
        .execute(db.pool.as_ref())
        .await?;
        count += r.rows_affected() as usize;
    }
    info!("💾 Persisted {} IOC entries from {}", count, source);
    Ok(count)
}

/// Load all IOC entries at startup to seed the Bloom filter.
pub async fn load_all(db: &ThorDb) -> Result<Vec<IocEntry>> {
    let rows = sqlx::query!(
        "SELECT value, ioc_type::text, threat_level, source, tags FROM ioc_entries"
    )
    .fetch_all(db.pool.as_ref())
    .await?;

    let entries = rows.into_iter().filter_map(|r| {
        let ioc_type = match r.ioc_type.as_deref() {
            Some("ip_address") => IocType::IpAddress,
            Some("domain")     => IocType::Domain,
            Some("file_hash")  => IocType::FileHash,
            Some("url")        => IocType::Url,
            _ => return None,
        };
        Some(IocEntry {
            value: r.value,
            ioc_type,
            threat_level: r.threat_level,
            source: r.source,
            tags: r.tags.unwrap_or_default(),
        })
    }).collect();

    Ok(entries)
}
