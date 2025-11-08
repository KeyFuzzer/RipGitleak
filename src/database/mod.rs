//! SQLite数据库存储模块
//! 
//! 为大型代码库扫描提供高性能的SQLite存储支持

use rusqlite::{Connection, params, Result as SqlResult};
use std::path::Path;
use crate::output::formatter::MatchResult;

/// SQLite数据库管理器
pub struct DatabaseManager {
    conn: Connection,
}

impl DatabaseManager {
    /// 创建新的数据库管理器
    pub fn new(db_path: &Path) -> SqlResult<Self> {
        let conn = Connection::open(db_path)?;
        
        // 创建表结构
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                pattern_name TEXT NOT NULL,
                confidence TEXT NOT NULL,
                integrity TEXT NOT NULL,
                matched_text TEXT NOT NULL,
                line_content TEXT NOT NULL,
                context TEXT NOT NULL,
                file_hash TEXT,
                scan_session TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_file_path ON scan_results(file_path);
            CREATE INDEX IF NOT EXISTS idx_pattern_name ON scan_results(pattern_name);
            CREATE INDEX IF NOT EXISTS idx_confidence ON scan_results(confidence);
            CREATE INDEX IF NOT EXISTS idx_integrity ON scan_results(integrity);
            CREATE INDEX IF NOT EXISTS idx_scan_session ON scan_results(scan_session);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_results(scan_timestamp);"
        )?;

        Ok(Self { conn })
    }


    /// 分批次插入大量结果（优化版本）
    pub fn insert_results_batch_optimized(
        &mut self,
        results: &[MatchResult],
        scan_session: Option<&str>,
        batch_size: usize,
    ) -> SqlResult<usize> {
        if results.is_empty() {
            return Ok(0);
        }

        // 优化设置
        self.conn.execute_batch(
            "PRAGMA synchronous = OFF; \
             PRAGMA journal_mode = MEMORY; \
             PRAGMA cache_size = -64000; \
             PRAGMA temp_store = MEMORY;"
        )?;

        let mut total_inserted = 0;
        
        for chunk in results.chunks(batch_size) {
            let tx = self.conn.transaction()?;
            
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO scan_results (
                        file_path, line_number, pattern_name, confidence, 
                        integrity, matched_text, line_content, context, scan_session
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )?;

                for result in chunk {
                    stmt.execute(params![
                        result.file_path.to_string_lossy(),
                        result.line_number as i64,
                        &result.pattern_name,
                        &result.confidence,
                        &result.integrity,
                        &result.matched_text,
                        &result.line_content,
                        &result.context,
                        scan_session
                    ])?;
                }
            }
            
            tx.commit()?;
            total_inserted += chunk.len();
            
            // 每处理一定批次后输出进度
            if total_inserted % (batch_size * 10) == 0 {
                println!("已插入 {} 条记录...", total_inserted);
            }
        }

        // 重新启用同步模式并重建索引
        self.conn.execute_batch(
            "PRAGMA synchronous = NORMAL; \
             PRAGMA journal_mode = WAL;"
        )?;

        // 分析表以优化查询性能
        self.conn.execute("ANALYZE", [])?;
        
        Ok(total_inserted)
    }


    /// 获取统计信息
    pub fn get_statistics(&self, scan_session: Option<&str>) -> SqlResult<Statistics> {
        let mut stats = Statistics::default();

        // 总匹配数
        let total_count: i64 = if let Some(session) = scan_session {
            self.conn.query_row(
                "SELECT COUNT(*) FROM scan_results WHERE scan_session = ?",
                [session],
                |row| row.get(0),
            )?
        } else {
            self.conn.query_row(
                "SELECT COUNT(*) FROM scan_results",
                [],
                |row| row.get(0),
            )?
        };
        stats.total_matches = total_count as usize;

        // 按置信度统计
        if let Some(session) = scan_session {
            let mut stmt = self.conn.prepare(
                "SELECT confidence, COUNT(*) FROM scan_results WHERE scan_session = ? GROUP BY confidence"
            )?;
            let confidence_iter = stmt.query_map([session], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            
            for item in confidence_iter {
                let (confidence, count) = item?;
                stats.confidence_counts.insert(confidence, count as usize);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT confidence, COUNT(*) FROM scan_results GROUP BY confidence"
            )?;
            let confidence_iter = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            
            for item in confidence_iter {
                let (confidence, count) = item?;
                stats.confidence_counts.insert(confidence, count as usize);
            }
        }

        // 按模式统计
        if let Some(session) = scan_session {
            let mut stmt = self.conn.prepare(
                "SELECT pattern_name, COUNT(*) FROM scan_results WHERE scan_session = ? GROUP BY pattern_name ORDER BY COUNT(*) DESC LIMIT 10"
            )?;
            let pattern_iter = stmt.query_map([session], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            
            for item in pattern_iter {
                let (pattern, count) = item?;
                stats.top_patterns.push((pattern, count as usize));
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT pattern_name, COUNT(*) FROM scan_results GROUP BY pattern_name ORDER BY COUNT(*) DESC LIMIT 10"
            )?;
            let pattern_iter = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            
            for item in pattern_iter {
                let (pattern, count) = item?;
                stats.top_patterns.push((pattern, count as usize));
            }
        }

        Ok(stats)
    }

}

/// 统计信息
#[derive(Default, Debug)]
pub struct Statistics {
    pub total_matches: usize,
    pub confidence_counts: std::collections::HashMap<String, usize>,
    pub top_patterns: Vec<(String, usize)>,
}

impl Statistics {
    pub fn print_summary(&self) {
        println!("扫描统计信息:");
        println!("  总匹配数: {}", self.total_matches);
        println!("  置信度分布:");
        for (confidence, count) in &self.confidence_counts {
            println!("    {}: {}", confidence, count);
        }
        println!("  前10个最常匹配的模式:");
        for (i, (pattern, count)) in self.top_patterns.iter().enumerate() {
            println!("    {}. {}: {}", i + 1, pattern, count);
        }
    }
}
