//! 同步数据库写入器
//!
//! 提供简单可靠的同步SQLite写入支持

use std::path::Path;
use crate::database::DatabaseManager;
use crate::output::formatter::MatchResult;

/// 同步数据库写入管理器
pub struct SyncDatabaseManager {
    db_manager: DatabaseManager,
    buffer: Vec<MatchResult>,
    buffer_size: usize,
    total_inserted: usize,
}

impl SyncDatabaseManager {
    /// 创建新的同步数据库管理器
    pub fn new(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let db_manager = DatabaseManager::new(db_path)?;
        Ok(Self {
            db_manager,
            buffer: Vec::new(),
            buffer_size: 1000, // 每1000条记录批量插入一次
            total_inserted: 0,
        })
    }

    /// 添加匹配结果到缓冲区
    pub fn add_match(
        &mut self,
        match_result: MatchResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 应用熵过滤
        if !crate::analysis::entropy::has_sufficient_entropy(
            &match_result.matched_text,
            &match_result.pattern_name,
        ) {
            return Ok(());
        }

        self.buffer.push(match_result);

        // 当缓冲区达到阈值时批量插入到数据库
        if self.buffer.len() >= self.buffer_size {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// 刷新缓冲区到数据库
    pub fn flush_buffer(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.buffer.is_empty() {
            let matches = std::mem::take(&mut self.buffer);
            let inserted = self.db_manager.insert_results_batch_optimized(&matches, None, 1000)?;
            self.total_inserted += inserted;
            
            // 每插入一定数量后输出进度
            if self.total_inserted % 10000 == 0 {
                println!("已同步插入 {} 条记录...", self.total_inserted);
            }
        }
        Ok(())
    }

    /// 关闭同步数据库管理器
    pub fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 刷新剩余缓冲区数据
        self.flush_buffer()?;
        
        println!("INFO: 同步数据库写入完成，总共插入 {} 条记录", self.total_inserted);
        Ok(())
    }

    /// 获取已插入的记录总数
    pub fn get_total_inserted(&self) -> usize {
        self.total_inserted
    }
}
