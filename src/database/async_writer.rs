//! 异步数据库写入器
//!
//! 提供高性能的异步SQLite写入支持

use crossbeam_channel::{Receiver, Sender, unbounded};
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::database::DatabaseManager;
use crate::output::formatter::MatchResult;

/// 异步数据库写入器
pub struct AsyncDatabaseWriter {
    sender: Sender<Vec<MatchResult>>,
    shutdown_sender: Sender<()>,
    worker_handle: Option<thread::JoinHandle<()>>,
}

impl AsyncDatabaseWriter {
    /// 创建新的异步数据库写入器
    pub fn new(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let (sender, receiver) = unbounded();
        let (shutdown_sender, shutdown_receiver) = unbounded();

        // 创建数据库管理器
        let db_manager = DatabaseManager::new(db_path)?;

        // 启动异步写入线程
        let worker_handle = thread::spawn(move || {
            Self::database_writer_worker(receiver, shutdown_receiver, db_manager);
        });

        Ok(Self {
            sender,
            shutdown_sender,
            worker_handle: Some(worker_handle),
        })
    }

    /// 数据库写入工作线程
    fn database_writer_worker(
        receiver: Receiver<Vec<MatchResult>>,
        shutdown_receiver: Receiver<()>,
        mut db_manager: DatabaseManager,
    ) {
        let mut batch_count = 0;
        let mut total_records = 0;

        loop {
            // 检查是否收到关闭信号
            if shutdown_receiver.try_recv().is_ok() {
                println!("INFO: 数据库写入线程收到关闭信号");
                break;
            }

            // 尝试接收数据，带超时以避免无限阻塞
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(matches) => {
                    if !matches.is_empty() {
                        match db_manager.insert_results_batch_optimized(&matches, None, 1000) {
                            Ok(count) => {
                                batch_count += 1;
                                total_records += count;
                                
                                // 每处理一定批次后输出进度
                                if batch_count % 100 == 0 {
                                    println!("异步写入进度: 已处理 {} 批次，{} 条记录", batch_count, total_records);
                                }
                            }
                            Err(e) => {
                                eprintln!("ERROR: 异步写入数据库失败: {}", e);
                            }
                        }
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // 超时，继续循环检查关闭信号
                    continue;
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    println!("INFO: 数据库写入通道已断开，线程退出");
                    break;
                }
            }
        }

        // 处理剩余的数据
        let mut remaining_records = 0;
        let mut remaining_batches = 0;
        while let Ok(matches) = receiver.try_recv() {
            if !matches.is_empty() {
                if let Ok(count) = db_manager.insert_results_batch_optimized(&matches, None, 1000) {
                    remaining_records += count;
                    remaining_batches += 1;
                }
            }
        }

        println!(
            "INFO: 数据库写入线程完成，总共处理 {} 批次，{} 条记录 (剩余 {} 批次)",
            batch_count,
            total_records + remaining_records,
            remaining_batches
        );
    }

    /// 异步发送匹配结果到数据库
    pub fn send_matches(
        &self,
        matches: Vec<MatchResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !matches.is_empty() {
            self.sender
                .send(matches)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        }
        Ok(())
    }

    /// 关闭异步写入器
    pub fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 发送关闭信号
        self.shutdown_sender
            .send(())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // 等待工作线程完成
        if let Some(handle) = self.worker_handle.take() {
            handle.join().map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{:?}", e),
                ))
            })?;
        }

        println!("INFO: 异步数据库写入器已关闭");
        Ok(())
    }
}

impl Drop for AsyncDatabaseWriter {
    fn drop(&mut self) {
        // 如果用户没有显式调用shutdown，尝试优雅关闭
        if self.worker_handle.is_some() {
            let _ = self.shutdown_sender.send(());
        }
    }
}

/// 异步数据库写入管理器
pub struct AsyncDatabaseManager {
    writer: Option<AsyncDatabaseWriter>,
    buffer: Vec<MatchResult>,
    buffer_size: usize,
}

impl AsyncDatabaseManager {
    /// 创建新的异步数据库管理器
    pub fn new(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let writer = AsyncDatabaseWriter::new(db_path)?;
        Ok(Self {
            writer: Some(writer),
            buffer: Vec::new(),
            buffer_size: 1000, // 每1000条记录发送一次，提高性能
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

        // 当缓冲区达到阈值时发送到异步写入器
        if self.buffer.len() >= self.buffer_size {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// 刷新缓冲区到异步写入器
    pub fn flush_buffer(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref writer) = self.writer {
            if !self.buffer.is_empty() {
                let matches = std::mem::take(&mut self.buffer);
                writer.send_matches(matches)?;
            }
        }
        Ok(())
    }

    /// 关闭异步数据库管理器
    pub fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 刷新剩余缓冲区数据
        self.flush_buffer()?;

        // 关闭异步写入器
        if let Some(writer) = self.writer.take() {
            writer.shutdown()?;
        }

        Ok(())
    }
}
