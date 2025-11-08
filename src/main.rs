//! RipGitleak - 代码库敏感信息检测工具
//! 
//! 模块化重构版本，支持流式输出和分屏显示

use clap::Parser;
use colored::Colorize;
use crossbeam_channel::Sender;
use ignore::WalkBuilder;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

// 导入模块
mod config;
mod scanner;
mod analysis;
mod output;
mod progress;
mod utils;
mod database;

// 导入具体功能
use config::args::Args;
use database::DatabaseManager;
use output::streaming::{create_streaming_output, StreamMessage};
use scanner::engine::create_patterns_arc;
use scanner::file_scanner::scan_file;

/// 流式扫描管理器
struct StreamingScanner {
    message_txs: Vec<Sender<StreamMessage>>,
    files_scanned: usize,
    total_files: usize,
    matches_found: usize,
}

impl StreamingScanner {
    fn new(message_tx: Sender<StreamMessage>) -> Self {
        Self {
            message_txs: vec![message_tx],
            files_scanned: 0,
            total_files: 0,
            matches_found: 0,
        }
    }

    /// 扫描单个文件并发送结果
    fn scan_file_streaming(
        &mut self,
        file_path: &PathBuf,
        patterns: &scanner::engine::CompiledPatterns,
        include_ext: &[String],
        exclude_ext: &[String],
        max_file_size: u64,
        max_line_length: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 发送当前文件进度
        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        for tx in &self.message_txs {
            let _ = tx.send(StreamMessage::Progress {
                current_file: file_name.clone(),
                files_scanned: self.files_scanned,
                total_files: self.total_files,
                matches_found: self.matches_found,
            });
        }

        // 扫描文件
        let matches = scan_file(
            file_path,
            patterns,
            include_ext,
            exclude_ext,
            max_file_size,
            max_line_length,
            None, // 不再使用进度条
            None, // 不再使用进度条
        )?;

        // 发送匹配结果
        for match_result in matches {
            for tx in &self.message_txs {
                let _ = tx.send(StreamMessage::Match(match_result.clone()));
            }
            self.matches_found += 1;
        }

        self.files_scanned += 1;

        // 更新进度
        for tx in &self.message_txs {
            let _ = tx.send(StreamMessage::Progress {
                current_file: file_name.clone(),
                files_scanned: self.files_scanned,
                total_files: self.total_files,
                matches_found: self.matches_found,
            });
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start_time = Instant::now();

    // 解析文件扩展名过滤器
    let include_ext: Vec<String> = args
        .include_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    let exclude_ext: Vec<String> = args
        .exclude_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    println!(
        "{} 正在扫描目录: {}",
        "INFO:".blue(),
        args.path.display()
    );
    println!(
        "{} 使用模式数据库: {}",
        "INFO:".blue(),
        args.database.display()
    );

    // 加载模式
    let pattern_load_start = Instant::now();
    let patterns_arc = create_patterns_arc(
        &args.database,
        args.high_confidence_only,
        &args.integrity_filter,
    )?;
    let pattern_load_time = pattern_load_start.elapsed();

    if patterns_arc.individual_regexes.is_empty() {
        eprintln!(
            "{} 没有加载任何模式。请检查您的数据库文件。",
            "ERROR:".red()
        );
        return Ok(());
    }

    // 首先收集所有要扫描的文件
    let files_to_scan: Vec<PathBuf> = WalkBuilder::new(&args.path)
        .build()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file())
        .filter(|path| utils::keywords::should_scan_file(path, &include_ext, &exclude_ext))
        .collect();

    let total_files = files_to_scan.len();
    println!("{} 找到 {} 个文件需要扫描", "INFO:".blue(), total_files);

    // 使用流式输出模式
    run_streaming_scan(
        &args,
        &files_to_scan,
        &patterns_arc,
        &include_ext,
        &exclude_ext,
        total_files,
        pattern_load_time,
        start_time,
    )
}

/// 运行流式扫描
fn run_streaming_scan(
    args: &Args,
    files_to_scan: &[PathBuf],
    patterns_arc: &Arc<scanner::engine::CompiledPatterns>,
    include_ext: &[String],
    exclude_ext: &[String],
    total_files: usize,
    pattern_load_time: std::time::Duration,
    start_time: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建消息通道
    let (streaming_output, message_tx) = create_streaming_output();

    // 启动显示线程
    let display_handle = std::thread::spawn(move || {
        if let Err(e) = streaming_output.run_display() {
            eprintln!("{} 显示线程错误: {}", "ERROR:".red(), e);
        }
    });

    // 创建扫描器
    let mut scanner = StreamingScanner::new(message_tx.clone());
    scanner.total_files = total_files;

    // 使用普通迭代而不是并行迭代，避免线程安全问题
    let mut errors = Vec::new();
    for file_path in files_to_scan {
        if let Err(e) = scanner.scan_file_streaming(
            file_path,
            patterns_arc,
            include_ext,
            exclude_ext,
            args.max_file_size,
            args.max_line_length,
        ) {
            errors.push(e.to_string());
        }
    }

    // 处理扫描错误
    if !errors.is_empty() {
        eprintln!("{} 扫描过程中发生 {} 个错误", "ERROR:".red(), errors.len());
        for error in errors.iter().take(5) {
            eprintln!("  - {}", error);
        }
    }

    // 发送完成信号
    let _ = message_tx.send(StreamMessage::Complete);

    // 等待显示线程完成
    if let Err(e) = display_handle.join() {
        eprintln!("{} 显示线程异常退出: {:?}", "ERROR:".red(), e);
    }

    let scan_time = start_time.elapsed();
    let files_per_second = total_files as f64 / scan_time.as_secs_f64();

    println!(
        "\n{} 扫描完成 - 模式加载: {:.2?}, 总时间: {:.2?}, 每秒文件: {:.1}",
        "SUMMARY:".green(),
        pattern_load_time,
        scan_time,
        files_per_second
    );

    // 如果指定了SQLite数据库，存储结果
    if let Some(sqlite_db_path) = &args.sqlite_db {
        println!("{} 正在将结果存储到SQLite数据库: {}", "INFO:".blue(), sqlite_db_path.display());
        
        let mut db_manager = DatabaseManager::new(sqlite_db_path)?;
        
        // 收集所有匹配结果
        let mut all_matches = Vec::new();
        for file_path in files_to_scan {
            if let Ok(matches) = scan_file(
                file_path,
                patterns_arc,
                include_ext,
                exclude_ext,
                args.max_file_size,
                args.max_line_length,
                None,
                None,
            ) {
                all_matches.extend(matches);
            }
        }
        
        // 使用优化版本插入所有数据
        match db_manager.insert_results_batch_optimized(&all_matches, None, 1000) {
            Ok(count) => {
                println!("{} 成功存储 {} 条记录到数据库", "SUCCESS:".green(), count);
                
                // 显示统计信息
                if let Ok(stats) = db_manager.get_statistics(None) {
                    stats.print_summary();
                }
            }
            Err(e) => {
                eprintln!("{} 存储结果到数据库失败: {}", "ERROR:".red(), e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aho_corasick::{AhoCorasick, MatchKind};

    #[test]
    fn test_case_insensitive_detection() {
        // 创建仅包含几个关键词的简单预过滤器
        let fast_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password"])
            .unwrap();

        let full_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password", "api", "secret"])
            .unwrap();

        // 测试各种大小写组合
        let test_cases = vec![
            ("token", true),
            ("TOKEN", true),
            ("Token", true),
            ("ToKeN", true),
            ("api_key=abc123", true),
            ("API_KEY=ABC123", true),
            ("Password123", true),
            ("PASSWORD123", true),
            ("normal text", false),
            ("", false),
        ];

        for (content, expected) in test_cases {
            let result = scanner::prefilter::should_apply_regex_patterns_optimized(
                content,
                &fast_prefilter,
                &full_prefilter,
                1000,
            );
            assert_eq!(result, expected, "内容 '{}' 测试失败", content);
        }
    }

    #[test]
    fn test_entropy_filtering() {
        // 高熵密钥应该通过
        assert!(analysis::entropy::has_sufficient_entropy(
            "AKIAIOSFODNN7EXAMPLE",
            "AWS API Key"
        ));
        assert!(analysis::entropy::has_sufficient_entropy(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "GitHub Token"
        ));

        // 低熵字符串应该被过滤掉
        assert!(!analysis::entropy::has_sufficient_entropy("password", "Password"));

        // 不同模式类型的不同阈值
        assert!(analysis::entropy::has_sufficient_entropy("MySecurePass123!", "Password")); // 密码的较低阈值
        assert!(!analysis::entropy::has_sufficient_entropy("MyPass123", "API Key")); // API密钥的较高阈值
    }
}
