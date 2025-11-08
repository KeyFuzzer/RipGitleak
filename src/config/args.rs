use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// 完整性过滤器选项
#[derive(ValueEnum, Clone, Debug)]
pub enum IntegrityFilter {
    Part,
    Full,
    All,
}

/// 命令行参数定义
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// 要扫描的目录
    #[arg(short, long)]
    pub path: PathBuf,

    /// 模式数据库文件
    #[arg(short, long, default_value = "rules/golden-rules.yml")]
    pub database: PathBuf,

    /// 仅显示高置信度匹配
    #[arg(short = 'H', long)]
    pub high_confidence_only: bool,


    /// 要包含的文件扩展名（逗号分隔）
    #[arg(short, long, default_value = "")]
    pub include_ext: String,

    /// 要排除的文件扩展名（逗号分隔）
    #[arg(short, long, default_value = "")]
    pub exclude_ext: String,

    /// 并行处理的批次大小（未指定时自动检测）
    #[arg(short, long)]
    pub batch_size: Option<usize>,

    /// 要扫描的最大文件大小（MB，默认：10MB）
    #[arg(short = 'M', long, default_value = "10")]
    pub max_file_size: u64,

    /// SQLite数据库文件路径（用于存储扫描结果）
    #[arg(short = 'o', long)]
    pub sqlite_db: Option<PathBuf>,

    /// 以token格式输出匹配结果
    #[arg(short = 't', long)]
    pub token_format: bool,

    /// 完整性过滤器: part, full, 或 all
    #[arg(short = 'I', long, default_value = "all")]
    pub integrity_filter: IntegrityFilter,

    /// 要扫描的最大行长度（跳过超过此长度的行）
    #[arg(short = 'L', long, default_value = "1000")]
    pub max_line_length: usize,

    #[arg(long)]
    pub enable_encoding_detection: bool,
}
