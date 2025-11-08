use serde::{Deserialize, Serialize};

/// 单个模式定义
#[derive(Debug, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub regex: String,
    pub confidence: String,
    pub integrity: String,
}

/// 模式条目
#[derive(Debug, Deserialize)]
pub struct PatternEntry {
    pub pattern: Pattern,
}

/// 模式数据库
#[derive(Debug, Deserialize)]
pub struct PatternDatabase {
    pub patterns: Vec<PatternEntry>,
}

/// Token匹配结果
#[derive(Debug, Serialize)]
pub struct TokenMatch {
    pub file_hash: String,
    pub value: String,
}
