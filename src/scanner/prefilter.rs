use aho_corasick::{AhoCorasick, MatchKind};
use colored::Colorize;
use std::collections::HashSet;

use crate::config::patterns::PatternEntry;

/// 提取分层关键词用于优化预过滤
pub fn extract_tiered_keywords(pattern_entries: &[PatternEntry]) -> (Vec<String>, Vec<String>) {
    let mut fast_keywords = HashSet::new();
    let mut full_keywords = HashSet::new();

    // 快速过滤器：仅包含最常见/高价值关键词
    let fast_keyword_set = vec![
        "key", "password", "token", "secret", "api", "akia", "ghp_", "sk-", "auth",
    ];

    // 完整过滤器：全面的关键词列表
    let full_keyword_set = vec![
        "key",
        "password",
        "token",
        "secret",
        "api",
        "auth",
        "credential",
        "private",
        "access",
        "session",
        "jwt",
        "bearer",
        "oauth",
        "cert",
        "hash",
        "sign",
        "encrypt",
        "akia",
        "asia",
        "ghp_",
        "sk-",
        "github",
        "aws",
        "passwd",
        "pwd",
        "cred",
        "database",
        "db",
        "sql",
        "ssh",
        "ssl",
        "tls",
        "guid",
        "uuid",
    ];

    for keyword in fast_keyword_set {
        fast_keywords.insert(keyword.to_string());
        full_keywords.insert(keyword.to_string());
    }

    for keyword in full_keyword_set {
        full_keywords.insert(keyword.to_string());
    }

    // 从模式中提取关键词
    for entry in pattern_entries {
        let pattern = &entry.pattern;

        // 从模式名称中提取
        let name_lower = pattern.name.to_lowercase();
        let name_words: Vec<&str> = name_lower.split_whitespace().collect();
        for word in name_words {
            if word.len() >= 3 && word.len() <= 15 {
                full_keywords.insert(word.to_string());

                // 如果是高价值关键词，添加到快速过滤器
                if word == "key"
                    || word == "password"
                    || word == "token"
                    || word == "secret"
                    || word == "api"
                    || word == "auth"
                {
                    fast_keywords.insert(word.to_string());
                }
            }
        }

        // 从正则表达式中提取（仅重要模式）
        let regex_lower = pattern.regex.to_lowercase();

        // 快速过滤器关键词
        if regex_lower.contains("akia") {
            fast_keywords.insert("akia".to_string());
            full_keywords.insert("akia".to_string());
        }
        if regex_lower.contains("ghp_") {
            fast_keywords.insert("ghp_".to_string());
            full_keywords.insert("ghp_".to_string());
        }
        if regex_lower.contains("sk-") {
            fast_keywords.insert("sk-".to_string());
            full_keywords.insert("sk-".to_string());
        }

        // 仅完整过滤器
        if regex_lower.contains("token") {
            full_keywords.insert("token".to_string());
        }
        if regex_lower.contains("password") {
            full_keywords.insert("password".to_string());
        }
        if regex_lower.contains("secret") {
            full_keywords.insert("secret".to_string());
        }
        if regex_lower.contains("key") && !regex_lower.contains("akia") {
            full_keywords.insert("key".to_string());
        }
    }

    let mut fast_list: Vec<String> = fast_keywords.into_iter().collect();
    let mut full_list: Vec<String> = full_keywords.into_iter().collect();
    fast_list.sort();
    full_list.sort();

    println!(
        "{} 分层关键词：{} 快速，{} 完整",
        "INFO:".blue(),
        fast_list.len(),
        full_list.len()
    );

    (fast_list, full_list)
}

/// 构建Aho-Corasick预过滤器
pub fn build_prefilters(fast_keywords: &[String], full_keywords: &[String]) -> Result<(AhoCorasick, AhoCorasick), Box<dyn std::error::Error>> {
    // 构建快速预过滤器（仅高置信度关键词）
    let fast_prefilter = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(fast_keywords)
        .map_err(|e| format!("构建快速Aho-Corasick自动机失败: {}", e))?;

    // 构建完整预过滤器（所有关键词）
    let full_prefilter = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(full_keywords)
        .map_err(|e| format!("构建完整Aho-Corasick自动机失败: {}", e))?;

    Ok((fast_prefilter, full_prefilter))
}

/// 检查是否应该应用正则表达式模式（优化版本）
pub fn should_apply_regex_patterns_optimized(
    content: &str,
    fast_prefilter: &AhoCorasick,
    full_prefilter: &AhoCorasick,
    file_size: u64,
) -> bool {
    let content_lower = content.to_lowercase();

    // 对于小文件（<1KB），仅使用快速预过滤器以最小化开销
    if file_size < 1024 {
        return fast_prefilter.find(&content_lower).is_some();
    }

    // 对于中等文件（1KB-10KB），先尝试快速，如果需要再使用完整
    if file_size < 10 * 1024 {
        if fast_prefilter.find(&content_lower).is_some() {
            return true; // 找到快速关键词，继续正则匹配
        }
        return false; // 没有快速关键词，跳过
    }

    // 对于大文件（>10KB），使用完整预过滤器进行全面覆盖
    full_prefilter.find(&content_lower).is_some()
}
