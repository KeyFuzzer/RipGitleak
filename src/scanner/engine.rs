use aho_corasick::AhoCorasick;
use colored::Colorize;
use fancy_regex::Regex;
use rayon::prelude::*;
use std::fs::File;
use std::sync::Arc;

use crate::config::patterns::PatternDatabase;
use crate::config::args::IntegrityFilter;
use crate::scanner::prefilter::{extract_tiered_keywords, build_prefilters};

/// 编译后的模式集合
#[derive(Debug)]
pub struct CompiledPatterns {
    pub individual_regexes: Vec<Regex>,
    pub names: Vec<String>,
    pub confidences: Vec<String>,
    pub integrities: Vec<String>,
    // 分层预过滤以提升性能
    pub fast_prefilter: AhoCorasick, // 仅高置信度关键词
    pub full_prefilter: AhoCorasick, // 所有关键词
}

/// 加载并编译模式
pub fn load_patterns(
    database_path: &std::path::Path,
    high_confidence_only: bool,
    integrity_filter: &IntegrityFilter,
) -> Result<CompiledPatterns, Box<dyn std::error::Error>> {
    let file = File::open(database_path)?;
    let db: PatternDatabase = serde_yaml::from_reader(file)?;

    let pattern_entries: Vec<_> = db
        .patterns
        .into_iter()
        .filter(|entry| !high_confidence_only || entry.pattern.confidence == "high")
        .filter(|entry| match integrity_filter {
            IntegrityFilter::Part => entry.pattern.integrity == "part",
            IntegrityFilter::Full => entry.pattern.integrity == "full",
            IntegrityFilter::All => true,
        })
        .collect();

    // 提取分层关键词用于优化预过滤
    let (fast_keywords, full_keywords) = extract_tiered_keywords(&pattern_entries);

    // 构建预过滤器
    let (fast_prefilter, full_prefilter) = build_prefilters(&fast_keywords, &full_keywords)?;

    // 并行编译单个正则表达式
    let compiled: Vec<_> = pattern_entries
        .par_iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            let pattern = &entry.pattern;
            match Regex::new(&pattern.regex) {
                Ok(regex) => Some((
                    idx,
                    pattern.name.clone(),
                    regex,
                    pattern.confidence.clone(),
                    pattern.integrity.clone(),
                )),
                Err(e) => {
                    eprintln!(
                        "{} 编译模式 '{}' 失败: {}",
                        "WARNING:".yellow(),
                        pattern.name,
                        e
                    );
                    None
                }
            }
        })
        .collect();

    // 按原始索引排序以保持顺序
    let mut compiled = compiled;
    compiled.sort_by_key(|(idx, _, _, _, _)| *idx);

    let mut names = Vec::new();
    let mut regexes = Vec::new();
    let mut confidences = Vec::new();
    let mut integrities = Vec::new();

    for (_, name, regex, confidence, integrity) in compiled {
        names.push(name);
        regexes.push(regex);
        confidences.push(confidence);
        integrities.push(integrity);
    }

    println!(
        "{} 已加载 {} 个模式（{} 个已编译，{} 个跳过）使用分层预过滤",
        "INFO:".blue(),
        pattern_entries.len(),
        regexes.len(),
        pattern_entries.len() - regexes.len()
    );

    Ok(CompiledPatterns {
        individual_regexes: regexes,
        names: names,
        confidences: confidences,
        integrities: integrities,
        fast_prefilter,
        full_prefilter,
    })
}

/// 创建Arc包装的模式，用于线程间共享
pub fn create_patterns_arc(
    database_path: &std::path::Path,
    high_confidence_only: bool,
    integrity_filter: &IntegrityFilter,
) -> Result<Arc<CompiledPatterns>, Box<dyn std::error::Error>> {
    let patterns = load_patterns(database_path, high_confidence_only, integrity_filter)?;
    Ok(Arc::new(patterns))
}
