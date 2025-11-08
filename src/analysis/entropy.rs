use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

/// 上下文感知的熵分析器
#[derive(Debug)]
pub struct ContextAwareEntropyAnalyzer {
    total_checks: AtomicUsize,
    high_entropy_count: AtomicUsize,
    adaptive_threshold: f64,
}

impl ContextAwareEntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            total_checks: AtomicUsize::new(0),
            high_entropy_count: AtomicUsize::new(0),
            adaptive_threshold: 3.5, // 初始阈值
        }
    }

    /// 根据历史数据自适应调整阈值
    pub fn update_threshold(&mut self) {
        let total = self.total_checks.load(Ordering::Relaxed);
        let high_entropy = self.high_entropy_count.load(Ordering::Relaxed);
        
        if total > 100 {
            let high_entropy_ratio = high_entropy as f64 / total as f64;
            
            // 如果高熵比例过高，提高阈值以减少误报
            if high_entropy_ratio > 0.3 {
                self.adaptive_threshold = (self.adaptive_threshold + 0.1).min(4.0);
            }
            // 如果高熵比例过低，降低阈值以增加检测率
            else if high_entropy_ratio < 0.05 {
                self.adaptive_threshold = (self.adaptive_threshold - 0.05).max(3.0);
            }
        }
    }
}

/// 计算字符串的香农熵
/// 更高的熵表示更多的随机性，通常是加密密钥的特征
pub fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut frequency_map = HashMap::new();
    let total_chars = text.len() as f64;

    // 计算字符频率
    for ch in text.chars() {
        *frequency_map.entry(ch).or_insert(0) += 1;
    }

    // 计算熵值
    let entropy = frequency_map
        .values()
        .map(|&count| {
            let probability = count as f64 / total_chars;
            -probability * probability.log2()
        })
        .sum::<f64>();

    entropy
}

/// 计算字符串的字符集多样性
pub fn calculate_character_diversity(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    
    let unique_chars: HashSet<char> = text.chars().collect();
    unique_chars.len() as f64 / text.len() as f64
}

/// 检查字符串是否具有密钥特征
pub fn has_key_characteristics(text: &str) -> bool {
    // 检查长度
    if text.len() < 16 || text.len() > 256 {
        return false;
    }
    
    // 检查字符多样性
    let diversity = calculate_character_diversity(text);
    if diversity < 0.5 {
        return false;
    }
    
    // 检查是否包含常见密钥前缀
    let key_prefixes = ["AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AIza", "sk_", "pk_"];
    key_prefixes.iter().any(|&prefix| text.starts_with(prefix))
}

/// 上下文感知的熵检测
pub fn has_sufficient_entropy_context_aware(
    text: &str, 
    pattern_name: &str, 
    context: &str,
    analyzer: Option<&mut ContextAwareEntropyAnalyzer>
) -> bool {
    let entropy = calculate_entropy(text);
    
    // 更新统计信息
    if let Some(analyzer) = analyzer {
        analyzer.total_checks.fetch_add(1, Ordering::Relaxed);
        if entropy >= 3.5 {
            analyzer.high_entropy_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    // 基于上下文调整阈值
    let context_lower = context.to_lowercase();
    let mut threshold = get_base_threshold(pattern_name);
    
    // 上下文感知调整
    if context_lower.contains("test") || context_lower.contains("example") || context_lower.contains("demo") {
        threshold += 0.2; // 测试环境提高阈值
    }
    
    if context_lower.contains("prod") || context_lower.contains("production") || context_lower.contains("live") {
        threshold -= 0.1; // 生产环境降低阈值
    }
    
    if context_lower.contains("config") || context_lower.contains("env") || context_lower.contains("setting") {
        threshold -= 0.15; // 配置文件降低阈值
    }
    
    // 检查密钥特征
    let has_key_chars = has_key_characteristics(text);
    
    // 最终决策
    if has_key_chars {
        entropy >= threshold - 0.2 // 具有密钥特征时降低阈值
    } else {
        entropy >= threshold
    }
}

/// 获取基础阈值
fn get_base_threshold(pattern_name: &str) -> f64 {
    match pattern_name {
        // API密钥和令牌通常具有高熵值
        name if name.contains("API Key") || name.contains("Token") => 3.6,
        // 通用密钥
        name if name.contains("Secret") => 3.45,
        // 密码通常具有较低的熵值
        name if name.contains("Password") || name.contains("Pass") => 3.2,
        // 其他模式的默认阈值
        _ => 3.5,
    }
}

/// 检查匹配的文本是否具有足够的熵值以被视为真正的密钥
/// 这有助于过滤掉误报，如变量名、函数名等
/// 对于password/username类规则，禁用熵过滤以避免过滤弱口令
pub fn has_sufficient_entropy(text: &str, pattern_name: &str) -> bool {
    // 对password/username类规则禁用熵过滤
    let pattern_lower = pattern_name.to_lowercase();
    if pattern_lower.contains("password") || 
       pattern_lower.contains("pass") || 
       pattern_lower.contains("username") || 
       pattern_lower.contains("user") {
        return true; // 禁用熵过滤，允许弱口令检测
    }
    
    has_sufficient_entropy_context_aware(text, pattern_name, "", None)
}

/// 批量熵检测，优化性能
pub fn batch_entropy_check(texts: &[&str], pattern_names: &[&str]) -> Vec<bool> {
    texts.iter()
        .zip(pattern_names.iter())
        .map(|(&text, &pattern_name)| has_sufficient_entropy(text, pattern_name))
        .collect()
}
