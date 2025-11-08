use std::collections::HashMap;

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

/// 检查匹配的文本是否具有足够的熵值以被视为真正的密钥
/// 这有助于过滤掉误报，如变量名、函数名等
pub fn has_sufficient_entropy(text: &str, pattern_name: &str) -> bool {
    let entropy = calculate_entropy(text);

    // 基于模式类型的不同熵值阈值
    match pattern_name {
        // API密钥和令牌通常具有高熵值
        name if name.contains("API Key") || name.contains("Token") => entropy >= 3.6,
        // 通用密钥
        name if name.contains("Secret") => entropy >= 3.45,
        // 其他模式的默认阈值
        _ => entropy >= 3.5,
    }
}
