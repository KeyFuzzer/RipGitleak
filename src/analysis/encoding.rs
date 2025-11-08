use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // 编码模式检测
    static ref BASE64_PATTERN: Regex = Regex::new(r#"["']([A-Za-z0-9+/]{20,}={0,2})["']"#).unwrap();
    static ref HEX_PATTERN: Regex = Regex::new(r#"["']([a-fA-F0-9]{32,})["']"#).unwrap();
    static ref CHARACTER_ARRAY_PATTERN: Regex = Regex::new(r"\[(?:\s*\d+\s*,?\s*){10,}\]").unwrap();
    static ref URL_ENCODED_PATTERN: Regex = Regex::new(r#"(?i)(database[_\s\-]?url|db[_\s\-]?url|connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]*%[0-9A-Fa-f]{2}[^"'\s]*)["']?"#).unwrap();
}

/// 编码检测结果
#[derive(Debug, Clone)]
pub struct EncodedSecret {
    pub pattern_name: String,
    pub decoded_value: String,
    pub encoded_value: String,
    pub encoding_type: String,
}

/// 分析 Base64 编码的字符串
pub fn analyze_base64_for_secrets(b64_string: &str) -> Vec<EncodedSecret> {
    let mut found_secrets = Vec::new();
    
    // 尝试解码 Base64
    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(b64_string) {
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            // 检查解码后的字符串是否匹配已知密钥模式
            let decoded_secrets = analyze_decoded_string(&decoded_str);
            for (pattern_name, secret_value) in decoded_secrets {
                found_secrets.push(EncodedSecret {
                    pattern_name,
                    decoded_value: secret_value,
                    encoded_value: b64_string.to_string(),
                    encoding_type: "Base64".to_string(),
                });
            }
        }
    }
    
    found_secrets
}

/// 分析十六进制编码的字符串
pub fn analyze_hex_for_secrets(hex_string: &str) -> Vec<EncodedSecret> {
    let mut found_secrets = Vec::new();
    
    // 尝试解码十六进制
    if let Ok(decoded_bytes) = hex::decode(hex_string) {
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            // 检查解码后的字符串是否匹配已知密钥模式
            let decoded_secrets = analyze_decoded_string(&decoded_str);
            for (pattern_name, secret_value) in decoded_secrets {
                found_secrets.push(EncodedSecret {
                    pattern_name,
                    decoded_value: secret_value,
                    encoded_value: hex_string.to_string(),
                    encoding_type: "Hex".to_string(),
                });
            }
        }
    }
    
    found_secrets
}

/// 分析字符数组编码的字符串
pub fn analyze_character_array_for_secrets(char_array_str: &str) -> Vec<EncodedSecret> {
    let mut found_secrets = Vec::new();
    
    // 从数组格式 [65, 73, 122, ...] 中提取数字
    let numbers: Vec<u8> = char_array_str
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect();
    
    if numbers.len() > 8 {
        // 尝试转换为字符串
        if let Ok(decoded_str) = String::from_utf8(numbers) {
            // 检查解码后的字符串是否匹配已知密钥模式
            let decoded_secrets = analyze_decoded_string(&decoded_str);
            for (pattern_name, secret_value) in decoded_secrets {
                found_secrets.push(EncodedSecret {
                    pattern_name,
                    decoded_value: secret_value,
                    encoded_value: char_array_str.to_string(),
                    encoding_type: "Character Array".to_string(),
                });
            }
        }
    }
    
    found_secrets
}

/// 分析 URL 编码的字符串
pub fn analyze_url_encoded_for_secrets(url_encoded_string: &str) -> Vec<EncodedSecret> {
    let mut found_secrets = Vec::new();
    
    // 尝试解码 URL 编码的字符串
    let decoded_str = url_encoded_string
        .replace("%3A", ":")
        .replace("%2F", "/")
        .replace("%40", "@")
        .replace("%3F", "?")
        .replace("%3D", "=")
        .replace("%26", "&");
    
    if decoded_str != url_encoded_string {
        // 检查解码后的字符串是否匹配数据库模式
        if decoded_str.contains("://") && decoded_str.contains("@") {
            found_secrets.push(EncodedSecret {
                pattern_name: "Database Connection String".to_string(),
                decoded_value: decoded_str.clone(),
                encoded_value: url_encoded_string.to_string(),
                encoding_type: "URL Encoded".to_string(),
            });
        }
    }
    
    found_secrets
}

/// 分析解码后的字符串是否包含已知密钥模式
fn analyze_decoded_string(decoded_str: &str) -> Vec<(String, String)> {
    let mut found_secrets = Vec::new();
    
    // 检查常见的密钥模式
    let patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", r"(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Stripe API Key", r"(sk|pk)_(test|live)_[0-9A-Za-z]{24,}"),
        ("Generic API Key", r"[A-Za-z0-9\-_]{20,40}"),
    ];
    
    for (pattern_name, pattern_regex) in patterns {
        if let Ok(regex) = Regex::new(pattern_regex) {
            if let Some(mat) = regex.find(decoded_str) {
                found_secrets.push((pattern_name.to_string(), mat.as_str().to_string()));
            }
        }
    }
    
    found_secrets
}

/// 检查 Base64 字符串是否可疑
pub fn is_suspicious_base64(b64_string: &str, context: &str) -> bool {
    let context_lower = context.to_lowercase();
    
    // 可疑上下文关键词
    let suspicious_context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential",
        "aws", "github", "google", "stripe", "config", "env", "prod", "production"
    ];
    
    let has_suspicious_context = suspicious_context.iter()
        .any(|&keyword| context_lower.contains(keyword));
    
    // Base64 特征
    let has_good_length = b64_string.len() >= 16;
    let has_good_chars = b64_string.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let has_padding = b64_string.ends_with('=') || b64_string.ends_with("==");
    
    has_suspicious_context && has_good_length && has_good_chars && (has_padding || b64_string.len() % 4 == 0)
}

/// 检查十六进制字符串是否可疑
pub fn is_suspicious_hex(hex_string: &str, context: &str) -> bool {
    let context_lower = context.to_lowercase();
    
    // 可疑上下文关键词
    let suspicious_context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential",
        "aws", "github", "google", "stripe", "config", "env", "prod", "production"
    ];
    
    let has_suspicious_context = suspicious_context.iter()
        .any(|&keyword| context_lower.contains(keyword));
    
    // 十六进制特征
    let has_good_length = hex_string.len() >= 32;
    let is_valid_hex = hex_string.chars().all(|c| c.is_ascii_hexdigit());
    let has_even_length = hex_string.len() % 2 == 0;
    
    has_suspicious_context && has_good_length && is_valid_hex && has_even_length
}

/// 分析一行文本中的编码密钥
pub fn analyze_line_for_encoded_secrets(line: &str, line_number: usize, file_path: &std::path::Path) -> Vec<crate::output::formatter::MatchResult> {
    use crate::output::formatter::MatchResult;
    use std::path::PathBuf;
    
    let mut findings: Vec<MatchResult> = Vec::new();
    
    // 分析 Base64 编码
    for cap in BASE64_PATTERN.captures_iter(line) {
        if let Some(b64_match) = cap.get(1) {
            let b64_string = b64_match.as_str();
            
            if is_suspicious_base64(b64_string, line) {
                let decoded_secrets = analyze_base64_for_secrets(b64_string);
                for encoded_secret in decoded_secrets {
                    findings.push(MatchResult {
                        file_path: PathBuf::from(file_path),
                        line_number,
                        pattern_name: encoded_secret.pattern_name,
                        confidence: "high".to_string(),
                        integrity: "full".to_string(),
                        matched_text: format!("{} ({} encoded: {})", 
                            encoded_secret.decoded_value, 
                            encoded_secret.encoding_type,
                            encoded_secret.encoded_value),
                        line_content: line.to_string(),
                        context: format!("Detected {} encoded secret", encoded_secret.encoding_type),
                    });
                }
            }
        }
    }
    
    // 分析十六进制编码
    for cap in HEX_PATTERN.captures_iter(line) {
        if let Some(hex_match) = cap.get(1) {
            let hex_string = hex_match.as_str();
            
            if is_suspicious_hex(hex_string, line) {
                let decoded_secrets = analyze_hex_for_secrets(hex_string);
                for encoded_secret in decoded_secrets {
                    findings.push(MatchResult {
                        file_path: PathBuf::from(file_path),
                        line_number,
                        pattern_name: encoded_secret.pattern_name,
                        confidence: "high".to_string(),
                        integrity: "full".to_string(),
                        matched_text: format!("{} ({} encoded: {})", 
                            encoded_secret.decoded_value, 
                            encoded_secret.encoding_type,
                            encoded_secret.encoded_value),
                        line_content: line.to_string(),
                        context: format!("Detected {} encoded secret", encoded_secret.encoding_type),
                    });
                }
            }
        }
    }
    
    // 分析字符数组编码
    for mat in CHARACTER_ARRAY_PATTERN.find_iter(line) {
        let array_string = mat.as_str();
        
        let decoded_secrets = analyze_character_array_for_secrets(array_string);
        for encoded_secret in decoded_secrets {
            findings.push(MatchResult {
                file_path: PathBuf::from(file_path),
                line_number,
                pattern_name: encoded_secret.pattern_name,
                confidence: "high".to_string(),
                integrity: "full".to_string(),
                matched_text: format!("{} ({} encoded: {})", 
                    encoded_secret.decoded_value, 
                    encoded_secret.encoding_type,
                    encoded_secret.encoded_value),
                line_content: line.to_string(),
                context: format!("Detected {} encoded secret", encoded_secret.encoding_type),
            });
        }
    }
    
    // 分析 URL 编码
    for cap in URL_ENCODED_PATTERN.captures_iter(line) {
        if let Some(url_match) = cap.get(2) {
            let url_string = url_match.as_str();
            
            let decoded_secrets = analyze_url_encoded_for_secrets(url_string);
            for encoded_secret in decoded_secrets {
                findings.push(MatchResult {
                    file_path: PathBuf::from(file_path),
                    line_number,
                    pattern_name: encoded_secret.pattern_name,
                    confidence: "medium".to_string(),
                    integrity: "full".to_string(),
                    matched_text: format!("{} ({} encoded: {})", 
                        encoded_secret.decoded_value, 
                        encoded_secret.encoding_type,
                        encoded_secret.encoded_value),
                    line_content: line.to_string(),
                    context: format!("Detected {} encoded secret", encoded_secret.encoding_type),
                });
            }
        }
    }
    
    findings
}
