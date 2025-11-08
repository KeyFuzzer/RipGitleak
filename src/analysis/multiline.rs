/// 检查URL是否包含参数（查询字符串）
pub fn url_has_parameters(url: &str) -> bool {
    url.contains('?') || url.contains('&')
}

/// 检测到私钥头时提取多行私钥内容
/// 在第一个私钥结束标记处停止
pub fn extract_multiline_private_key(lines: &[&str], start_line: usize) -> Option<(String, usize)> {
    if start_line >= lines.len() {
        return None;
    }

    let current_line = lines[start_line];

    // 检查此行是否包含私钥头
    if !current_line.contains("-----BEGIN") || !current_line.contains("PRIVATE KEY-----") {
        return None;
    }

    // 从BEGIN标记中提取密钥类型
    let key_type = if current_line.contains("RSA") {
        "RSA"
    } else if current_line.contains("DSA") {
        "DSA"
    } else if current_line.contains("EC") {
        "EC"
    } else if current_line.contains("OPENSSH") {
        "OPENSSH"
    } else if current_line.contains("PGP") {
        "PGP"
    } else {
        "" // 通用私钥
    };

    let mut private_key_lines = vec![current_line.to_string()];
    let mut current_idx = start_line + 1;
    let mut found_end = false;

    // 读取行直到找到私钥结束标记
    while current_idx < lines.len() && current_idx < start_line + 1000 {
        let line = lines[current_idx];
        
        // 检查此行是否包含私钥结束标记
        if line.contains("-----END") && line.contains("PRIVATE KEY-----") {
            // 检查END标记类型是否与BEGIN标记类型匹配
            let end_matches_begin = match key_type {
                "RSA" => line.contains("RSA"),
                "DSA" => line.contains("DSA"),
                "EC" => line.contains("EC"),
                "OPENSSH" => line.contains("OPENSSH"),
                "PGP" => line.contains("PGP"),
                _ => true, // 对于通用私钥，任何END标记都可接受
            };
            
            if end_matches_begin {
                private_key_lines.push(line.to_string());
                found_end = true;
                break;
            } else {
                // 如果找到END标记但与BEGIN类型不匹配，
                // 这是一个不完整的密钥块 - 不返回任何内容
                return None;
            }
        }
        
        private_key_lines.push(line.to_string());
        current_idx += 1;
    }

    // 如果找到结束标记，返回完整的私钥内容
    if found_end {
        let private_key_content = private_key_lines.join("\n");
        Some((private_key_content, current_idx - start_line + 1))
    } else {
        // 如果没有找到结束标记，不返回任何内容
        None
    }
}
