use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

use crate::analysis::context::ContextExtractor;
use crate::analysis::entropy::has_sufficient_entropy;
use crate::analysis::multiline::{extract_multiline_private_key, url_has_parameters};
use crate::output::formatter::MatchResult;
use crate::scanner::engine::CompiledPatterns;
use crate::scanner::prefilter::should_apply_regex_patterns_optimized;
use crate::utils::keywords::should_scan_file;

/// 扫描单个文件
pub fn scan_file(
    file_path: &Path,
    patterns: &CompiledPatterns,
    include_ext: &[String],
    exclude_ext: &[String],
    max_file_size: u64,
    max_line_length: usize,
    current_file_pb: Option<&indicatif::ProgressBar>,
    current_pattern_pb: Option<&indicatif::ProgressBar>,
) -> Result<Vec<MatchResult>, Box<dyn std::error::Error>> {
    if !should_scan_file(file_path, include_ext, exclude_ext) {
        return Ok(Vec::new());
    }

    // 先检查文件大小
    let metadata = std::fs::metadata(file_path)?;
    if metadata.len() > max_file_size * 1024 * 1024 {
        return Ok(Vec::new());
    }

    let file = File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let file_size = metadata.len();
    
    // 检查文件是否为有效的UTF-8编码，如果不是则跳过
    let content = match std::str::from_utf8(&mmap) {
        Ok(text) => text,
        Err(_) => {
            // 非UTF-8文件，直接跳过
            return Ok(Vec::new());
        }
    };

    // 应用优化的分层预过滤：仅在找到关键词时才继续正则匹配
    if !should_apply_regex_patterns_optimized(
        content,
        &patterns.fast_prefilter,
        &patterns.full_prefilter,
        file_size,
    ) {
        return Ok(Vec::new()); // 跳过正则匹配 - 未找到关键词
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut matches = Vec::new();

    // 创建语境提取器
    let context_extractor = ContextExtractor::new(content);

    // 更新当前文件进度（延迟更新）
    if let Some(pb) = current_file_pb {
        pb.set_message(
            file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        );
    }

    // 跟踪已处理的行以避免重复的多行匹配
    let mut processed_lines = HashSet::new();

    // 对大文件使用并行处理
    if lines.len() > 1000 {
        let chunk_size = std::cmp::max(100, lines.len() / num_cpus::get());
        let line_matches: Vec<Vec<MatchResult>> = lines
            .chunks(chunk_size)
            .enumerate()
            .par_bridge()
            .map(|(chunk_idx, chunk)| {
                let mut chunk_matches = Vec::new();
                let mut processed_lines = HashSet::new();

                let mut local_line_idx = 0;
                while local_line_idx < chunk.len() {
                    let line = chunk[local_line_idx];
                    let line_number = chunk_idx * chunk_size + local_line_idx + 1;

                    // 跳过过长的行（可能是噪音）
                    if line.len() > max_line_length {
                        local_line_idx += 1;
                        continue;
                    }

                    // 如果此行已作为多行匹配的一部分处理过，则跳过
                    if processed_lines.contains(&local_line_idx) {
                        local_line_idx += 1;
                        continue;
                    }

                    // 先检查多行私钥
                    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                        // 对于并行处理，我们需要小心处理多行匹配
                        // 我们将仅从此块中提取私钥
                        let mut private_key_lines = vec![line.to_string()];
                        let mut lines_consumed = 1;
                        let mut found_end = false;

                        // 读取行直到找到私钥结束标记
                        let mut next_idx = local_line_idx + 1;
                        while next_idx < chunk.len() && lines_consumed < 1000 {
                            let next_line = chunk[next_idx];
                            
                            // 检查此行是否包含私钥结束标记
                            if next_line.contains("-----END") && next_line.contains("PRIVATE KEY-----") {
                                private_key_lines.push(next_line.to_string());
                                lines_consumed += 1;
                                found_end = true;
                                break;
                            }
                            
                            private_key_lines.push(next_line.to_string());
                            lines_consumed += 1;
                            next_idx += 1;
                        }

                        // 仅在我们找到完整的私钥块时报告
                        if found_end {
                            // 标记此多行匹配中的所有行已处理
                            for i in 0..lines_consumed {
                                processed_lines.insert(local_line_idx + i);
                            }

                            let private_key_content = private_key_lines.join("\n");
                            chunk_matches.push(MatchResult {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                pattern_name: "Private Key Block".to_string(),
                                confidence: "high".to_string(),
                                integrity: "full".to_string(),
                                matched_text: private_key_content.clone(),
                                line_content: line.to_string(),
                                context: private_key_content.clone(),
                            });

                            // 跳到下一个未处理的行
                            local_line_idx += lines_consumed;
                            continue;
                        }
                    }

                    let mut found_high_confidence = false;

                    // 先检查高置信度模式
                    for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                        if patterns.confidences[pattern_idx] == "high" {
                            if let Ok(Some(captures)) = regex.captures(line) {
                                if let Some(matched_text) = captures.get(0) {
                                    let matched_text_str = matched_text.as_str();
                                    let pattern_name = &patterns.names[pattern_idx];

                                    // 规则1：对于URL模式，如果没有参数则跳过
                                    if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                        if !url_has_parameters(matched_text_str) {
                                            continue; // 跳过没有参数的URL匹配
                                        }
                                    }

                                    // 对于完整完整性模式，应用熵过滤
                                    if patterns.integrities[pattern_idx] == "full" {
                                        if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                            continue; // 跳过低熵匹配的完整完整性模式
                                        }
                                    }

                                    // 根据置信度和完整性规则提取语境
                                    let context = if patterns.confidences[pattern_idx] == "medium" || 
                                                   patterns.confidences[pattern_idx] == "low" || 
                                                   patterns.integrities[pattern_idx] == "part" {
                                        // 对于中/低置信度或part完整性，提取代码块上下文
                                        context_extractor.extract_context(line_number)
                                    } else {
                                        // 对于高置信度且full完整性，context就是line本身
                                        line.to_string()
                                    };

                                    chunk_matches.push(MatchResult {
                                        file_path: file_path.to_path_buf(),
                                        line_number,
                                        pattern_name: pattern_name.clone(),
                                        confidence: patterns.confidences[pattern_idx].clone(),
                                        integrity: patterns.integrities[pattern_idx].clone(),
                                        matched_text: matched_text_str.to_string(),
                                        line_content: line.to_string(),
                                        context: context,
                                    });
                                    found_high_confidence = true;
                                    break; // 跳过此行剩余的模式
                                }
                            }
                        }
                    }

                    // 如果没有找到高置信度匹配，检查低置信度模式
                    if !found_high_confidence {
                        for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                            if patterns.confidences[pattern_idx] == "low" {
                                if let Ok(Some(captures)) = regex.captures(line) {
                                    if let Some(matched_text) = captures.get(0) {
                                        let matched_text_str = matched_text.as_str();
                                        let pattern_name = &patterns.names[pattern_idx];

                                        // 规则1：对于URL模式，如果没有参数则跳过
                                        if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                            if !url_has_parameters(matched_text_str) {
                                                continue; // 跳过没有参数的URL匹配
                                            }
                                        }

                                        // 对于完整完整性模式，应用熵过滤
                                        if patterns.integrities[pattern_idx] == "full" {
                                            if !has_sufficient_entropy(
                                                matched_text_str,
                                                pattern_name,
                                            ) {
                                                continue; // 跳过低熵匹配的完整完整性模式
                                            }
                                        }

                                        // 根据置信度和完整性规则提取语境
                                        let context = if patterns.confidences[pattern_idx] == "medium" || 
                                                       patterns.confidences[pattern_idx] == "low" || 
                                                       patterns.integrities[pattern_idx] == "part" {
                                            // 对于中/低置信度或part完整性，提取代码块上下文
                                            context_extractor.extract_context(line_number)
                                        } else {
                                            // 对于高置信度且full完整性，context就是line本身
                                            line.to_string()
                                        };

                                        chunk_matches.push(MatchResult {
                                            file_path: file_path.to_path_buf(),
                                            line_number,
                                            pattern_name: pattern_name.clone(),
                                            confidence: patterns.confidences[pattern_idx].clone(),
                                            integrity: patterns.integrities[pattern_idx].clone(),
                                            matched_text: matched_text_str.to_string(),
                                            line_content: line.to_string(),
                                            context: context,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    local_line_idx += 1;
                }

                chunk_matches
            })
            .collect();

        // 展平所有匹配
        for chunk_match in line_matches {
            matches.extend(chunk_match);
        }
    } else {
        // 对于小文件，使用顺序处理
        let mut line_number = 1;
        while line_number <= lines.len() {
            let line = lines[line_number - 1];

            // 跳过过长的行（可能是噪音）
            if line.len() > max_line_length {
                line_number += 1;
                continue;
            }

            // 如果此行已作为多行匹配的一部分处理过，则跳过
            if processed_lines.contains(&line_number) {
                line_number += 1;
                continue;
            }

            // 更新当前模式进度（延迟更新 - 每100行）
            if let Some(pb) = current_pattern_pb {
                if line_number % 100 == 0 {
                    pb.set_message(format!("行 {}/{}", line_number, lines.len()));
                }
            }

            // 先检查多行私钥
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                if let Some((private_key_content, lines_consumed)) =
                    extract_multiline_private_key(&lines, line_number - 1)
                {
                    // 标记此多行匹配中的所有行已处理
                    for i in 0..lines_consumed {
                        processed_lines.insert(line_number + i);
                    }

                    matches.push(MatchResult {
                        file_path: file_path.to_path_buf(),
                        line_number,
                        pattern_name: "Private Key Block".to_string(),
                        confidence: "high".to_string(),
                        integrity: "full".to_string(),
                        matched_text: private_key_content.clone(),
                        line_content: line.to_string(),
                        context: private_key_content.clone(),
                    });

                    // 跳到下一个未处理的行
                    line_number += lines_consumed;
                    continue;
                }
            }

            let mut found_high_confidence = false;

            // 先检查高置信度模式
            for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                if patterns.confidences[pattern_idx] == "high" {
                    if let Ok(Some(captures)) = regex.captures(line) {
                        if let Some(matched_text) = captures.get(0) {
                            let matched_text_str = matched_text.as_str();
                            let pattern_name = &patterns.names[pattern_idx];

                            // 规则1：对于URL模式，如果没有参数则跳过
                            if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                if !url_has_parameters(matched_text_str) {
                                    continue; // 跳过没有参数的URL匹配
                                }
                            }

                            // 规则2：跳过单个私钥头匹配，因为我们用多行提取处理它们
                            if pattern_name == "Private Key Block" || pattern_name == "PGP Private Key Block" {
                                continue; // 跳过单个私钥头匹配
                            }

                            // 对于完整完整性模式，应用熵过滤
                            if patterns.integrities[pattern_idx] == "full" {
                                if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                    continue; // 跳过低熵匹配的完整完整性模式
                                }
                            }

                            // 根据置信度和完整性规则提取语境
                            let context = if patterns.confidences[pattern_idx] == "medium" || 
                                           patterns.confidences[pattern_idx] == "low" || 
                                           patterns.integrities[pattern_idx] == "part" {
                                // 对于中/低置信度或part完整性，提取代码块上下文
                                context_extractor.extract_context(line_number)
                            } else {
                                // 对于高置信度且full完整性，context就是line本身
                                line.to_string()
                            };

                            matches.push(MatchResult {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                pattern_name: pattern_name.clone(),
                                confidence: patterns.confidences[pattern_idx].clone(),
                                integrity: patterns.integrities[pattern_idx].clone(),
                                matched_text: matched_text_str.to_string(),
                                line_content: line.to_string(),
                                context: context,
                            });
                            found_high_confidence = true;
                            break; // 跳过此行剩余的模式
                        }
                    }
                }
            }

            // 如果没有找到高置信度匹配，检查低置信度模式
            if !found_high_confidence {
                for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                    if patterns.confidences[pattern_idx] == "low" {
                        if let Ok(Some(captures)) = regex.captures(line) {
                            if let Some(matched_text) = captures.get(0) {
                                let matched_text_str = matched_text.as_str();
                                let pattern_name = &patterns.names[pattern_idx];

                                // 规则1：对于URL模式，如果没有参数则跳过
                                if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                    if !url_has_parameters(matched_text_str) {
                                        continue; // 跳过没有参数的URL匹配
                                    }
                                }

                                // 规则2：跳过单个私钥头匹配，因为我们用多行提取处理它们
                                if pattern_name == "Private Key Block" || pattern_name == "PGP Private Key Block" {
                                    continue; // 跳过单个私钥头匹配
                                }

                                // 对于完整完整性模式，应用熵过滤
                                if patterns.integrities[pattern_idx] == "full" {
                                    if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                        continue; // 跳过低熵匹配的完整完整性模式
                                    }
                                }

                                // 根据置信度和完整性规则提取语境
                                let context = if patterns.confidences[pattern_idx] == "medium" || 
                                               patterns.confidences[pattern_idx] == "low" || 
                                               patterns.integrities[pattern_idx] == "part" {
                                    // 对于中/低置信度或part完整性，提取代码块上下文
                                    context_extractor.extract_context(line_number)
                                } else {
                                    // 对于高置信度且full完整性，context就是line本身
                                    line.to_string()
                                };

                                matches.push(MatchResult {
                                    file_path: file_path.to_path_buf(),
                                    line_number,
                                    pattern_name: pattern_name.clone(),
                                    confidence: patterns.confidences[pattern_idx].clone(),
                                    integrity: patterns.integrities[pattern_idx].clone(),
                                    matched_text: matched_text_str.to_string(),
                                    line_content: line.to_string(),
                                    context: context,
                                });
                            }
                        }
                    }
                }
            }

            line_number += 1;
        }
    }

    Ok(matches)
}
