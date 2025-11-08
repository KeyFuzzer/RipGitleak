/// 代码块上下文提取器
pub struct ContextExtractor {
    lines: Vec<String>,
}

impl ContextExtractor {
    /// 创建新的上下文提取器
    pub fn new(content: &str) -> Self {
        let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        Self { lines }
    }

    /// 提取匹配行的最小代码块上下文
    /// 
    /// 对于part完整性规则，提取匹配内容所在行所在的最小代码块
    /// 例如最内层的大括号或最后一层的缩进
    /// 如果没有匹配到，则前后各取五行
    pub fn extract_context(&self, line_number: usize) -> String {
        if self.lines.is_empty() || line_number == 0 || line_number > self.lines.len() {
            return String::new();
        }

        // 尝试提取最小代码块
        if let Some(code_block) = self.extract_minimal_code_block(line_number - 1) {
            return code_block;
        }

        // 如果没有找到代码块，则前后各取25行
        self.extract_lines_around(line_number - 1, 25)
    }

    /// 提取最小代码块
    fn extract_minimal_code_block(&self, line_index: usize) -> Option<String> {
        let current_line = &self.lines[line_index];
        
        // 检查当前行是否在代码块中（通过缩进或大括号）
        let current_indent = self.get_indent_level(current_line);
        
        // 向前查找代码块开始
        let start_line = self.find_block_start(line_index, current_indent);
        
        // 向后查找代码块结束
        let end_line = self.find_block_end(line_index, current_indent);
        
        // 如果找到了有效的代码块范围
        if start_line < end_line && end_line < self.lines.len() {
            let block_lines: Vec<String> = self.lines[start_line..=end_line].to_vec();
            Some(block_lines.join("\n"))
        } else {
            None
        }
    }

    /// 获取行的缩进级别
    fn get_indent_level(&self, line: &str) -> usize {
        line.chars()
            .take_while(|c| c.is_whitespace())
            .count()
    }

    /// 查找代码块开始位置
    fn find_block_start(&self, start_index: usize, base_indent: usize) -> usize {
        let mut current_index = start_index;
        
        // 向前查找，直到找到缩进级别更小的行或代码块开始标记
        while current_index > 0 {
            let prev_line = &self.lines[current_index - 1];
            let prev_indent = self.get_indent_level(prev_line);
            
            // 如果前一行缩进更小，说明是代码块开始
            if prev_indent < base_indent {
                // 检查是否是代码块开始标记（如函数定义、类定义等）
                if self.is_block_start_marker(prev_line) {
                    return current_index - 1;
                }
                break;
            }
            
            // 检查当前行是否包含代码块开始标记
            if self.is_block_start_marker(prev_line) {
                return current_index - 1;
            }
            
            current_index -= 1;
            
            // 限制向前查找的范围（最多向前50行）
            if start_index - current_index > 50 {
                break;
            }
        }
        
        current_index
    }

    /// 查找代码块结束位置
    fn find_block_end(&self, start_index: usize, base_indent: usize) -> usize {
        let mut current_index = start_index;
        
        // 向后查找，直到找到缩进级别更小的行或代码块结束标记
        while current_index < self.lines.len() - 1 {
            let next_line = &self.lines[current_index + 1];
            let next_indent = self.get_indent_level(next_line);
            
            // 如果下一行缩进更小，说明是代码块结束
            if next_indent < base_indent {
                // 检查是否是代码块结束标记
                if self.is_block_end_marker(next_line) {
                    return current_index + 1;
                }
                break;
            }
            
            // 检查当前行是否包含代码块结束标记
            if self.is_block_end_marker(next_line) {
                return current_index + 1;
            }
            
            current_index += 1;
            
            // 限制向后查找的范围（最多向后50行）
            if current_index - start_index > 50 {
                break;
            }
        }
        
        current_index
    }

    /// 检查是否是代码块开始标记
    fn is_block_start_marker(&self, line: &str) -> bool {
        let trimmed = line.trim();
        
        // 检查常见的代码块开始标记
        trimmed.ends_with('{') || // 大括号开始
        trimmed.ends_with(':') || // Python等语言的冒号
        trimmed.ends_with("do") || // Ruby的do
        trimmed.ends_with("then") || // Shell的then
        trimmed.starts_with("def ") || // Python函数定义
        trimmed.starts_with("class ") || // Python类定义
        trimmed.starts_with("function ") || // JavaScript函数定义
        trimmed.starts_with("if ") || // 条件语句
        trimmed.starts_with("for ") || // 循环
        trimmed.starts_with("while ") || // 循环
        trimmed.starts_with("switch ") // Switch语句
    }

    /// 检查是否是代码块结束标记
    fn is_block_end_marker(&self, line: &str) -> bool {
        let trimmed = line.trim();
        
        // 检查常见的代码块结束标记
        trimmed.starts_with('}') || // 大括号结束
        trimmed == "end" || // Ruby/Python的end
        trimmed == "fi" || // Shell的fi
        trimmed == "done" || // Shell的done
        trimmed == "esac" // Shell的esac
    }

    /// 提取指定行周围的若干行
    fn extract_lines_around(&self, line_index: usize, context_lines: usize) -> String {
        let start = if line_index >= context_lines {
            line_index - context_lines
        } else {
            0
        };
        
        let end = if line_index + context_lines < self.lines.len() {
            line_index + context_lines
        } else {
            self.lines.len() - 1
        };
        
        let context_lines: Vec<String> = self.lines[start..=end].to_vec();
        context_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_context_with_code_block() {
        let content = r#"function test() {
    const api_key = "sk-1234567890abcdef";
    return api_key;
}"#;
        
        let extractor = ContextExtractor::new(content);
        let context = extractor.extract_context(2); // api_key所在行
        
        assert!(context.contains("function test() {"));
        assert!(context.contains("const api_key = \"sk-1234567890abcdef\";"));
        assert!(context.contains("return api_key;"));
        assert!(context.contains("}"));
    }

    #[test]
    fn test_extract_context_with_indentation() {
        let content = r#"class MyClass:
    def __init__(self):
        self.secret = "ghp_abcdefghijklmnop"
        self.public = "hello""#;
        
        let extractor = ContextExtractor::new(content);
        let context = extractor.extract_context(3); // secret所在行
        
        assert!(context.contains("def __init__(self):"));
        assert!(context.contains("self.secret = \"ghp_abcdefghijklmnop\""));
        assert!(context.contains("self.public = \"hello\""));
    }

    #[test]
    fn test_extract_context_fallback() {
        let content = r#"line1
line2
line3
line4
line5
line6
line7
line8
line9
line10
line11"#;
        
        let extractor = ContextExtractor::new(content);
        let context = extractor.extract_context(6); // line6所在行
        
        // 应该返回line1到line11（前后各25行，但由于文件只有11行，所以返回全部）
        assert!(context.contains("line1"));
        assert!(context.contains("line6"));
        assert!(context.contains("line11"));
    }
}
