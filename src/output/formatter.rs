/// 匹配结果结构
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub file_path: std::path::PathBuf,
    pub line_number: usize,
    pub pattern_name: String,
    pub confidence: String,
    pub integrity: String,
    pub matched_text: String,
    pub line_content: String,
    pub context: String,
}
