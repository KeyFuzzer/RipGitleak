use std::path::Path;

/// 检查是否应该扫描文件
pub fn should_scan_file(file_path: &Path, include_ext: &[String], exclude_ext: &[String]) -> bool {
    if let Some(extension) = file_path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();

        // 先检查排除列表
        if !exclude_ext.is_empty() && exclude_ext.contains(&ext) {
            return false;
        }

        // 检查包含列表
        if !include_ext.is_empty() && !include_ext.contains(&ext) {
            return false;
        }

        true
    } else {
        // 没有扩展名的文件总是被扫描，除非明确排除
        true
    }
}
