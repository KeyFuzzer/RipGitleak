use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

/// 创建多进度显示
pub fn create_multi_progress(total_files: u64) -> (MultiProgress, ProgressBar, ProgressBar, ProgressBar) {
    // 创建多进度显示
    let multi_progress = MultiProgress::new();

    // 第1行：总体进度条
    let overall_pb = ProgressBar::new(total_files);
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) 文件已扫描")
            .unwrap()
            .progress_chars("█▓▒░")
    );
    let overall_pb = multi_progress.add(overall_pb);

    // 第2行：当前正在处理的文件
    let current_file_pb = ProgressBar::new(1);
    current_file_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.yellow} 当前文件: {msg}")
            .unwrap(),
    );
    current_file_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let current_file_pb = multi_progress.add(current_file_pb);

    // 第3行：当前正在匹配的模式
    let current_pattern_pb = ProgressBar::new(1);
    current_pattern_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} 当前模式: {msg}")
            .unwrap(),
    );
    current_pattern_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let current_pattern_pb = multi_progress.add(current_pattern_pb);

    (multi_progress, overall_pb, current_file_pb, current_pattern_pb)
}
