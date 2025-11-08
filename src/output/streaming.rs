use crossbeam_channel::{Receiver, Sender};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use crossterm::event::{self, Event, KeyCode};
use std::io;

use crate::output::formatter::MatchResult;

/// 流式输出消息类型
#[derive(Debug, Clone)]
pub enum StreamMessage {
    /// 匹配结果
    Match(MatchResult),
    /// 进度更新
    Progress {
        current_file: String,
        files_scanned: usize,
        total_files: usize,
        matches_found: usize,
    },
    /// 扫描完成
    Complete,
}

/// 流式输出管理器
pub struct StreamingOutput {
    tx: Sender<StreamMessage>,
    rx: Receiver<StreamMessage>,
}

impl StreamingOutput {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self { tx, rx }
    }

    /// 获取发送端用于发送消息
    pub fn sender(&self) -> Sender<StreamMessage> {
        self.tx.clone()
    }

    /// 启动流式输出显示
    pub fn run_display(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // 启用原始模式以控制终端
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(
            io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableMouseCapture
        )?;

        let mut matches: Vec<MatchResult> = Vec::new();
        let mut current_file = String::new();
        let mut files_scanned = 0;
        let mut total_files = 0;
        let mut matches_found = 0;
        let mut current_pattern = String::new();
        let mut should_exit = false;

        loop {
            // 检查键盘事件
            if event::poll(std::time::Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            should_exit = true;
                        }
                        KeyCode::Esc => {
                            should_exit = true;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            should_exit = true;
                        }
                        _ => {}
                    }
                }
            }

            // 处理消息
            while let Ok(msg) = self.rx.try_recv() {
                match msg {
                    StreamMessage::Match(match_result) => {
                        matches.push(match_result.clone());
                        matches_found += 1;
                        // 更新当前匹配的规则
                        current_pattern = match_result.pattern_name.clone();
                    }
                    StreamMessage::Progress {
                        current_file: file,
                        files_scanned: scanned,
                        total_files: total,
                        matches_found: found,
                    } => {
                        current_file = file;
                        files_scanned = scanned;
                        total_files = total;
                        matches_found = found;
                    }
                    StreamMessage::Complete => {
                        // 扫描完成，但不立即退出，等待用户手动退出
                        // 这样给JSON写入线程足够的时间处理所有消息
                        current_file = "扫描完成，按 q 或 Ctrl+C 退出".to_string();
                    }
                }
            }

            // 绘制界面
            terminal.draw(|f| {
                // 创建分屏布局
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(10),  // 上方结果区域
                        Constraint::Length(8), // 下方进度区域（增加高度以容纳更多信息）
                    ])
                    .split(f.size());

                // 上方区域：匹配结果列表
                let results_chunk = chunks[0];
                let results_block = Block::default()
                    .title("匹配结果 (按 q 或 Ctrl+C 退出)")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow));

                // 创建结果列表项，限制文件名长度为30字符
                let items: Vec<ListItem> = matches
                    .iter()
                    .rev() // 最新的结果显示在最上面
                    .take(100) // 限制显示数量避免内存问题
                    .map(|m| {
                        let confidence_color = match m.confidence.as_str() {
                            "high" => Color::Red,
                            "low" => Color::Yellow,
                            _ => Color::White,
                        };

                        // 限制文件名显示长度为30字符
                        let file_path_str = m.file_path.display().to_string();
                        let truncated_file_path = if file_path_str.len() > 30 {
                            format!("{}...", &file_path_str[..27])
                        } else {
                            file_path_str
                        };

                        let line = Line::from(vec![
                            Span::styled(
                                format!("{}:{} ", truncated_file_path, m.line_number),
                                Style::default().fg(Color::Cyan),
                            ),
                            Span::styled(
                                format!("{} ", m.pattern_name),
                                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                format!("[{}] ", m.confidence),
                                Style::default().fg(confidence_color),
                            ),
                            Span::styled(
                                m.matched_text.clone(),
                                Style::default().fg(Color::Red),
                            ),
                        ]);
                        ListItem::new(line)
                    })
                    .collect();

                let results_list = List::new(items)
                    .block(results_block)
                    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

                f.render_widget(results_list, results_chunk);

                // 下方区域：进度和详细信息
                let progress_chunk = chunks[1];
                
                // 在进度区域内创建子布局
                let progress_subchunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // 进度条
                        Constraint::Length(1), // 当前文件信息
                        Constraint::Length(1), // 当前匹配规则
                        Constraint::Length(1), // 匹配统计信息
                        Constraint::Length(1), // 退出提示
                    ])
                    .split(progress_chunk);

                // 文件进度条
                let progress_block = Block::default()
                    .title("扫描进度")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue));

                let progress_percent = if total_files > 0 {
                    files_scanned as f64 / total_files as f64
                } else {
                    0.0
                };

                let progress_gauge = Gauge::default()
                    .block(progress_block)
                    .gauge_style(Style::default().fg(Color::Blue))
                    .percent((progress_percent * 100.0) as u16)
                    .label(format!(
                        "{}/{} 文件 ({}%)",
                        files_scanned,
                        total_files,
                        (progress_percent * 100.0) as u16
                    ));

                f.render_widget(progress_gauge, progress_subchunks[0]);

                // 当前文件信息（限制文件名长度）
                let current_file_text = if !current_file.is_empty() {
                    let truncated_file = if current_file.len() > 30 {
                        format!("{}...", &current_file[..27])
                    } else {
                        current_file.clone()
                    };
                    format!("当前文件: {}", truncated_file)
                } else {
                    "等待扫描...".to_string()
                };

                let file_info = Paragraph::new(current_file_text)
                    .style(Style::default().fg(Color::Yellow));

                f.render_widget(file_info, progress_subchunks[1]);

                // 当前匹配规则信息
                let pattern_text = if !current_pattern.is_empty() {
                    format!("当前规则: {}", current_pattern)
                } else {
                    "等待匹配...".to_string()
                };

                let pattern_info = Paragraph::new(pattern_text)
                    .style(Style::default().fg(Color::Magenta));

                f.render_widget(pattern_info, progress_subchunks[2]);

                // 匹配统计信息
                let stats_text = format!("已找到匹配: {}", matches_found);
                let stats_info = Paragraph::new(stats_text)
                    .style(Style::default().fg(Color::Green));

                f.render_widget(stats_info, progress_subchunks[3]);

                // 退出提示
                let exit_hint = Paragraph::new("按 q 或 Ctrl+C 退出")
                    .style(Style::default().fg(Color::Gray));

                f.render_widget(exit_hint, progress_subchunks[4]);
            })?;

            // 检查是否应该退出
            if should_exit {
                // 如果是扫描完成导致的退出，等待用户手动退出
                if current_file.is_empty() && files_scanned == total_files && total_files > 0 {
                    // 扫描已完成，但等待用户手动退出
                    current_file = "扫描完成，按 q 或 Ctrl+C 退出".to_string();
                } else {
                    break;
                }
            }

            // 短暂休眠以减少CPU使用
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // 清理终端
        crossterm::execute!(
            io::stdout(),
            crossterm::event::DisableMouseCapture,
            crossterm::terminal::LeaveAlternateScreen
        )?;
        crossterm::terminal::disable_raw_mode()?;

        Ok(())
    }
}

/// 创建流式输出实例
pub fn create_streaming_output() -> (StreamingOutput, Sender<StreamMessage>) {
    let output = StreamingOutput::new();
    let sender = output.sender();
    (output, sender)
}
