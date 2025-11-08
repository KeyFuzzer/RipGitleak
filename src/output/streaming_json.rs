use colored::Colorize;
use crossbeam_channel::Receiver;
use serde_json::to_writer;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::output::formatter::MatchResult;
use crate::output::streaming::StreamMessage;

/// 流式JSON写入器
pub struct StreamingJsonWriter {
    output_path: std::path::PathBuf,
    writer: BufWriter<File>,
    first_item: bool,
}

impl StreamingJsonWriter {
    pub fn new(output_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // 创建输出目录
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 创建文件
        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);
        
        // 写入JSON数组开始标记
        writer.write_all(b"[\n")?;

        Ok(Self {
            output_path: output_path.to_path_buf(),
            writer,
            first_item: true,
        })
    }

    /// 写入单个匹配结果
    pub fn write_match(&mut self, match_result: &MatchResult) -> Result<(), Box<dyn std::error::Error>> {
        // 添加逗号分隔符（除了第一个元素）
        if !self.first_item {
            self.writer.write_all(b",\n")?;
        } else {
            self.first_item = false;
        }

        // 序列化并写入匹配结果
        let json_match = self.match_to_json(match_result);
        let json_string = serde_json::to_string(&json_match)?;
        self.writer.write_all(json_string.as_bytes())?;

        Ok(())
    }

    /// 完成写入并关闭文件
    pub fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 写入JSON数组结束标记
        self.writer.write_all(b"\n]")?;
        
        // 确保所有数据都写入磁盘
        self.writer.flush()?;

        println!(
            "{} 结果已写入: {}",
            "INFO:".blue(),
            self.output_path.display()
        );

        Ok(())
    }

    /// 将匹配结果转换为JSON格式
    fn match_to_json(&self, match_result: &MatchResult) -> HashMap<&str, String> {
        let mut map = HashMap::new();
        map.insert("file", match_result.file_path.to_string_lossy().to_string());
        map.insert("line", match_result.line_number.to_string());
        map.insert("pattern", match_result.pattern_name.clone());
        map.insert("confidence", match_result.confidence.clone());
        map.insert("match", match_result.matched_text.clone());
        map.insert("content", match_result.line_content.clone());
        map
    }
}

/// 启动流式JSON写入线程
pub fn start_json_writer_thread(
    output_path: &Path,
    rx: Receiver<StreamMessage>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn std::error::Error>> {
    let output_path = output_path.to_path_buf();
    
    let handle = std::thread::spawn(move || {
        let mut json_writer = match StreamingJsonWriter::new(&output_path) {
            Ok(writer) => writer,
            Err(e) => {
                eprintln!("{} 创建JSON写入器失败: {}", "ERROR:".red(), e);
                return;
            }
        };

        let mut match_count = 0;

        loop {
            match rx.recv() {
                Ok(StreamMessage::Match(match_result)) => {
                    if let Err(e) = json_writer.write_match(&match_result) {
                        eprintln!("{} 写入JSON失败: {}", "ERROR:".red(), e);
                        break;
                    }
                    match_count += 1;
                    
                    // 每写入一定数量的匹配就刷新一次
                    if match_count % 100 == 0 {
                        if let Err(e) = json_writer.writer.flush() {
                            eprintln!("{} 刷新JSON文件失败: {}", "ERROR:".red(), e);
                        }
                    }
                }
                Ok(StreamMessage::Complete) => {
                    break;
                }
                Err(_) => {
                    // 通道关闭，退出
                    break;
                }
                _ => {
                    // 忽略其他消息类型
                }
            }
        }

        // 完成写入
        if let Err(e) = json_writer.finish() {
            eprintln!("{} 完成JSON写入失败: {}", "ERROR:".red(), e);
        }
    });

    Ok(handle)
}
