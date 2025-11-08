use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use lru::LruCache;

/// 文件缓存管理器
#[derive(Debug)]
pub struct FileCacheManager {
    cache: Mutex<LruCache<String, Arc<String>>>,
    max_size: usize,
}

impl FileCacheManager {
    pub fn new(max_size: usize) -> Self {
        let non_zero_size = NonZeroUsize::new(max_size).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(non_zero_size)),
            max_size,
        }
    }

    /// 获取文件内容，如果缓存中不存在则从文件系统读取
    pub fn get_or_load(&self, file_path: &str) -> Option<Arc<String>> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(content) = cache.get(file_path) {
            return Some(content.clone());
        }
        
        // 从文件系统读取
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let content_arc = Arc::new(content);
            cache.put(file_path.to_string(), content_arc.clone());
            Some(content_arc)
        } else {
            None
        }
    }

    /// 清除缓存
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// 获取缓存统计信息
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap();
        CacheStats {
            size: cache.len(),
            max_size: self.max_size,
        }
    }
}

/// 缓存统计信息
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
}

impl CacheStats {
    pub fn usage_percentage(&self) -> f64 {
        (self.size as f64 / self.max_size as f64) * 100.0
    }
}

/// 内存池管理器
#[derive(Debug)]
pub struct MemoryPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl MemoryPool {
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::new()),
            buffer_size,
            max_pool_size,
        }
    }

    /// 从池中获取缓冲区
    pub fn get_buffer(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.pop().unwrap_or_else(|| vec![0; self.buffer_size])
    }

    /// 将缓冲区返回到池中
    pub fn return_buffer(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.lock().unwrap();
        if buffers.len() < self.max_pool_size {
            buffer.clear();
            buffers.push(buffer);
        }
    }

    /// 获取池统计信息
    pub fn stats(&self) -> PoolStats {
        let buffers = self.buffers.lock().unwrap();
        PoolStats {
            available_buffers: buffers.len(),
            max_pool_size: self.max_pool_size,
            buffer_size: self.buffer_size,
        }
    }
}

/// 内存池统计信息
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available_buffers: usize,
    pub max_pool_size: usize,
    pub buffer_size: usize,
}

impl PoolStats {
    pub fn usage_percentage(&self) -> f64 {
        (self.available_buffers as f64 / self.max_pool_size as f64) * 100.0
    }
}

/// 性能监控器
#[derive(Debug)]
pub struct PerformanceMonitor {
    start_time: Instant,
    file_scans: Mutex<usize>,
    matches_found: Mutex<usize>,
    total_bytes_processed: Mutex<usize>,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            file_scans: Mutex::new(0),
            matches_found: Mutex::new(0),
            total_bytes_processed: Mutex::new(0),
        }
    }

    /// 记录文件扫描
    pub fn record_file_scan(&self, bytes_processed: usize) {
        let mut file_scans = self.file_scans.lock().unwrap();
        let mut total_bytes = self.total_bytes_processed.lock().unwrap();
        
        *file_scans += 1;
        *total_bytes += bytes_processed;
    }

    /// 记录匹配发现
    pub fn record_match(&self) {
        let mut matches_found = self.matches_found.lock().unwrap();
        *matches_found += 1;
    }

    /// 获取性能统计信息
    pub fn get_stats(&self) -> PerformanceStats {
        let elapsed = self.start_time.elapsed();
        let file_scans = *self.file_scans.lock().unwrap();
        let matches_found = *self.matches_found.lock().unwrap();
        let total_bytes = *self.total_bytes_processed.lock().unwrap();

        let files_per_second = if elapsed.as_secs() > 0 {
            file_scans as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let bytes_per_second = if elapsed.as_secs() > 0 {
            total_bytes as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        PerformanceStats {
            elapsed_time: elapsed,
            files_scanned: file_scans,
            matches_found,
            total_bytes_processed: total_bytes,
            files_per_second,
            bytes_per_second,
        }
    }

    /// 重置监控器
    pub fn reset(&mut self) {
        self.start_time = Instant::now();
        *self.file_scans.lock().unwrap() = 0;
        *self.matches_found.lock().unwrap() = 0;
        *self.total_bytes_processed.lock().unwrap() = 0;
    }
}

/// 性能统计信息
#[derive(Debug, Clone)]
pub struct PerformanceStats {
    pub elapsed_time: Duration,
    pub files_scanned: usize,
    pub matches_found: usize,
    pub total_bytes_processed: usize,
    pub files_per_second: f64,
    pub bytes_per_second: f64,
}

impl PerformanceStats {
    pub fn print_summary(&self) {
        println!("性能统计:");
        println!("  运行时间: {:.2?}", self.elapsed_time);
        println!("  扫描文件: {}", self.files_scanned);
        println!("  发现匹配: {}", self.matches_found);
        println!("  处理数据: {:.2} MB", self.total_bytes_processed as f64 / 1024.0 / 1024.0);
        println!("  文件/秒: {:.1}", self.files_per_second);
        println!("  数据/秒: {:.2} MB/s", self.bytes_per_second / 1024.0 / 1024.0);
    }
}

/// 全局性能管理器
#[derive(Debug)]
pub struct PerformanceManager {
    pub file_cache: FileCacheManager,
    pub memory_pool: MemoryPool,
    pub monitor: PerformanceMonitor,
}

impl PerformanceManager {
    pub fn new() -> Self {
        Self {
            file_cache: FileCacheManager::new(100), // 缓存100个文件
            memory_pool: MemoryPool::new(1024 * 1024, 50), // 1MB缓冲区，最多50个
            monitor: PerformanceMonitor::new(),
        }
    }

    /// 获取完整性能报告
    pub fn get_full_report(&self) -> FullPerformanceReport {
        let cache_stats = self.file_cache.stats();
        let pool_stats = self.memory_pool.stats();
        let perf_stats = self.monitor.get_stats();

        FullPerformanceReport {
            cache_stats,
            pool_stats,
            perf_stats,
        }
    }
}

/// 完整性能报告
#[derive(Debug, Clone)]
pub struct FullPerformanceReport {
    pub cache_stats: CacheStats,
    pub pool_stats: PoolStats,
    pub perf_stats: PerformanceStats,
}

impl FullPerformanceReport {
    pub fn print_detailed(&self) {
        println!("=== 详细性能报告 ===");
        self.perf_stats.print_summary();
        println!();
        println!("缓存统计:");
        println!("  缓存文件: {}/{} ({:.1}%)", 
            self.cache_stats.size, 
            self.cache_stats.max_size,
            self.cache_stats.usage_percentage());
        println!();
        println!("内存池统计:");
        println!("  可用缓冲区: {}/{} ({:.1}%)", 
            self.pool_stats.available_buffers,
            self.pool_stats.max_pool_size,
            self.pool_stats.usage_percentage());
        println!("  缓冲区大小: {:.2} MB", 
            self.pool_stats.buffer_size as f64 / 1024.0 / 1024.0);
    }
}

// 全局性能管理器实例
use std::sync::OnceLock;

static GLOBAL_PERF_MANAGER: OnceLock<PerformanceManager> = OnceLock::new();

pub fn get_global_perf_manager() -> &'static PerformanceManager {
    GLOBAL_PERF_MANAGER.get_or_init(|| PerformanceManager::new())
}
