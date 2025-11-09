# RipGitleak SQLite 数据库格式说明

## 概述

RipGitleak 使用 SQLite 数据库存储代码扫描结果，为大型代码库提供高性能的存储和查询能力。本文档详细描述了数据库的表结构、字段类型和索引设计。

## 数据库表结构

### scan_results 表

`scan_results` 表存储所有扫描匹配结果，包含以下字段：

| 字段名 | 数据类型 | 约束 | 描述 |
|--------|----------|------|------|
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | 自增主键，唯一标识每条记录 |
| `scan_timestamp` | `DATETIME` | `DEFAULT CURRENT_TIMESTAMP` | 扫描时间戳，自动记录插入时间 |
| `file_path` | `TEXT` | `NOT NULL` | 文件路径，包含匹配的文件完整路径 |
| `line_number` | `INTEGER` | `NOT NULL` | 行号，匹配在文件中的行号（从1开始） |
| `pattern_name` | `TEXT` | `NOT NULL` | 模式名称，匹配的敏感信息模式名称 |
| `confidence` | `TEXT` | `NOT NULL` | 置信度，匹配的置信级别（high/medium/low） |
| `integrity` | `TEXT` | `NOT NULL` | 完整性，匹配的完整性级别（full/part） |
| `matched_text` | `TEXT` | `NOT NULL` | 匹配文本，实际匹配到的敏感信息内容 |
| `line_content` | `TEXT` | `NOT NULL` | 行内容，包含匹配的完整行文本 |
| `context` | `TEXT` | `NOT NULL` | 上下文信息，匹配周围的代码上下文 |
| `file_hash` | `TEXT` | 可为空 | 文件哈希值，用于文件去重（可选） |
| `scan_session` | `TEXT` | 可为空 | 扫描会话标识，用于区分不同扫描会话 |

**注意**: 在实际插入数据时，`file_hash` 字段目前未被使用，所有插入操作都将其设为 NULL。

## 字段详细说明

### 主键字段
- **`id`**: 自动递增的整数主键，确保每条记录的唯一性

### 时间字段
- **`scan_timestamp`**: 自动记录数据插入时间，格式为 SQLite 的 DATETIME 格式

### 文件相关字段
- **`file_path`**: 存储文件的完整路径，使用操作系统原生路径格式
- **`line_number`**: 匹配在文件中的行号，从1开始计数
- **`file_hash`**: 可选字段，可用于文件内容哈希值，用于去重分析

### 匹配信息字段
- **`pattern_name`**: 匹配的敏感信息模式名称，如 "AWS Access Key ID"、"GitHub Token" 等
- **`confidence`**: 置信度级别，表示匹配的可信程度：
  - `high`: 高置信度，极有可能是真实的敏感信息
  - `medium`: 中等置信度，可能是敏感信息
  - `low`: 低置信度，可能是误报
- **`integrity`**: 完整性级别，表示匹配的完整程度：
  - `full`: 完整匹配，包含所有必需的部分
  - `part`: 部分匹配，可能缺少某些部分

### 内容字段
- **`matched_text`**: 实际匹配到的敏感信息文本内容
- **`line_content`**: 包含匹配的完整行文本，便于查看上下文
- **`context`**: 扩展的上下文信息，可能包含多行代码或函数块

### 会话管理字段
- **`scan_session`**: 扫描会话标识，可用于区分不同时间或不同配置的扫描结果

## 索引结构

为提高查询性能，数据库创建了以下索引：

| 索引名 | 字段 | 用途 |
|--------|------|------|
| `idx_file_path` | `file_path` | 按文件路径快速查询 |
| `idx_pattern_name` | `pattern_name` | 按模式名称快速查询 |
| `idx_confidence` | `confidence` | 按置信度快速过滤 |
| `idx_integrity` | `integrity` | 按完整性快速过滤 |
| `idx_scan_session` | `scan_session` | 按扫描会话快速查询 |
| `idx_timestamp` | `scan_timestamp` | 按时间戳排序和查询 |

## 数据类型映射

| SQLite 类型 | Rust 类型 | 描述 |
|-------------|-----------|------|
| `INTEGER` | `i64` | 64位整数 |
| `TEXT` | `String` | UTF-8 字符串 |
| `DATETIME` | `String` | ISO 8601 格式日期时间字符串 |

## 查询示例

### 基本查询
```sql
-- 查询所有高置信度匹配
SELECT * FROM scan_results WHERE confidence = 'high';

-- 按文件路径查询
SELECT * FROM scan_results WHERE file_path LIKE '%config%';

-- 按模式统计
SELECT pattern_name, COUNT(*) FROM scan_results 
GROUP BY pattern_name ORDER BY COUNT(*) DESC;
```

### 高级查询
```sql
-- 查询特定扫描会话的结果
SELECT * FROM scan_results 
WHERE scan_session = 'scan_20241108' AND confidence = 'high';

-- 按时间范围查询
SELECT * FROM scan_results 
WHERE scan_timestamp >= '2024-11-08 00:00:00' 
AND scan_timestamp <= '2024-11-08 23:59:59';

-- 获取统计信息
SELECT confidence, COUNT(*) as count 
FROM scan_results 
GROUP BY confidence 
ORDER BY count DESC;
```

### 性能优化查询
```sql
-- 使用索引的查询（推荐）
SELECT file_path, pattern_name, confidence 
FROM scan_results 
WHERE file_path LIKE '%.py' AND confidence = 'high'
ORDER BY scan_timestamp DESC
LIMIT 100;

-- 避免全表扫描的查询
SELECT COUNT(*) FROM scan_results 
WHERE pattern_name = 'AWS Access Key ID' 
AND integrity = 'full';
```

## 数据库写入器实现

RipGitleak 提供了两种数据库写入器来满足不同场景的需求：

### 同步写入器 (`SyncDatabaseManager`)

同步写入器提供简单可靠的同步写入支持，适用于小型项目或需要即时反馈的场景。

**特点：**
- 同步操作，立即返回结果
- 自动批量插入，默认每1000条记录批量插入一次
- 内置熵过滤，避免存储低熵的误报
- 自动进度报告

**使用示例：**
```rust
let mut sync_manager = SyncDatabaseManager::new(db_path)?;
sync_manager.add_match(match_result)?;
sync_manager.flush_buffer()?;
sync_manager.shutdown()?;
```

### 异步写入器 (`AsyncDatabaseManager`)

异步写入器提供高性能的异步写入支持，适用于大型代码库扫描。

**特点：**
- 异步操作，不阻塞主线程
- 使用独立的工作线程处理数据库写入
- 内置缓冲区管理，默认每1000条记录发送一次
- 自动熵过滤和批量优化
- 优雅关闭机制

**使用示例：**
```rust
let mut async_manager = AsyncDatabaseManager::new(db_path)?;
async_manager.add_match(match_result)?;
async_manager.flush_buffer()?;
async_manager.shutdown()?;
```

### 熵过滤机制

两种写入器都内置了熵过滤机制，在存储前会调用 `has_sufficient_entropy` 函数检查匹配文本的熵值，避免存储低熵的误报。这包括：
- 过滤面向对象语法（如 `Token::GetTokenInfo`）
- 过滤低熵的变量赋值（如 `token = get_info`）
- 保留高熵的真实密钥

## 使用建议

1. **批量操作**: 对于大量数据插入，使用 `insert_results_batch_optimized` 方法
2. **索引利用**: 查询时尽量使用已建立索引的字段作为条件
3. **会话管理**: 使用 `scan_session` 字段区分不同扫描任务
4. **定期维护**: 对于长期使用的数据库，定期执行 `ANALYZE` 命令优化查询性能
5. **写入器选择**: 
   - 小型项目：使用同步写入器
   - 大型代码库：使用异步写入器提高性能

## 性能特点

- **快速插入**: 使用事务和批量操作优化插入性能
- **高效查询**: 通过多字段索引支持复杂查询
- **可扩展**: 表结构设计支持未来的功能扩展
- **兼容性**: 使用标准 SQLite 格式，兼容各种数据库工具

此数据库设计为 RipGitleak 提供了强大的数据存储和分析能力，特别适合处理大型代码库的扫描结果。
