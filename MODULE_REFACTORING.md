# RipGitleak 模块化重构文档

## 重构概述

本次重构将原有的单一 `main.rs` 文件拆分为多个模块，实现了代码的职责分离和更好的可维护性。

## 模块结构

```
src/
├── main.rs              # 程序入口，命令行解析
├── config/              # 配置相关模块
│   ├── mod.rs
│   ├── args.rs          # 命令行参数定义
│   └── patterns.rs      # 模式数据结构定义
├── scanner/             # 扫描引擎模块
│   ├── mod.rs
│   ├── engine.rs        # 主扫描逻辑和模式编译
│   ├── file_scanner.rs  # 文件扫描实现
│   └── prefilter.rs     # 预过滤优化
├── analysis/            # 分析工具模块
│   ├── mod.rs
│   ├── entropy.rs       # 熵值计算
│   └── multiline.rs     # 多行匹配处理
├── output/              # 输出模块
│   ├── mod.rs
│   ├── formatter.rs     # 结果格式化
│   └── writer.rs        # 文件写入
├── progress/            # 进度显示模块
│   ├── mod.rs
│   └── display.rs       # 进度条管理
└── utils/               # 工具函数模块
    ├── mod.rs
    └── keywords.rs      # 关键词提取和文件过滤
```

## 模块职责说明

### config 模块
- **args.rs**: 定义命令行参数结构体和枚举类型
- **patterns.rs**: 定义模式相关的数据结构（Pattern, PatternEntry, PatternDatabase, TokenMatch）

### scanner 模块
- **engine.rs**: 模式加载、编译和线程间共享
- **file_scanner.rs**: 文件扫描核心逻辑，包括并行处理和模式匹配
- **prefilter.rs**: 分层预过滤优化，提升扫描性能

### analysis 模块
- **entropy.rs**: 香农熵计算和熵值过滤
- **multiline.rs**: 多行匹配处理（如私钥块提取）

### output 模块
- **formatter.rs**: 结果格式化输出（简单、详细、JSON、Token格式）
- **writer.rs**: 结果写入文件功能

### progress 模块
- **display.rs**: 多进度条显示管理

### utils 模块
- **keywords.rs**: 文件扩展名过滤和关键词处理

## 重构优势

1. **职责分离**: 每个模块专注于单一职责，代码结构更清晰
2. **可测试性**: 模块化后更容易编写单元测试
3. **可维护性**: 代码逻辑分散在不同模块，便于理解和修改
4. **可扩展性**: 新增功能时只需在相应模块添加代码
5. **性能优化**: 可以针对不同模块进行针对性优化

## 功能验证

重构后的代码通过了以下验证：
- ✅ 编译成功，无错误
- ✅ 所有单元测试通过
- ✅ 程序正常运行，扫描功能完整
- ✅ 命令行参数解析正常
- ✅ 进度显示正常工作
- ✅ 多种输出格式正常

## 性能表现

重构后的程序保持了原有的性能特性：
- 分层预过滤优化
- 并行文件处理
- 内存映射文件读取
- 动态批次大小调整

## 使用方式

重构后的使用方式保持不变：

```bash
# 扫描当前目录
cargo run -- --path . --format simple

# 扫描指定目录，输出详细结果
cargo run -- --path /path/to/scan --format detailed

# 仅显示高置信度匹配
cargo run -- --path . --high-confidence-only

# 输出JSON格式结果
cargo run -- --path . --format json --output-dir ./results
```

## 后续改进建议

1. 为每个模块添加更详细的文档注释
2. 增加更多的单元测试覆盖
3. 考虑添加配置文件的持久化支持
4. 实现插件系统以支持自定义模式
5. 添加性能监控和统计功能

## 总结

本次模块化重构成功地将一个大型单文件项目重构为结构清晰的模块化项目，提高了代码的可维护性和可扩展性，同时保持了原有的功能和性能。
