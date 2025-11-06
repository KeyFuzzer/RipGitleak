# RipGitleak 🚀

**基于 Rust 的超快速密钥泄露扫描器**

RipGitleak 是一个高性能的密钥泄露检测工具，利用 Rust 的 `fancy-regex` crate 来快速扫描代码仓库中的敏感信息泄露。

数据源来自 [KEYSENTINEL](https://github.com/XingTuLab/KEYSENTINEL) 和 [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) 。

## 🚀 Quick Start

### Installation

```bash
# 克隆项目
git clone https://github.com/your-username/RipGitleak.git
cd RipGitleak

# 构建项目
cargo build --release
```

### Basic Usage

```bash
# 扫描当前目录
./target/release/RipGitleak

# 扫描指定目录
./target/release/RipGitleak --path /path/to/repo

# 只显示高置信度结果
./target/release/RipGitleak --high-confidence-only

# 简单输出格式
./target/release/RipGitleak --format simple

# JSON 输出格式
./target/release/RipGitleak --format json
```
## 🔧 Command Line Arguments

```bash
USAGE:
    RipGitleak [OPTIONS]

OPTIONS:
    -p, --path <PATH>              # 要扫描的目录 [默认: .]
    -d, --database <DATABASE>      # 模式数据库文件 [默认: rules/rules-stable.yml]
    -H, --high-confidence-only     # 只显示高置信度匹配
    -f, --format <FORMAT>          # 输出格式: simple, detailed, json [默认: detailed]
    -i, --include-ext <INCLUDE_EXT> # 包含的文件扩展名（逗号分隔）
    -e, --exclude-ext <EXCLUDE_EXT> # 排除的文件扩展名（逗号分隔）
    -h, --help                     # 显示帮助信息
    -V, --version                  # 显示版本信息
```

## 🔍 Features

1. **模式加载**: 从 YAML 数据库加载600多个正则表达式模式
2. **正则编译**: 使用 Rust 的 `fancy-regex` crate 编译所有模式
3. **文件遍历**: 递归扫描目标目录中的所有文件
4. **模式匹配**: 对每个文件逐行应用所有正则表达式
5. **结果聚合**: 收集并格式化所有匹配结果

## 📄 Licence

本项目基于 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。
