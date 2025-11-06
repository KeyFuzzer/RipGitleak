# RipGitleak 🚀

**基于 Rust 的超快速密钥泄露扫描器**

RipGitleak 是一个高性能的密钥泄露检测工具，利用 Rust 的 `regex` crate（ripgrep 的底层引擎）和 [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db) 来快速扫描代码仓库中的敏感信息泄露。

## ✨ 特性

- **极速扫描**: 基于 ripgrep 的底层正则表达式引擎，提供超高性能
- **全面覆盖**: 集成 1600+ 个密钥检测规则，覆盖 AWS、GitHub、Google 等主流服务
- **智能过滤**: 支持按置信度（高/低）过滤结果
- **多格式输出**: 支持详细、简单、JSON 三种输出格式
- **灵活配置**: 支持文件扩展名过滤和目录递归扫描
- **彩色输出**: 直观的彩色终端输出，便于快速识别问题

## 🚀 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/your-username/RipGitleak.git
cd RipGitleak

# 构建项目
cargo build --release
```

### 基本使用

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

## 📖 使用示例

### 详细输出模式
```bash
./target/release/RipGitleak --path ./test_directory
```

输出示例：
```
→ test_directory/test_file.py:4 AWS API Key
  Confidence: high
  Match: AKIAIOSFODNN7EXAMPLE
  Line: aws_key = "AKIAIOSFODNN7EXAMPLE"
```

### 简单输出模式
```bash
./target/release/RipGitleak --path ./test_directory --format simple
```

输出示例：
```
test_directory/test_file.py:4 AWS API Key [high]
test_directory/test_file.py:7 Github Personal Access Token [high]
```

### JSON 输出模式
```bash
./target/release/RipGitleak --path ./test_directory --format json
```

## 🔧 命令行选项

```bash
USAGE:
    RipGitleak [OPTIONS]

OPTIONS:
    -p, --path <PATH>              # 要扫描的目录 [默认: .]
    -d, --database <DATABASE>      # 模式数据库文件 [默认: secrets-patterns-db/db/rules-stable.yml]
    -H, --high-confidence-only     # 只显示高置信度匹配
    -f, --format <FORMAT>          # 输出格式: simple, detailed, json [默认: detailed]
    -i, --include-ext <INCLUDE_EXT> # 包含的文件扩展名（逗号分隔）
    -e, --exclude-ext <EXCLUDE_EXT> # 排除的文件扩展名（逗号分隔）
    -h, --help                     # 显示帮助信息
    -V, --version                  # 显示版本信息
```

## 📊 性能对比

RipGitleak 利用 Rust 的高性能正则表达式引擎，在大型代码仓库中表现出色：

- **快速启动**: 毫秒级启动时间
- **高效内存**: 优化的内存使用
- **并行处理**: 支持多文件并行扫描
- **智能缓存**: 编译后的正则表达式缓存

## 🗃️ 支持的密钥类型

RipGitleak 可以检测以下类型的敏感信息：

- **AWS**: API Keys, Access Keys, Secret Keys, ARNs
- **GitHub**: Personal Access Tokens, OAuth Tokens
- **Google**: API Keys, OAuth Tokens, Service Account Keys
- **Database**: Connection Strings, Passwords
- **API Keys**: Stripe, Twilio, SendGrid, etc.
- **加密密钥**: SSH Keys, PGP Keys, SSL Certificates
- **认证令牌**: JWT Tokens, Session Tokens

完整的检测规则列表请参考 [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db)。

## 🔍 工作原理

1. **模式加载**: 从 YAML 数据库加载 1600+ 个正则表达式模式
2. **正则编译**: 使用 Rust 的 `regex` crate 编译所有模式
3. **文件遍历**: 递归扫描目标目录中的所有文件
4. **模式匹配**: 对每个文件逐行应用所有正则表达式
5. **结果聚合**: 收集并格式化所有匹配结果

## 🛠️ 开发

### 项目结构
```
RipGitleak/
├── Cargo.toml              # Rust 项目配置
├── src/
│   └── main.rs             # 主应用程序
├── secrets-patterns-db/    # 密钥模式数据库
│   ├── db/                 # 模式数据库文件
│   ├── datasets/           # 各种模式源
│   └── scripts/            # Python 脚本
└── test_directory/         # 测试文件
```

### 构建和测试

```bash
# 开发构建
cargo build

# 发布构建
cargo build --release

# 运行测试
cargo test

# 代码格式化
cargo fmt

# 代码检查
cargo clippy
```

## 🤝 贡献

欢迎贡献！请参考以下步骤：

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目基于 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db) - 提供全面的密钥检测模式
- [ripgrep](https://github.com/BurntSushi/ripgrep) - 高性能正则表达式引擎的灵感来源
- [Rust](https://www.rust-lang.org/) - 提供内存安全和性能保证

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 [Issue](https://github.com/your-username/RipGitleak/issues)
- 发送邮件: your-email@example.com

---

**RipGitleak** - 让密钥泄露检测变得快速而简单！ 🚀