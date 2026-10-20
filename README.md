# SecAgentGuard
> 基于大模型Agent的安全研判系统，集成向量检索、权限过滤、蜜罐工具与操作审计，面向AI安全场景。

## ✨ 项目简介
SecAgentGuard 是一个安全领域智能Agent原型，基于 LangGraph 构建Agent工作流，结合 Chroma 向量数据库 + BGE Embedding 实现知识库检索，支持 `where` 元数据权限过滤，内置 HoneyTool 恶意扫描工具，所有工具调用、LLM输出全程留存审计日志，用于研究Agent权限管控、提示注入、恶意指令劫持等AI安全风险。

## 🛠️ 技术栈
- Agent框架：LangGraph、LangChain
- 向量检索：ChromaDB、BGE Embedding
- 运行环境：Python 3.11，支持 Docker Compose 容器一键部署
- 安全能力：元数据权限过滤、蜜罐工具调用、全链路审计日志、恶意行为检测

## 📁 目录结构
```
SecAgentGuard/
├── src/                 # 核心源码
├── .venv/               # Python虚拟环境（已加入gitignore）
├── Dockerfile           # 容器构建配置
├── docker-compose.yml    # compose编排文件
├── requirements.txt     # 依赖清单
├── .gitignore
└── README.md
```

## 🚀 快速启动
### 方式1：本地虚拟环境运行
```bash
# 创建虚拟环境
python -m venv .venv
# 激活环境
.venv\Scripts\activate
# 安装依赖
pip install -r requirements.txt
# 启动
python src/demo_core.py
```

### 方式2：Docker Compose 部署
```bash
docker compose up --build
```

## ⚠️ 环境配置
新建 `.env` 文件存放密钥与配置，**不要提交到代码仓库**
```env
# Embedding / LLM API KEY
API_KEY=xxx
```

## 📌 核心能力
1. 向量知识库检索：BGE Embedding + Chroma，支持文档向量化检索
2. 细粒度权限控制：Chroma where条件过滤，不同角色隔离可访问文档
3. Agent工具调用：LangGraph编排，内置 HoneyTool 恶意扫描工具
4. 安全审计：所有LLM输入、工具调用、返回结果自动记录审计日志
5. 风险研究：用于验证Agent越权访问、恶意指令劫持的防护方案

## 📜 License
MIT
```

---
### 配套小提示
1. 在仓库页面点 `Add file` → `Create new file`，文件名填 `README.md`，粘贴上面全部内容，提交即可
2. 你现在仓库里把 `.venv` 传上去了！这个是**问题**：
`.venv` 不应该上传，我给你清理的命令（PowerShell执行）：
```powershell
# 从git版本库删除 .venv，本地文件保留
git rm --cached -r .venv
git commit -m "chore: remove .venv from repo, already in gitignore"
git push
```
> `--cached` 只会删掉远程仓库里的，你本地的虚拟环境不会丢，非常关键。
