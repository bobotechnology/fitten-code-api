# Fitten Code API Server

[English](https://github.com/bobotechnology/fitten-code-api/blob/master/README.md) | 简体中文

### 简介
Fitten Code API Server 是一个基于 Flask 的应用程序，为 Fitten Code 提供 API 服务。它作为客户端和 Fitten Code 服务之间的中间件，提供类似 OpenAI API 格式的标准化 API 接口。

### 特性
- 通过 config.ini 进行配置管理
- 自动令牌管理（登录、刷新）
- OpenAI 风格的 API 端点
- 支持聊天补全功能
- 内置错误处理和令牌过期管理

### 环境要求
- Python 3.x
- Flask
- Requests
- 其他依赖项（见 requirements.txt）

### 安装步骤
1. 克隆此仓库
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

### 配置说明
1. 复制或重命名 `config.ini` 并填写您的凭据：
   ```ini
   [Main]
   username=你的_fittentech_用户名
   password=你的_fittentech_密码
   api_key=你的自定义_api_密钥
   ```
   - `username`：您的 Fitten Code 账号用户名
   - `password`：您的 Fitten Code 账号密码
   - `api_key`：用于客户端认证的自定义 API 密钥

### 使用方法
1. 启动服务器：
   ```bash
   python api.py
   ```
   服务器将在 `http://localhost:5000` 运行

2. API 接口：
   - GET `/v1/models`：列出可用模型
   - POST `/v1/chat/completions`：聊天接口

3. API 调用示例：
   ```python
   import requests
   import json

   url = "http://localhost:5000/v1/chat/completions"
   headers = {
       "Authorization": "Bearer your_api_key",
       "Content-Type": "application/json"
   }
   data = {
       "messages": [
           {"role": "system", "content": "You are a helpful assistant."},
           {"role": "user", "content": "Hello!"}
       ]
   }

   response = requests.post(url, headers=headers, json=data)
   print(json.dumps(response.json(), indent=2))
   ```

### 许可证
本项目采用 MIT 许可证 - 详情请参见 LICENSE_CN.md 文件。