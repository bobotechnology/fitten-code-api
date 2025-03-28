# Fitten Code API Server

[English](https://github.com/bobotechnology/fitten-code-api/blob/main/README.md) | 简体中文

## 简介
Fitten Code API Server 是一个基于 Flask 的应用程序，为 Fitten Code 提供 API 服务。它作为客户端和 Fitten Code 服务之间的中间件，提供类似 OpenAI API 格式的标准化 API 接口。该服务器处理身份验证、令牌管理，并为应用程序提供一个简洁的接口来与 Fitten Code 的功能进行交互。

## 特性
- 通过 config.ini 进行配置管理
- 自动令牌管理（登录、刷新）
- OpenAI 风格的 API 端点
- 支持流式聊天补全功能
- 内置错误处理和令牌过期管理
- 用于调试和监控的日志系统
- 安全的 API 密钥认证
- 支持128k上下文长度

## 环境要求
- Python 3.x
- Flask
- Requests
- chardet

## 安装步骤
1. 克隆此仓库
   ```bash
   git clone https://github.com/bobotechnology/fitten-code-api.git
   cd fitten-code-api
   ```

2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

## 配置说明
1. 在项目根目录创建 `config.ini` 文件，内容如下：
   ```ini
   [Main]
   username=你的_fittentech_用户名
   password=你的_fittentech_密码
   api_key=你的自定义_api_密钥
   ```

   配置参数说明：
   - `username`：您的 Fitten Code 账号用户名
   - `password`：您的 Fitten Code 账号密码
   - `api_key`：用于客户端认证的自定义 API 密钥（您可以创建自己的安全密钥）

## 使用方法
1. 启动服务器：
   ```bash
   python api.py
   ```
   服务器默认将在 `http://localhost:5000` 运行

2. API 接口：
   - `GET /v1/models`：列出可用模型
   - `POST /v1/chat/completions`：聊天补全接口（支持流式响应）

3. API 调用示例：

   **常规请求：**
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

   **流式请求：**
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
           {"role": "user", "content": "Write a short story."}
       ]
   }

   with requests.post(url, headers=headers, json=data, stream=True) as response:
       for line in response.iter_lines():
           if line:
               line_text = line.decode('utf-8')
               if line_text.startswith('data: '):
                   data_str = line_text[6:]
                   if data_str == "[DONE]":
                       break
                   try:
                       chunk = json.loads(data_str)
                       if 'choices' in chunk and len(chunk['choices']) > 0:
                           content = chunk['choices'][0].get('delta', {}).get('content', '')
                           if content:
                               print(content, end='', flush=True)
                   except json.JSONDecodeError:
                       pass
   print()  # 最后的换行
   ```

## 高级配置

服务器在项目目录中创建一个 `fitten_api.log` 日志文件，其中包含有关服务器操作、API 请求和错误的详细信息。这对调试非常有用。

## 错误处理

API 服务器处理各种错误场景：
- 无效的 API 密钥认证
- 令牌过期和自动刷新
- API 请求失败
- 速率限制和服务器错误

## 许可证

本项目采用 MIT 许可证 - 详情请参见 [LICENSE_CN.md](https://github.com/bobotechnology/fitten-code-api/blob/main/LICENSE_CN.md) 文件。