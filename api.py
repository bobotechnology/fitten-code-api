from flask import Flask, request, jsonify
import requests
import json
import time
import random
import string
import configparser
import chardet

"""
Fitten Code API Server

这是一个Flask应用，用于提供Fitten Code API服务。主要功能包括：
1. 配置管理：从config.ini读取配置信息
2. 认证管理：处理Fitten Code的登录认证和token刷新
3. API接口：提供模型信息和聊天完成接口

This is a Flask application that provides Fitten Code API service. Main features include:
1. Configuration Management: Read configuration from config.ini
2. Authentication Management: Handle Fitten Code login authentication and token refresh
3. API Interface: Provide model information and chat completion interface
"""

app = Flask(__name__)

# 全局变量 / Global variables
Ft_username = '' 
Ft_password = ''
Ft_access_token = ''
Ft_refresh_token = ''
Ft_user_id = ''
API_KEY = ''

# ============ 配置管理 / Configuration Management ============

def initialize():
    """初始化配置，从config.ini读取必要的配置信息
    Initialize configuration by reading necessary information from config.ini
    """
    global Ft_username, Ft_password, API_KEY

    with open('config.ini', 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    config = configparser.ConfigParser()
    config.read('config.ini', encoding=encoding)

    Ft_username = config.get('Main', 'username')
    Ft_password = config.get('Main', 'password')
    API_KEY = config.get('Main', 'api_key')
    get_auth_token()
    
# ============ 认证管理 / Authentication Management ============

def get_auth_token():
    """登录Fitten Code并获取认证token
    Login to Fitten Code and get authentication token
    """
    global Ft_access_token, Ft_refresh_token, Ft_user_id

    login_url = 'https://fc.fittentech.com/codeuser/auth/login'
    login_headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Host": "fc.fittentech.com",
        "Origin": "https://fc.fittentech.com",
        "Pragma": "no-cache",
        "Referer": "https://fc.fittentech.com/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    }

    login_data = {
        "username": Ft_username,
        "password": Ft_password
    }

    if not Ft_username or not Ft_password:
        print("Please set your Fittentech username and password in config.ini")
        exit()
    
    response = requests.post(login_url, headers=login_headers, json=login_data)
    
    if response.status_code == 200:
        response_data = response.json()
        Ft_access_token = response_data.get("access_token")
        Ft_refresh_token = response_data.get("refresh_token")
        Ft_user_id = response_data.get("user_info", {}).get("user_id")
        print(f"Auth token: {Ft_access_token}")
        print(f"User ID: {Ft_user_id}")
    else:
        raise Exception(f"Failed to get auth token: {response.status_code}, {response.text}")

def refresh_auth_token():
    """刷新认证token
    Refresh authentication token
    """
    global Ft_access_token, Ft_refresh_token

    api_url = 'https://fc.fittentech.com/codeuser/auth/refresh_access_token'
    
    api_headers = {
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Origin': 'https://fc.fittentech.com',
        'Pragma': 'no-cache',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'),
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'authorization': f'Bearer {Ft_refresh_token}',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    }

    if not Ft_refresh_token:
        get_auth_token()
        return

    response = requests.post(api_url, headers=api_headers, json={})
    
    if response.status_code == 200:
        response_data = response.json()
        Ft_access_token = response_data.get("access_token")
        Ft_refresh_token = response_data.get("refresh_token")
        print("Refresh success.")
        print(f"Auth token: {Ft_access_token}")
    else:
        get_auth_token()

# ============ API接口 / API Interface ============

def generate_random_id(length=8):
    """生成指定长度的随机字符串ID
    Generate a random string ID with specified length
    
    Args:
        length (int): ID长度，默认为8 / ID length, default is 8
    
    Returns:
        str: 随机生成的ID / Generated random ID
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_response(user_input, system_prompt, assistant_last_response):
    """调用Fitten Code API获取响应
    Call Fitten Code API to get response
    
    Args:
        user_input (str): 用户输入 / User input
        system_prompt (str): 系统提示 / System prompt
        assistant_last_response (str): 助手上一次的回复 / Assistant's last response
    
    Returns:
        Response: API响应对象 / API response object
    """
    api_url = f'https://fc.fittentech.com/codeapi/chat_auth?apikey={Ft_user_id}'
    
    api_headers = {
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Origin': 'https://fc.fittentech.com',
        'Pragma': 'no-cache',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'),
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'authorization': f'Bearer {Ft_access_token}',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    }

    api_data = {
        "inputs": f"<|system|>\n{system_prompt}\n<|end|>\n<|user|>\n{user_input}\n<|end|>\n<|assistant|>\n{assistant_last_response}\n",
        "ft_token": Ft_user_id,
    }

    return requests.post(api_url, headers=api_headers, json=api_data)

def parse_response(response_text):
    """解析API响应文本
    Parse API response text
    
    Args:
        response_text (str): API响应文本 / API response text
    
    Returns:
        str: 解析后的输出文本 / Parsed output text
    """
    output_sentence = []
    for line in response_text.splitlines():
        try:
            json_data = json.loads(line)
            if 'delta' in json_data:
                output_sentence.append(json_data['delta'])
        except json.JSONDecodeError:
            pass
    return ''.join(output_sentence)

@app.route('/v1/models')
def models():
    """返回支持的模型信息
    Return supported model information
    
    Returns:
        Response: 模型信息的JSON响应 / JSON response containing model information
    """
    return jsonify({
        "models": [
            {
                "id": "fitten-code",
                "name": "Fitten Code"
            }
        ]
    })

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completion():
    """处理聊天完成请求
    Handle chat completion request
    
    Returns:
        Response: 聊天完成的JSON响应 / JSON response for chat completion
    """
    # 验证API密钥 / Verify API key
    api_key = request.headers.get('Authorization')
    if api_key != f'Bearer {API_KEY}':
        return jsonify({"error": "Unauthorized access. Invalid API Key."}), 401
    
    data = request.json
    messages = data.get('messages', [])
    
    if not messages or not isinstance(messages, list):
        return jsonify({"error": "Invalid input"}), 400

    # 提取消息内容 / Extract message content
    user_input = ''
    system_prompt = ''
    model = ''
    assistant_last_response = ''

    for message in messages:
        role = message.get('role')
        model = message.get('model', "fitten-code")
        content = message.get('content', '')
        if role == 'user':
            user_input = content
        elif role == 'system':
            system_prompt = content
        elif role == 'assistant':
            assistant_last_response = content

    if not user_input:
        return jsonify({"error": "User input not found"}), 400

    # 获取API响应 / Get API response
    response = get_response(user_input, system_prompt, assistant_last_response)
    
    # 处理token过期情况 / Handle token expiration
    if response.status_code == 401:
        if response.json().get("detail") == "Token time expired: expired_token: The token is expired":
            refresh_auth_token()
            response = get_response(user_input, system_prompt, assistant_last_response)
    
    final_output = parse_response(response.text)
    
    # 返回格式化的响应 / Return formatted response
    return jsonify({
        "id": generate_random_id(),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": final_output
            },
            "finish_reason": "stop"
        }]
    })

if __name__ == "__main__":
    initialize()
    app.run(host='0.0.0.0', port=5000)
