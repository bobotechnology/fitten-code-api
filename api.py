from flask import Flask, request, jsonify
import requests
import json
import time
import random
import string
import configparser

app = Flask(__name__)

# 初始化变量
# Initialize variables
Ft_username = '' 
Ft_password = ''
Ft_access_token = ''
Ft_refresh_token = ''
Ft_user_id = ''
API_KEY = ''

def initaliaze():
    # 初始化
    # initaliaze
    global Ft_username
    global Ft_password
    global API_KEY
    config = configparser.ConfigParser()
    config.read('config.ini')
    Ft_username = config.get('Main', 'username')
    Ft_password = config.get('Main', 'password')
    API_KEY = config.get('Main', 'api_key')
    get_auth_token()
    

def get_auth_token():
    # 登录并获取相关信息
    # Login and get related information
    global Ft_access_token
    global Ft_refresh_token
    global Ft_user_id
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
    # 刷新Fittentech auth token
    # Refresh Fittentech auth token
    global Ft_access_token
    global Ft_refresh_token

    api_url = f'https://fc.fittentech.com/codeuser/auth/refresh_access_token'
    
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

    api_data = {}
    if not Ft_refresh_token:
        get_auth_token()
        return
    response = requests.post(api_url, headers=api_headers, json=api_data)
    
    if response.status_code == 200:
        response_data = response.json()
        Ft_access_token = response_data.get("access_token")
        Ft_refresh_token = response_data.get("refresh_token")
        print("Refresh success.")
        print(f"Auth token: {Ft_access_token}")
    else:
        get_auth_token()


def generate_random_id(length=8):
    # 生成一个指定长度的随机字符串，包含字母和数字。
    # Generate a random string with specified length, containing letters and digits.
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_response(user_input, system_prompt, assistant_last_response):
    # 调用Fittentech的API获取响应
    # Call Fittentech API to get response

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

    response = requests.post(api_url, headers=api_headers, json=api_data)
    return response.text

def parse_response(response_text):
    # 解析Fittentech的API返回的响应
    # Parse Fittentech API response
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
    # 返回模型信息
    # Return model information
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
    # 聊天接口
    # Chat interface
    api_key = request.headers.get('Authorization')
    if api_key != f'Bearer {API_KEY}':
        return jsonify({"error": "Unauthorized access. Invalid API Key."}), 401
    
    data = request.json

    messages = data.get('messages', [])
    
    if not messages or not isinstance(messages, list):
        return jsonify({"error": "Invalid input"}), 400

    # 初始化变量
    # Initialize variables
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

    response_text = get_response(user_input, system_prompt, assistant_last_response)
    
    # 检测response_text是为token失效,重新获取token并重新请求
    # Detect response_text is token expired, refresh token and request again
    if response_text == {"detail":"Invalid token: Signature verification failed."}:
        refresh_auth_token()
        response_text = get_response(user_input, system_prompt, assistant_last_response)
    final_output = parse_response(response_text)
    
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
    initaliaze()
    app.run(host='0.0.0.0', port=5000)