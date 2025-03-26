from flask import Flask, request, jsonify, Response as FlaskResponse
import requests
import json
import time
import random
import string
import configparser
import chardet
import logging
import os
from typing import Dict, Any, Generator, Optional, Tuple

# 配置日志
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fitten_api.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('fitten-code-api')

app = Flask(__name__)


class FittenAuth:
    """处理Fitten Code认证相关功能的类
    Class for handling Fitten Code authentication related functions"""
    
    def __init__(self):
        self.username = ''
        self.password = ''
        self.access_token = ''
        self.refresh_token = ''
        self.user_id = ''
        
    def load_credentials(self, config: configparser.ConfigParser) -> None:
        """从配置中加载凭证
        Load credentials from configuration"""
        self.username = config.get('Main', 'username')
        self.password = config.get('Main', 'password')
        
        if not self.username or not self.password:
            logger.error("Please set username and password in config.ini")
            raise ValueError("Please set username and password in config.ini")
            
    def get_auth_token(self) -> bool:
        """获取认证token
        Get authentication token"""
        login_url = 'https://fc.fittentech.com/codeuser/auth/login'
        login_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            response = requests.post(login_url, json=login_data, headers={
                "Content-Type": "application/json"
            })
            
            response.raise_for_status()
            data = response.json()
            
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.user_id = data["user_info"]["user_id"]
            
            logger.info(f"Authentication successful, user ID: {self.user_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get token: {str(e)}")
            if response and hasattr(response, 'text'):
                logger.error(f"Response content: {response.text}")
            return False
            
    def refresh_auth_token(self) -> bool:
        """刷新token
        Refresh authentication token"""
        api_url = 'https://fc.fittentech.com/codeuser/auth/refresh_access_token'
        
        try:
            response = requests.post(api_url, headers={
                "Authorization": f"Bearer {self.refresh_token}",
                "Content-Type": "application/json"
            })
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data["access_token"]
                self.refresh_token = data["refresh_token"]
                logger.info("Token refreshed")
                return True
            else:
                logger.warning(f"Failed to refresh token, attempting to login again, status code: {response.status_code}")
                return self.get_auth_token()
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh token: {str(e)}")
            return self.get_auth_token()


class ConfigManager:
    """配置管理类
    Configuration management class"""
    
    def __init__(self, config_path: str = 'config.ini'):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.api_key = ''
        self.auth = FittenAuth()
        
    def load_config(self) -> bool:
        """加载配置文件
        Load configuration file"""
        try:
            # 检测文件编码
            if not os.path.exists(self.config_path):
                logger.error(f"Configuration file does not exist: {self.config_path}")
                return False
                
            with open(self.config_path, 'rb') as f:
                encoding = chardet.detect(f.read())['encoding']
            
            self.config.read(self.config_path, encoding=encoding)
            
            # 加载API密钥
            self.api_key = self.config.get('Main', 'api_key')
            if not self.api_key:
                logger.warning("API key not set, client will not be able to access the API")
                
            # 加载认证信息
            self.auth.load_credentials(self.config)
            
            # 获取认证token
            if not self.auth.get_auth_token():
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            return False
    
class FittenAPI:
    """处理Fitten Code API请求的类
    Class for handling Fitten Code API requests"""
    
    def __init__(self, auth: FittenAuth):
        self.auth = auth
        self.base_url = 'https://fc.fittentech.com/codeapi'
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'
        
    def get_chat_response(self, user_input: str, system_prompt: str = '', assistant_last_response: str = '') -> requests.Response:
        """获取API响应（流式）
        Get API response (streaming)
        
        Args:
            user_input: 用户输入的文本 (User input text)
            system_prompt: 系统提示词 (System prompt)
            assistant_last_response: 助手上一次的回复 (Assistant's last response)
            
        Returns:
            requests.Response: 流式响应对象 (Streaming response object)
        """
        api_url = f'{self.base_url}/chat_auth?apikey={self.auth.user_id}'
        
        headers = {
            'Authorization': f'Bearer {self.auth.access_token}',
            'Content-Type': 'application/json',
            'User-Agent': self.user_agent
        }

        data = {
            "inputs": f"<|system|>\n{system_prompt}\n<|end|>\n<|user|>\n{user_input}\n<|end|>\n<|assistant|>\n{assistant_last_response}\n",
            "ft_token": self.auth.user_id,
        }

        try:
            return requests.post(api_url, headers=headers, json=data, stream=True)
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            raise
            
    def process_stream_response(self, response: requests.Response, req_id: str, model: str) -> Generator[str, None, None]:
        """处理流式响应
        Process streaming response
        
        Args:
            response: 流式响应对象 (Streaming response object)
            req_id: 请求ID (Request ID)
            model: 模型名称 (Model name)
            
        Yields:
            str: 格式化的响应行 (Formatted response line)
        """
        if response.status_code != 200:
            error_msg = "Unknown error"
            try:
                error_data = response.json()
                error_msg = error_data.get("detail", "Internal Server Error")
            except:
                if hasattr(response, 'text'):
                    error_msg = response.text
                    
            yield f"data: {json.dumps({'error': {'message': error_msg, 'type': 'api_error', 'code': 'api_error'}})}\n\n"
            return
            
        for line in response.iter_lines():
            if not line:
                continue
                
            try:
                data = json.loads(line.decode('utf-8'))
                if 'delta' in data:
                    finish_reason = data.get('finish_reason')
                    chunk = {
                        "id": req_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [{
                            "delta": {"content": data['delta']},
                            "index": 0,
                            "finish_reason": finish_reason
                        }]
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse response line: {str(e)}")
                continue
            except Exception as e:
                logger.error(f"Error processing response line: {str(e)}")
                yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'internal_error', 'code': 'internal_error'}})}\n\n"
                return
                
        yield "data: [DONE]\n\n"


def generate_random_id(length: int = 8) -> str:
    """生成随机ID
    Generate random ID
    
    Args:
        length: ID长度 (ID length)
        
    Returns:
        str: 随机生成的ID (Randomly generated ID)
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class APIRoutes:
    """API路由处理类
    API routes handling class"""
    
    def __init__(self, app: Flask, config_manager: ConfigManager, fitten_api: FittenAPI):
        self.app = app
        self.config_manager = config_manager
        self.fitten_api = fitten_api
        self.register_routes()
        
    def register_routes(self) -> None:
        """注册所有路由
        Register all routes"""
        self.app.route('/v1/models')(self.models)
        self.app.route('/v1/chat/completions', methods=['POST'])(self.chat_completion)
        
    def models(self):
        """获取可用模型列表
        Get available models list"""
        return jsonify({
            "models": [
                {"id": "fitten-code", "name": "Fitten Code"}
            ]
        })
        
    def validate_api_key(self) -> Tuple[bool, Optional[str]]:
        """验证API密钥
        Validate API key
        
        Returns:
            Tuple[bool, Optional[str]]: (是否有效, 错误消息) (Whether valid, error message)
        """
        api_key = request.headers.get('Authorization')
        if not api_key:
            return False, "API key not provided"
            
        if api_key != f'Bearer {self.config_manager.api_key}':
            return False, "Invalid API key"
            
        return True, None
        
    def parse_messages(self, data: Dict[str, Any]) -> Tuple[str, str, str, str]:
        """解析消息数据
        Parse message data
        
        Args:
            data: 请求数据 (Request data)
            
        Returns:
            Tuple[str, str, str, str]: (用户输入, 系统提示, 助手上一次回复, 模型名称) (User input, system prompt, assistant's last response, model name)
        """
        messages = data.get('messages', [])
        
        if not messages or not isinstance(messages, list):
            raise ValueError("Invalid message format")
            
        user_input = ''
        system_prompt = ''
        model = 'fitten-code'
        assistant_last_response = ''

        for message in messages:
            role = message.get('role')
            content = message.get('content', '')
            if role == 'user':
                user_input = content
            elif role == 'system':
                system_prompt = content
            elif role == 'assistant':
                assistant_last_response = content
            message_model = message.get('model')
            if message_model:
                model = message_model

        if not user_input:
            raise ValueError("User input not found")
            
        return user_input, system_prompt, assistant_last_response, model
        
    def chat_completion(self):
        """流式处理接口
        Streaming processing interface"""
        # 验证API密钥
        is_valid, error_msg = self.validate_api_key()
        if not is_valid:
            logger.warning(f"API key validation failed: {error_msg}")
            return jsonify({"error": error_msg}), 401
        
        # 解析请求数据
        try:
            data = request.json
            user_input, system_prompt, assistant_last_response, model = self.parse_messages(data)
        except ValueError as e:
            logger.warning(f"Failed to parse request data: {str(e)}")
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"Error processing request data: {str(e)}")
            return jsonify({
                "error": {
                    "message": "Internal server error",
                    "type": "internal_server_error",
                    "code": 500
                }
            }), 500
        def generate():
            req_id = generate_random_id()
            max_retries = 2
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    # 获取API响应
                    response = self.fitten_api.get_chat_response(
                        user_input, system_prompt, assistant_last_response
                    )
                    
                    # 处理响应状态码
                    if response.status_code == 200:
                        # 处理流式响应
                        yield from self.fitten_api.process_stream_response(response, req_id, model)
                        return
                    elif response.status_code == 401:
                        # 刷新token并重试
                        logger.info("Token expired, attempting to refresh")
                        if self.config_manager.auth.refresh_auth_token():
                            retry_count += 1
                        else:
                            yield f"data: {json.dumps({'error': {'message': 'Token refresh failed', 'type': 'server_error', 'code': 'token_refresh_error'}})}\n\n"
                            return
                    else:
                        # 处理其他错误
                        try:
                            error_data = response.json()
                            error_msg = error_data.get("detail", "Internal Server Error")
                        except:
                            error_msg = "Unknown error"
                            if hasattr(response, 'text'):
                                error_msg = response.text
                                
                        logger.error(f"API request failed: {error_msg}")
                        yield f"data: {json.dumps({'error': {'message': error_msg, 'type': 'api_error', 'code': 'api_error'}})}\n\n"
                        return
                        
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request exception: {str(e)}")
                    yield f"data: {json.dumps({'error': {'message': f'Request Exception: {str(e)}', 'type': 'server_error', 'code': 'request_error'}})}\n\n"
                    return
                except Exception as e:
                    logger.error(f"Error processing response: {str(e)}")
                    yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'internal_server_error', 'code': 'internal_server_error'}})}\n\n"
                    return
            
            logger.warning("Maximum retry count reached")
            yield f"data: {json.dumps({'error': {'message': 'Maximum retry count reached', 'type': 'server_error', 'code': 'max_retries_reached'}})}\n\n"
        return FlaskResponse(generate(), mimetype='text/event-stream')

class FittenCodeAPI:
    """Fitten Code API主应用类
    Fitten Code API main application class"""
    
    def __init__(self, config_path: str = 'config.ini'):
        self.app = Flask(__name__)
        self.config_manager = ConfigManager(config_path)
        self.fitten_api = None
        self.routes = None
        
    def initialize(self) -> bool:
        """初始化应用
        Initialize application
        
        Returns:
            bool: 初始化是否成功 (Whether initialization is successful)
        """
        try:
            # 加载配置
            if not self.config_manager.load_config():
                logger.error("Failed to load configuration, application cannot start")
                return False
                
            # 初始化API客户端
            self.fitten_api = FittenAPI(self.config_manager.auth)
            
            # 注册路由
            self.routes = APIRoutes(self.app, self.config_manager, self.fitten_api)
            
            logger.info("Application initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing application: {str(e)}")
            return False
            
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
        """运行应用
        Run application
        
        Args:
            host: 监听地址 (Listening address)
            port: 监听端口 (Listening port)
            debug: 是否启用调试模式 (Whether to enable debug mode)
        """
        if not self.initialize():
            logger.error("Application initialization failed, cannot start")
            return
            
        logger.info(f"Application started at http://{host}:{port}/")
        self.app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    api = FittenCodeAPI()
    api.run(port=5000)