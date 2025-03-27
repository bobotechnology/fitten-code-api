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

# 配置日志记录
# Configure logging
logging.basicConfig(
    level=logging.INFO,  # 设置日志级别为INFO / Set log level to INFO
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # 设置日志格式 / Set log format
    handlers=[
        logging.StreamHandler(),  # 输出到控制台 / Output to console
        logging.FileHandler('fitten_api.log', encoding='utf-8')  # 输出到文件 / Output to file
    ]
)
logger = logging.getLogger('fitten-code-api')  # 创建日志记录器 / Create logger
app = Flask(__name__)  # 创建Flask应用实例 / Create Flask application instance

class FittenAuth:
    """
    处理Fitten Code的身份验证，包括登录、获取和刷新令牌
    Handles authentication for Fitten Code, including login, token acquisition and refresh
    """
    def __init__(self):
        """
        初始化FittenAuth对象
        Initialize FittenAuth object
        """
        self.username = ''  # Fitten Code用户名 / Fitten Code username
        self.password = ''  # Fitten Code密码 / Fitten Code password
        self.access_token = ''  # 访问令牌 / Access token
        self.refresh_token = ''  # 刷新令牌 / Refresh token
        self.user_id = ''  # 用户ID / User ID

    def load_credentials(self, config: configparser.ConfigParser) -> None:
        """
        从配置文件加载凭据
        Load credentials from configuration file
        
        参数 / Args:
            config: 配置解析器对象 / Configuration parser object
            
        抛出 / Raises:
            ValueError: 如果用户名或密码未设置 / If username or password is not set
        """
        self.username = config.get('Main', 'username')
        self.password = config.get('Main', 'password')
        if not self.username or not self.password:
            logger.error("Please set username and password in config.ini")
            raise ValueError("Please set username and password in config.ini")

    def get_auth_token(self) -> bool:
        """
        获取Fitten Code的认证令牌
        Get authentication token for Fitten Code
        
        返回 / Returns:
            bool: 如果成功获取令牌则为True，否则为False / True if token was successfully obtained, False otherwise
        """
        login_url = 'https://fc.fittentech.com/codeuser/auth/login'  # 登录URL / Login URL
        login_data = {
            "username": self.username,  # 用户名 / Username
            "password": self.password  # 密码 / Password
        }
        try:
            # 发送登录请求 / Send login request
            response = requests.post(login_url, json=login_data, headers={
                "Content-Type": "application/json"
            })
            response.raise_for_status()  # 如果响应状态码不是200，则抛出异常 / Raise exception if response status code is not 200
            data = response.json()  # 解析JSON响应 / Parse JSON response
            # 保存令牌和用户ID / Save tokens and user ID
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.user_id = data["user_info"]["user_id"]
            logger.info(f"Authentication successful, user ID: {self.user_id}")
            return True
        except requests.exceptions.RequestException as e:
            # 处理请求异常 / Handle request exceptions
            logger.error(f"Failed to get token: {str(e)}")
            if response and hasattr(response, 'text'):
                logger.error(f"Response content: {response.text}")
            return False

    def refresh_auth_token(self) -> bool:
        """
        刷新认证令牌
        Refresh authentication token
        
        返回 / Returns:
            bool: 如果成功刷新令牌则为True，否则为False / True if token was successfully refreshed, False otherwise
        """
        api_url = 'https://fc.fittentech.com/codeuser/auth/refresh_access_token'  # 刷新令牌的API URL / API URL for token refresh
        max_retries = 2  # 最大重试次数 / Maximum retry count
        for _ in range(max_retries):
            try:
                # 发送刷新令牌请求 / Send token refresh request
                response = requests.post(api_url, headers={
                    "Authorization": f"Bearer {self.refresh_token}",  # 使用刷新令牌进行认证 / Authenticate using refresh token
                    "Content-Type": "application/json"
                })
                if response.status_code == 200:
                    data = response.json()  # 解析JSON响应 / Parse JSON response
                    # 更新令牌 / Update tokens
                    self.access_token = data["access_token"]
                    self.refresh_token = data["refresh_token"]
                    logger.info("Token refreshed")
                    return True
                else:
                    logger.warning(f"Failed to refresh token, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                # 处理请求异常 / Handle request exceptions
                logger.error(f"Failed to refresh token: {str(e)}")
        # 如果刷新失败，尝试重新登录 / If refresh fails, try to login again
        return self.get_auth_token()

class ConfigManager:
    """
    配置管理器，负责加载配置文件和初始化认证
    Configuration manager responsible for loading config file and initializing authentication
    """
    def __init__(self, config_path: str = 'config.ini'):
        """
        初始化配置管理器
        Initialize configuration manager
        
        参数 / Args:
            config_path: 配置文件路径 / Configuration file path
        """
        self.config_path = config_path  # 配置文件路径 / Configuration file path
        self.config = configparser.ConfigParser()  # 配置解析器 / Configuration parser
        self.api_key = ''  # API密钥 / API key
        self.auth = FittenAuth()  # 认证对象 / Authentication object

    def load_config(self) -> bool:
        """
        加载配置文件并初始化认证
        Load configuration file and initialize authentication
        
        返回 / Returns:
            bool: 如果成功加载配置并认证则为True，否则为False / True if configuration was successfully loaded and authenticated, False otherwise
        """
        try:
            # 检查配置文件是否存在 / Check if configuration file exists
            if not os.path.exists(self.config_path):
                logger.error(f"Configuration file does not exist: {self.config_path}")
                return False
            # 读取配置文件 / Read configuration file
            self.config.read(self.config_path, encoding='utf-8')
            # 获取API密钥 / Get API key
            self.api_key = self.config.get('Main', 'api_key')
            # 加载认证凭据 / Load authentication credentials
            self.auth.load_credentials(self.config)
            # 获取认证令牌 / Get authentication token
            if not self.auth.get_auth_token():
                return False
            return True
        except Exception as e:
            # 处理异常 / Handle exceptions
            logger.error(f"Failed to load configuration: {str(e)}")
            return False

class FittenAPI:
    """
    Fitten API客户端，负责与Fitten Code API进行通信
    Fitten API client responsible for communicating with Fitten Code API
    """
    def __init__(self, auth: FittenAuth):
        """
        初始化Fitten API客户端
        Initialize Fitten API client
        
        参数 / Args:
            auth: 认证对象 / Authentication object
        """
        self.auth = auth  # 认证对象 / Authentication object
        self.base_url = 'https://fc.fittentech.com/codeapi'  # API基础URL / API base URL
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'  # 用户代理 / User agent

    def get_chat_response(self, full_conversation: str) -> requests.Response:
        """
        向Fitten Code API发送聊天请求
        Send chat request to Fitten Code API
        
        参数 / Args:
            full_conversation: 完整的对话内容 / Full conversation content
            
        返回 / Returns:
            requests.Response: API响应对象 / API response object
            
        抛出 / Raises:
            requests.exceptions.RequestException: 如果API请求失败 / If API request fails
        """
        api_url = f'{self.base_url}/chat_auth?apikey={self.auth.user_id}'  # API URL
        headers = {
            'Authorization': f'Bearer {self.auth.access_token}',  # 认证头 / Authorization header
            'Content-Type': 'application/json',  # 内容类型 / Content type
            'User-Agent': self.user_agent  # 用户代理 / User agent
        }
        data = {
            "inputs": full_conversation,  # 对话内容 / Conversation content
            "ft_token": self.auth.user_id  # 用户ID / User ID
        }
        try:
            # 发送POST请求，启用流式响应 / Send POST request with streaming enabled
            return requests.post(api_url, headers=headers, json=data, stream=True)
        except requests.exceptions.RequestException as e:
            # 记录错误并重新抛出异常 / Log error and re-raise exception
            logger.error(f"API request failed: {str(e)}")
            raise

    def process_stream_response(
        self,
        response: requests.Response,
        req_id: str,
        model: str
    ) -> Generator[str, None, None]:
        """
        处理流式响应并转换为OpenAI兼容格式
        Process streaming response and convert to OpenAI compatible format
        
        参数 / Args:
            response: API响应对象 / API response object
            req_id: 请求ID / Request ID
            model: 模型名称 / Model name
            
        返回 / Returns:
            Generator[str, None, None]: 生成OpenAI兼容的响应块 / Generator yielding OpenAI compatible response chunks
        """
        # 检查响应状态码 / Check response status code
        if response.status_code != 200:
            error_msg = "Unknown error"
            try:
                # 尝试解析错误信息 / Try to parse error message
                error_data = response.json()
                error_msg = error_data.get("detail", "Internal Server Error")
            except:
                # 如果无法解析JSON，使用原始响应文本 / If JSON parsing fails, use raw response text
                if hasattr(response, 'text'):
                    error_msg = response.text
            # 生成错误响应 / Generate error response
            yield f"data: {json.dumps({'error': {'message': error_msg, 'type': 'api_error', 'code': 'api_error'}})}\n\n"
            return
        # 处理响应行 / Process response lines
        for line in response.iter_lines():
            if not line:
                continue
            try:
                # 解析JSON响应 / Parse JSON response
                data = json.loads(line.decode('utf-8'))
                if 'delta' in data:
                    # 获取完成原因 / Get finish reason
                    finish_reason = data.get('finish_reason')
                    # 创建OpenAI兼容的响应块 / Create OpenAI compatible response chunk
                    chunk = {
                        "id": req_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [{
                            "delta": {"content": data['delta']},
                            "index": 0,
                            "finish_reason": None if finish_reason is None else finish_reason
                        }]
                    }
                    # 生成响应块 / Yield response chunk
                    yield f"data: {json.dumps(chunk)}\n\n"
            except json.JSONDecodeError as e:
                # 记录JSON解析错误 / Log JSON parsing error
                logger.warning(f"Failed to parse response line: {str(e)}")
                continue
            except Exception as e:
                # 记录其他错误并生成错误响应 / Log other errors and generate error response
                logger.error(f"Error processing response line: {str(e)}")
                yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'internal_error', 'code': 'internal_error'}})}\n\n"
                return
        # 生成完成响应 / Generate completion response
        yield "data: [DONE]\n\n"

def generate_random_id(length: int = 16) -> str:
    """
    生成指定长度的随机ID，用于请求标识
    Generate a random ID of specified length for request identification
    
    参数 / Args:
        length: ID的长度 / Length of the ID
        
    返回 / Returns:
        str: 生成的随机ID，包含字母和数字 / Generated random ID containing letters and digits
    """
    # 使用字母和数字生成随机ID / Generate random ID using letters and digits
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class APIRoutes:
    """
    API路由管理器，负责注册和处理API路由
    API routes manager responsible for registering and handling API routes
    """
    def __init__(self, app: Flask, config_manager: ConfigManager, fitten_api: FittenAPI):
        """
        初始化API路由管理器
        Initialize API routes manager
        
        参数 / Args:
            app: Flask应用实例 / Flask application instance
            config_manager: 配置管理器 / Configuration manager
            fitten_api: Fitten API客户端 / Fitten API client
        """
        self.app = app  # Flask应用实例 / Flask application instance
        self.config_manager = config_manager  # 配置管理器 / Configuration manager
        self.fitten_api = fitten_api  # Fitten API客户端 / Fitten API client
        self.register_routes()  # 注册路由 / Register routes

    def register_routes(self) -> None:
        """
        注册API路由
        Register API routes
        """
        self.app.route('/v1/models')(self.models)  # 注册模型列表路由 / Register models list route
        self.app.route('/v1/chat/completions', methods=['POST'])(self.chat_completion)  # 注册聊天补全路由 / Register chat completion route

    def models(self):
        """
        获取可用模型列表
        Get available models list
        
        返回 / Returns:
            Flask.Response: 包含模型列表的JSON响应 / JSON response containing models list
        """
        return jsonify({
            "models": [
                {"id": "fitten-code", "name": "Fitten Code"}  # Fitten Code模型 / Fitten Code model
            ]
        })

    def validate_api_key(self) -> Tuple[bool, Optional[str]]:
        """
        验证API密钥是否有效
        Validate if the API key is valid
        
        返回 / Returns:
            Tuple[bool, Optional[str]]: 包含验证结果和错误消息的元组 / Tuple containing validation result and error message
                - 第一个元素为True表示验证成功，False表示验证失败 / First element is True if validation succeeded, False if failed
                - 第二个元素为None表示没有错误，否则包含错误消息 / Second element is None if no error, otherwise contains error message
        """
        # 从请求头获取API密钥 / Get API key from request headers
        api_key = request.headers.get('Authorization')
        # 检查API密钥是否存在 / Check if API key exists
        if not api_key:
            return False, "API key not provided"
        # 验证API密钥是否正确 / Validate if API key is correct
        if api_key != f'Bearer {self.config_manager.api_key}':
            return False, "Invalid API key"
        # 验证成功 / Validation successful
        return True, None

    def parse_messages(self, data: Dict[str, Any]) -> Tuple[str, str, str, str]:
        """
        解析OpenAI格式的消息并转换为Fitten Code格式
        Parse OpenAI format messages and convert to Fitten Code format
        
        参数 / Args:
            data: 包含消息数组的请求数据 / Request data containing messages array
            
        返回 / Returns:
            Tuple[str, str, str, str]: 包含以下元素的元组 / Tuple containing the following elements:
                - 完整的对话内容 / Full conversation content
                - 系统提示内容 / System prompt content
                - 助手最后的回复 / Assistant's last response
                - 使用的模型名称 / Model name used
                
        抛出 / Raises:
            ValueError: 如果消息格式无效或未找到用户输入 / If message format is invalid or user input not found
        """
        # 获取消息数组 / Get messages array
        messages = data.get('messages', [])
        # 验证消息格式 / Validate message format
        if not messages or not isinstance(messages, list):
            raise ValueError("Invalid message format")
        # 默认使用fitten-code模型 / Default to fitten-code model
        model = 'fitten-code'
        # 初始化对话数组和其他变量 / Initialize conversation array and other variables
        conversation = []
        system_prompt = ""
        assistant_last_response = ""
        has_system_role = False
        
        # 处理每条消息 / Process each message
        for message in messages:
            role = message.get('role')  # 获取角色 / Get role
            content = message.get('content', '')  # 获取内容 / Get content
            message_model = message.get('model')  # 获取模型 / Get model
            # 如果消息指定了模型，则使用该模型 / If message specifies a model, use it
            if message_model:
                model = message_model
            # 处理系统、用户和助手角色的消息 / Process messages with system, user, and assistant roles
            if role in ['system', 'user', 'assistant']:
                # 添加格式化的消息到对话数组 / Add formatted message to conversation array
                conversation.append(f"<|{role}|>\n{content}\n<|end|>")
                # 保存系统提示和助手最后回复 / Save system prompt and assistant's last response
                if role == 'system':
                    system_prompt = content
                    has_system_role = True
                elif role == 'assistant':
                    assistant_last_response = content
        
        # 如果没有系统角色消息，添加一个空的系统消息 / If no system role message, add an empty one
        if not has_system_role:
            conversation.insert(0, "<|system|>\n\n<|end|>")
        # 验证是否存在用户输入 / Validate if user input exists
        if not any(msg.get('role') == 'user' for msg in messages):
            raise ValueError("User input not found")
        # 构建完整对话并添加助手标记 / Build full conversation and add assistant marker
        full_conversation = '\n'.join(conversation) + '\n<|assistant|>\n'
        return full_conversation, system_prompt, assistant_last_response, model

    def chat_completion(self):
        """
        处理聊天补全请求，将OpenAI格式的请求转换为Fitten Code格式并返回流式响应
        Handle chat completion request, convert OpenAI format request to Fitten Code format and return streaming response
        
        返回 / Returns:
            Flask.Response: 流式事件响应 / Streaming event response
        """
        # 验证API密钥 / Validate API key
        is_valid, error_msg = self.validate_api_key()
        if not is_valid:
            logger.warning(f"API key validation failed: {error_msg}")
            return jsonify({"error": error_msg}), 401

        try:
            # 解析请求数据 / Parse request data
            data = request.json
            # 解析消息并转换格式 / Parse messages and convert format
            full_conversation, system_prompt, assistant_last_response, model = self.parse_messages(data)
        except ValueError as e:
            # 处理值错误异常 / Handle value error exceptions
            logger.warning(f"Failed to parse request data: {str(e)}")
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            # 处理其他异常 / Handle other exceptions
            logger.error(f"Error processing request data: {str(e)}")
            return jsonify({
                "error": {
                    "message": "Internal server error",
                    "type": "internal_server_error",
                    "code": 500
                }
            }), 500

        def generate():
            """
            生成流式响应的内部函数
            Internal function to generate streaming response
            
            返回 / Returns:
                Generator: 生成流式响应块 / Generator yielding streaming response chunks
            """
            # 生成请求ID / Generate request ID
            req_id = generate_random_id()
            # 设置最大重试次数 / Set maximum retry count
            max_retries = 2
            retry_count = 0
            # 尝试获取响应，最多重试指定次数 / Try to get response, retry up to specified times
            while retry_count < max_retries:
                try:
                    # 发送聊天请求 / Send chat request
                    response = self.fitten_api.get_chat_response(full_conversation)
                    # 处理成功响应 / Handle successful response
                    if response.status_code == 200:
                        # 处理流式响应并生成响应块 / Process streaming response and yield response chunks
                        for chunk in self.fitten_api.process_stream_response(
                            response, req_id=req_id, model=model
                        ):
                            yield chunk
                        return
                    # 处理认证失败 / Handle authentication failure
                    elif response.status_code == 401:
                        # 尝试刷新令牌 / Try to refresh token
                        if self.config_manager.auth.refresh_auth_token():
                            retry_count += 1
                        else:
                            # 令牌刷新失败 / Token refresh failed
                            yield f"data: {json.dumps({'error': {'message': 'Token refresh failed', 'type': 'server_error', 'code': 'token_refresh_error'}})}\n"
                            return
                    # 处理其他错误 / Handle other errors
                    else:
                        # 获取错误消息 / Get error message
                        error_msg = response.text if hasattr(response, 'text') else "Unknown error"
                        # 生成错误响应 / Generate error response
                        yield f"data: {json.dumps({'error': {'message': error_msg, 'type': 'api_error', 'code': 'api_error'}})}\n"
                        return
                # 处理请求异常 / Handle request exceptions
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request exception: {str(e)}")
                    # 生成请求错误响应 / Generate request error response
                    yield f"data: {json.dumps({'error': {'message': f'Request Exception: {str(e)}', 'type': 'server_error', 'code': 'request_error'}})}\n"
                    return
                # 处理其他异常 / Handle other exceptions
                except Exception as e:
                    logger.error(f"Error processing response: {str(e)}")
                    # 生成内部服务器错误响应 / Generate internal server error response
                    yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'internal_server_error', 'code': 'internal_server_error'}})}\n"
                    return
            # 达到最大重试次数 / Maximum retry count reached
            yield f"data: {json.dumps({'error': {'message': 'Maximum retry count reached', 'type': 'server_error', 'code': 'max_retries_reached'}})}\n"

        # 返回流式响应 / Return streaming response
        return FlaskResponse(generate(), mimetype='text/event-stream')

class FittenCodeAPI:
    """
    Fitten Code API服务器的主类，负责初始化和运行API服务
    Main class for Fitten Code API server, responsible for initializing and running the API service
    """
    def __init__(self, config_path: str = 'config.ini'):
        """
        初始化FittenCodeAPI对象
        Initialize FittenCodeAPI object
        
        参数 / Args:
            config_path: 配置文件路径 / Configuration file path
        """
        self.app = Flask(__name__)  # Flask应用实例 / Flask application instance
        self.config_manager = ConfigManager(config_path)  # 配置管理器 / Configuration manager
        self.fitten_api = None  # Fitten API客户端 / Fitten API client
        self.routes = None  # API路由管理器 / API routes manager

    def initialize(self) -> bool:
        """
        初始化API服务，加载配置并设置路由
        Initialize API service, load configuration and set up routes
        
        返回 / Returns:
            bool: 如果初始化成功则为True，否则为False / True if initialization was successful, False otherwise
        """
        try:
            # 加载配置 / Load configuration
            if not self.config_manager.load_config():
                logger.error("Failed to load configuration, application cannot start")
                return False
            # 创建API客户端 / Create API client
            self.fitten_api = FittenAPI(self.config_manager.auth)
            # 设置路由 / Set up routes
            self.routes = APIRoutes(self.app, self.config_manager, self.fitten_api)
            logger.info("Application initialized successfully")
            return True
        except Exception as e:
            # 记录初始化错误 / Log initialization error
            logger.error(f"Error initializing application: {str(e)}")
            return False

    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
        """
        运行API服务器
        Run the API server
        
        参数 / Args:
            host: 服务器主机地址 / Server host address
            port: 服务器端口 / Server port
            debug: 是否启用调试模式 / Whether to enable debug mode
        """
        # 初始化应用 / Initialize application
        if not self.initialize():
            logger.error("Application initialization failed, cannot start")
            return
        # 记录启动信息 / Log startup information
        logger.info(f"Application started at http://{host}:{port}/")
        # 启动Flask应用 / Start Flask application
        self.app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    api = FittenCodeAPI()
    api.run(port=5000)