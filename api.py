import os
import json
import time
import random
import string
import logging
import configparser
from typing import Dict, Any, List, Optional, Generator

# FastAPI related imports for building the REST API
# 导入FastAPI相关模块用于构建REST API
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx  # HTTP client for making API requests
from pydantic import BaseModel, Field  # For data validation and settings management

# Configure logging to output to both console and file
# 配置日志输出到控制台和文件
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('fitten_api.log', encoding='utf-8')]
)
logger = logging.getLogger('fitten-code-api')

# Data models for API requests and responses
# API请求和响应的数据模型

class Message(BaseModel):
    """Message model for chat completion
    聊天完成的消息模型"""
    role: str  # Role of the message (system, user, assistant) / 消息的角色（系统、用户、助手）
    content: str = ""  # Content of the message / 消息内容

class ChatCompletionRequest(BaseModel):
    """Chat completion request model
    聊天完成请求模型"""
    messages: List[Message]  # List of messages in the conversation / 对话中的消息列表
    model: Optional[str] = "fitten-code"  # Model to use for completion / 用于完成的模型
    stream: Optional[bool] = True  # Whether to stream the response / 是否流式返回响应

class ModelInfo(BaseModel):
    """Model information
    模型信息"""
    id: str  # Model ID / 模型ID
    name: str  # Model name / 模型名称

class ModelsResponse(BaseModel):
    """Response for models endpoint
    模型端点的响应"""
    models: List[ModelInfo]  # List of available models / 可用模型列表

# Security scheme for API key authentication
# API密钥认证的安全方案
security = HTTPBearer()

class FittenAuth:
    """Authentication manager for Fitten Code API
    Fitten Code API的认证管理器"""
    def __init__(self):
        """Initialize authentication attributes
        初始化认证属性"""
        self.username = ''  # Username for authentication / 用于认证的用户名
        self.password = ''  # Password for authentication / 用于认证的密码
        self.access_token = ''  # Access token for API calls / 用于API调用的访问令牌
        self.refresh_token = ''  # Refresh token for renewing access token / 用于更新访问令牌的刷新令牌
        self.user_id = ''  # User ID from authentication response / 来自认证响应的用户ID

    def load_credentials(self, config):
        """Load credentials from configuration
        从配置中加载凭证"""
        self.username = config.get('Main', 'username')  # Get username from config / 从配置中获取用户名
        self.password = config.get('Main', 'password')  # Get password from config / 从配置中获取密码
        if not self.username or not self.password:
            raise ValueError("Please set username and password in config.ini")  # Validate credentials / 验证凭证

    async def get_auth_token(self):
        """Get authentication token from Fitten Code API
        从Fitten Code API获取认证令牌"""
        login_url = 'https://fc.fittentech.com/codeuser/auth/login'  # Login API endpoint / 登录API端点
        login_data = {"username": self.username, "password": self.password}  # Login request data / 登录请求数据
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    login_url, 
                    json=login_data, 
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()  # Raise exception for HTTP errors / 对HTTP错误抛出异常
                data = response.json()  # Parse JSON response / 解析JSON响应
                self.access_token = data["access_token"]  # Store access token / 存储访问令牌
                self.refresh_token = data["refresh_token"]  # Store refresh token / 存储刷新令牌
                self.user_id = data["user_info"]["user_id"]  # Store user ID / 存储用户ID
                return True
        except Exception as e:
            logger.error(f"Failed to get token: {str(e)}")  # Log error / 记录错误
            return False

    async def refresh_auth_token(self):
        """Refresh the access token using refresh token
        使用刷新令牌更新访问令牌"""
        api_url = 'https://fc.fittentech.com/codeuser/auth/refresh_access_token'  # Refresh token API endpoint / 刷新令牌API端点
        for _ in range(2):  # Try twice / 尝试两次
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        api_url, 
                        headers={
                            "Authorization": f"Bearer {self.refresh_token}",
                            "Content-Type": "application/json"
                        }
                    )
                    if response.status_code == 200:  # If successful / 如果成功
                        data = response.json()  # Parse JSON response / 解析JSON响应
                        self.access_token = data["access_token"]  # Update access token / 更新访问令牌
                        return True
            except Exception as e:
                logger.error(f"Failed to refresh token: {str(e)}")  # Log error / 记录错误
        return await self.get_auth_token()  # Fall back to getting a new token / 回退到获取新令牌

class ConfigManager:
    """Configuration manager for Fitten Code API
    Fitten Code API的配置管理器"""
    def __init__(self, config_path='config.ini'):
        """Initialize configuration manager
        初始化配置管理器"""
        self.config_path = config_path  # Path to configuration file / 配置文件路径
        self.config = configparser.ConfigParser()  # Config parser / 配置解析器
        self.api_key = ''  # API key for authentication / 用于认证的API密钥
        self.auth = FittenAuth()  # Authentication manager / 认证管理器

    async def load_config(self):
        """Load configuration from file and initialize authentication
        从文件加载配置并初始化认证"""
        try:
            if not os.path.exists(self.config_path):  # Check if config file exists / 检查配置文件是否存在
                return False
            self.config.read(self.config_path, encoding='utf-8')  # Read config file / 读取配置文件
            self.api_key = self.config.get('Main', 'api_key')  # Get API key / 获取API密钥
            self.auth.load_credentials(self.config)  # Load credentials / 加载凭证
            return await self.auth.get_auth_token()  # Get authentication token / 获取认证令牌
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")  # Log error / 记录错误
            return False

class FittenAPI:
    """API client for Fitten Code service
    Fitten Code服务的API客户端"""
    def __init__(self, auth: FittenAuth):
        """Initialize API client
        初始化API客户端"""
        self.auth = auth  # Authentication manager / 认证管理器
        self.base_url = 'https://fc.fittentech.com/codeapi'  # Base URL for API / API的基础URL
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'  # User agent for requests / 请求的用户代理

    async def get_chat_response(self, full_conversation: str):
        """Send chat request to Fitten Code API and get response
        向Fitten Code API发送聊天请求并获取响应"""
        api_url = f'{self.base_url}/chat_auth?apikey={self.auth.user_id}'  # API endpoint with user ID / 带用户ID的API端点
        headers = {
            'Authorization': f'Bearer {self.auth.access_token}',  # Authorization header / 授权头
            'Content-Type': 'application/json',  # Content type / 内容类型
            'User-Agent': self.user_agent  # User agent / 用户代理
        }
        data = {
            "inputs": full_conversation,  # Conversation history / 对话历史
            "ft_token": self.auth.user_id  # User ID token / 用户ID令牌
        }
        try:
            async with httpx.AsyncClient() as client:
                return await client.post(api_url, headers=headers, json=data, timeout=None)  # Send request / 发送请求
        except Exception as e:
            logger.error(f"API request failed: {str(e)}")  # Log error / 记录错误
            raise

    async def process_stream_response(
        self,
        response: httpx.Response,
        req_id: str,
        model: str,
        prompt_tokens: int
    ) -> Generator[str, None, None]:
        """Process streaming response from Fitten Code API and yield formatted chunks
        处理来自Fitten Code API的流式响应并生成格式化的数据块"""
        generated_tokens = 0  # Counter for generated tokens / 生成的令牌计数器
        first_chunk = True  # Flag for first chunk processing / 第一个数据块处理的标志
        async for line in response.aiter_lines():  # Iterate through response lines / 遍历响应行
            if not line:  # Skip empty lines / 跳过空行
                continue
            try:  # Parse and process each line / 解析和处理每一行
                data = json.loads(line)  # Parse JSON data / 解析JSON数据
                if 'delta' in data:  # Check if data contains delta content / 检查数据是否包含增量内容
                    delta_content = data['delta']  # Get delta content / 获取增量内容
                    finish_reason = data.get('finish_reason')  # Get finish reason if exists / 获取完成原因（如果存在）
                    chunk = {  # Format chunk in OpenAI API format / 按OpenAI API格式构建数据块
                        "id": req_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [{
                            "delta": {},
                            "index": 0
                        }]
                    }
                    if first_chunk:  # Special handling for first chunk / 对第一个数据块的特殊处理
                        chunk["choices"][0]["delta"] = {
                            "role": "assistant",  # Set role for first chunk / 为第一个数据块设置角色
                            "content": delta_content  # Set content for first chunk / 为第一个数据块设置内容
                        }
                        first_chunk = False  # Reset first chunk flag / 重置第一个数据块标志
                    else:  # For subsequent chunks / 对于后续数据块
                        chunk["choices"][0]["delta"]["content"] = delta_content  # Only update content / 仅更新内容
                    chunk["choices"][0]["finish_reason"] = None  # Set finish reason to None for ongoing chunks / 为进行中的数据块设置完成原因为None
                    generated_tokens += len(delta_content)  # Count generated tokens / 计算生成的令牌数量
                    yield f"data: {json.dumps(chunk)}\n\n"  # Yield formatted chunk / 生成格式化的数据块
            except json.JSONDecodeError as e:  # Handle JSON parsing errors / 处理JSON解析错误
                logger.warning(f"JSON parsing failed: {str(e)}")  # Log warning / 记录警告
                continue  # Continue to next line / 继续处理下一行
            except Exception as e:  # Handle other exceptions / 处理其他异常
                logger.error(f"Error processing response: {str(e)}")  # Log error / 记录错误
                yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'internal_error'}})}\n\n"  # Yield error message / 生成错误消息
                return  # Stop processing / 停止处理
        # Create final chunk with completion information / 创建带有完成信息的最终数据块
        final_chunk = {
            "id": req_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "delta": {},
                "index": 0,
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": generated_tokens,
                "total_tokens": prompt_tokens + generated_tokens
            }
        }
        yield f"data: {json.dumps(final_chunk)}\n\n"  # Yield final chunk / 生成最终数据块
        yield "data: [DONE]\n\n"  # Signal completion / 发送完成信号

def generate_random_id(length=16):
    """Generate a random ID string of specified length
    生成指定长度的随机ID字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))  # Generate random string / 生成随机字符串

class FittenCodeAPI:
    """Main FastAPI application class for Fitten Code API
    Fitten Code API的主FastAPI应用类"""
    def __init__(self):
        """Initialize FastAPI application and configuration
        初始化FastAPI应用和配置"""
        self.app = FastAPI(title="Fitten Code API")  # Create FastAPI instance / 创建FastAPI实例
        self.config_manager = ConfigManager()  # Create config manager / 创建配置管理器
        self.fitten_api = None  # API client, initialized during startup / API客户端，在启动时初始化
        self.setup_routes()  # Setup API routes / 设置API路由

    def setup_routes(self):
        """Setup API routes and event handlers
        设置API路由和事件处理程序"""
        @self.app.on_event("startup")
        async def startup_event():
            """Startup event handler to load configuration and initialize API client
            启动事件处理程序，用于加载配置和初始化API客户端"""
            if not await self.config_manager.load_config():  # Load configuration / 加载配置
                logger.error("Failed to load configuration or authenticate")  # Log error / 记录错误
                return
            self.fitten_api = FittenAPI(self.config_manager.auth)  # Initialize API client / 初始化API客户端

        @self.app.get("/v1/models", response_model=ModelsResponse)
        async def get_models():
            """Get available models endpoint
            获取可用模型的端点"""
            return {"models": [{"id": "fitten-code", "name": "Fitten Code"}]}  # Return available models / 返回可用模型

        async def validate_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Validate API key from request
            验证请求中的API密钥"""
            if credentials.scheme != "Bearer" or credentials.credentials != self.config_manager.api_key:  # Check API key / 检查API密钥
                raise HTTPException(  # Raise HTTP exception for invalid API key / 对无效的API密钥抛出HTTP异常
                    status_code=401,  # Unauthorized status code / 未授权状态码
                    detail={  # Error details in OpenAI format / OpenAI格式的错误详情
                        "error": {
                            "message": "Invalid API key",  # Error message / 错误消息
                            "type": "invalid_request_error",  # Error type / 错误类型
                            "param": "Authorization",  # Parameter with error / 有错误的参数
                            "code": "invalid_api_key"  # Error code / 错误代码
                        }
                    }
                )
            return credentials.credentials  # Return validated credentials / 返回验证后的凭证

        @self.app.post("/v1/chat/completions")
        async def chat_completion(request: ChatCompletionRequest, api_key: str = Depends(validate_api_key)):
            """Chat completion endpoint compatible with OpenAI API format
            与OpenAI API格式兼容的聊天完成端点"""
            try:  # Process chat completion request / 处理聊天完成请求
                conversation = []  # Initialize conversation array / 初始化对话数组
                has_system_role = False  # Flag to track if system role exists / 标记是否存在系统角色
                for msg in request.messages:  # Process each message / 处理每条消息
                    if msg.role in ['system', 'user', 'assistant']:  # Check valid roles / 检查有效角色
                        conversation.append(f"<|{msg.role}|>\n{msg.content}\n<|end|>")  # Format message / 格式化消息
                        if msg.role == 'system':  # Check if system role / 检查是否为系统角色
                            has_system_role = True  # Set system role flag / 设置系统角色标志
                if not has_system_role:  # If no system role found / 如果没有找到系统角色
                    conversation.insert(0, "<|system|>\n<|end|>")  # Add empty system message / 添加空的系统消息
                if not any(msg.role == 'user' for msg in request.messages):  # Validate user input / 验证用户输入
                    raise ValueError("User input not found")  # Raise error if no user input / 如果没有用户输入则抛出错误
                full_conversation = '\n'.join(conversation) + '\n<|assistant|>'  # Format full conversation / 格式化完整对话

                async def generate():  # Generator function for streaming response / 用于流式响应的生成器函数
                    req_id = generate_random_id()  # Generate unique request ID / 生成唯一请求ID
                    max_retries = 2  # Maximum retry attempts / 最大重试次数
                    for _ in range(max_retries):  # Retry loop / 重试循环
                        try:  # Try to get chat response / 尝试获取聊天响应
                            response = await self.fitten_api.get_chat_response(full_conversation)  # Get response from API / 从API获取响应
                            if response.status_code == 200:  # If successful response / 如果响应成功
                                prompt_tokens = len(full_conversation)  # Calculate prompt tokens / 计算提示令牌数量
                                async for chunk in self.fitten_api.process_stream_response(  # Process streaming response / 处理流式响应
                                    response,  # API response / API响应
                                    req_id=req_id,  # Request ID / 请求ID
                                    model=request.model,  # Model name / 模型名称
                                    prompt_tokens=prompt_tokens  # Prompt token count / 提示令牌数量
                                ):
                                    yield chunk  # Yield each chunk / 生成每个数据块
                                return  # Exit after successful response / 成功响应后退出
                            elif response.status_code == 401:  # If unauthorized / 如果未授权
                                if await self.config_manager.auth.refresh_auth_token():  # Try to refresh token / 尝试刷新令牌
                                    continue  # Retry after token refresh / 令牌刷新后重试
                        except Exception as e:  # Handle request exceptions / 处理请求异常
                            logger.error(f"Request exception: {str(e)}")  # Log error / 记录错误
                            yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'server_error'}})}\n\n"  # Yield error message / 生成错误消息
                            return  # Stop processing / 停止处理
                    # If max retries reached / 如果达到最大重试次数
                    yield f"data: {json.dumps({'error': {'message': 'Max retries reached', 'type': 'server_error'}})}\n\n"  # Yield max retries error / 生成最大重试错误

                return StreamingResponse(generate(), media_type="text/event-stream")  # Return streaming response / 返回流式响应
            except Exception as e:  # Handle general exceptions / 处理一般异常
                logger.error(f"Error processing request: {str(e)}")  # Log error / 记录错误
                raise HTTPException(status_code=400, detail={"error": str(e)})  # Raise HTTP exception / 抛出HTTP异常

# Create application instance / 创建应用实例
app = FittenCodeAPI().app

# Run server if script is executed directly / 如果脚本直接执行则运行服务器
if __name__ == "__main__":
    import uvicorn  # Import uvicorn for ASGI server / 导入uvicorn作为ASGI服务器
    uvicorn.run("api:app", host="0.0.0.0", port=5000, reload=False)  # Run server on all interfaces port 5000 / 在所有接口的5000端口运行服务器