# Fitten Code API Server

English | [简体中文](https://github.com/bobotechnology/fitten-code-api/blob/main/README_CN.md)

## Introduction
Fitten Code API Server is a Flask-based application that provides API service for Fitten Code. It acts as a middleware between clients and the Fitten Code service, offering a standardized API interface similar to OpenAI's API format. This server handles authentication, token management, and provides a clean interface for applications to interact with Fitten Code's capabilities.

## Features
- Configuration management through config.ini
- Automatic token management (login, refresh)
- OpenAI-like API endpoints
- Support for streaming chat completion
- Built-in error handling and token expiration management
- Logging system for debugging and monitoring
- Secure API key authentication
- Support for 128k context length

## Requirements
- Python 3.x
- Flask
- Requests
- chardet

## Installation
1. Clone this repository
   ```bash
   git clone https://github.com/bobotechnology/fitten-code-api.git
   cd fitten-code-api
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration
1. Create a `config.ini` file in the project root directory with the following content:
   ```ini
   [Main]
   username=your_fittentech_username
   password=your_fittentech_password
   api_key=your_custom_api_key
   ```

   Configuration parameters:
   - `username`: Your Fitten Code account username
   - `password`: Your Fitten Code account password
   - `api_key`: Custom API key for client authentication (you can create your own secure key)

## Usage
1. Start the server:
   ```bash
   python api.py
   ```
   The server will run on `http://localhost:5000` by default

2. API Endpoints:
   - `GET /v1/models`: List available models
   - `POST /v1/chat/completions`: Chat completion endpoint (supports streaming responses)

3. Example API calls:

   **Regular Request:**
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

   **Streaming Request:**
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
   print()  # Final newline
   ```

## Advanced Configuration

The server creates a log file `fitten_api.log` in the project directory that contains detailed information about server operations, API requests, and errors. This can be useful for debugging.

## Error Handling

The API server handles various error scenarios:
- Invalid API key authentication
- Token expiration and automatic refresh
- API request failures
- Rate limiting and server errors

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/bobotechnology/fitten-code-api/blob/main/LICENSE.md) file for details.