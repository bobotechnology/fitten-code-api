# Fitten Code API Server

English | [简体中文](https://github.com/bobotechnology/fitten-code-api/blob/main/README_CN.md)

### Introduction
Fitten Code API Server is a Flask-based application that provides API service for Fitten Code. It acts as a middleware between clients and the Fitten Code service, offering a standardized API interface similar to OpenAI's API format.

### Features
- Configuration management through config.ini
- Automatic token management (login, refresh)
- OpenAI-like API endpoints
- Support for chat completion
- Built-in error handling and token expiration management

### Requirements
- Python 3.x
- Flask
- Requests
- Other dependencies (see requirements.txt)

### Installation
1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration
1. Copy or rename `config.ini` and fill in your credentials:
   ```ini
   [Main]
   username=your_fittentech_username
   password=your_fittentech_password
   api_key=your_custom_api_key
   ```
   - `username`: Your Fitten Code account username
   - `password`: Your Fitten Code account password
   - `api_key`: Custom API key for client authentication

### Usage
1. Start the server:
   ```bash
   python api.py
   ```
   The server will run on `http://localhost:5000`

2. API Endpoints:
   - GET `/v1/models`: List available models
   - POST `/v1/chat/completions`: Chat completion endpoint

3. Example API call:
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

### License
This project is licensed under the MIT License - see the LICENSE.md file for details.