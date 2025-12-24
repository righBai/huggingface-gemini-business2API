import json, time, hmac, hashlib, base64, os, asyncio, uuid, ssl, re
from datetime import datetime
from typing import List, Optional, Union, Dict, Any
import logging
import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel

# ---------- 日志配置 ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gemini")

# ---------- 默认配置 (环境变量作为后备) ----------
ENV_SECURE_C_SES = os.getenv("SECURE_C_SES")
ENV_HOST_C_OSES  = os.getenv("HOST_C_OSES")
ENV_CSESIDX      = os.getenv("CSESIDX") 
ENV_CONFIG_ID    = os.getenv("CONFIG_ID")
PROXY            = os.getenv("PROXY") or None
TIMEOUT_SECONDS  = 600 

# ---------- 模型映射配置 ----------
MODEL_MAPPING = {
    "gemini-auto": None,
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-3-pro-preview": "gemini-3-pro-preview"
}

# ---------- 全局 Session 缓存 ----------
SESSION_CACHE: Dict[str, dict] = {}

# ---------- HTTP 客户端 ----------
http_client = httpx.AsyncClient(
    proxies=PROXY,
    verify=False,
    http2=False,
    timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=60.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
)

security = HTTPBearer()

# ---------- 凭证管理类 ----------
class UserCredentials:
    def __init__(self, config_id, secure_c_ses, host_c_oses, csesidx):
        self.config_id = config_id
        self.secure_c_ses = secure_c_ses
        self.host_c_oses = host_c_oses
        self.csesidx = csesidx

def parse_credentials(auth: HTTPAuthorizationCredentials = Depends(security)) -> UserCredentials:
    """
    解析 API Key。
    支持格式：
    1. CONFIG_ID#SECURE_C_SES#HOST_C_OSES#CSESIDX (推荐：全动态)
    2. CONFIG_ID#SECURE_C_SES#HOST_C_OSES (使用环境变量 CSESIDX)
    3. CONFIG_ID (使用全部环境变量)
    """
    token = auth.credentials
    parts = token.split("#")
    
    if len(parts) >= 4:
        # 格式: CONFIG_ID#SECURE_C_SES#HOST_C_OSES#CSESIDX
        return UserCredentials(parts[0], parts[1], parts[2], parts[3])
    elif len(parts) == 3:
        # 格式: CONFIG_ID#SECURE_C_SES#HOST_C_OSES (回退环境变量 CSESIDX)
        if not ENV_CSESIDX:
             logger.warning("Warning: Key missing CSESIDX and env CSESIDX is empty.")
        return UserCredentials(parts[0], parts[1], parts[2], ENV_CSESIDX or "")
    else:
        # 格式: CONFIG_ID (全部回退环境变量)
        if not (ENV_SECURE_C_SES and ENV_CSESIDX):
            raise HTTPException(401, "Server env missing cookies/csesidx, please provide in API Key")
        return UserCredentials(token, ENV_SECURE_C_SES, ENV_HOST_C_OSES, ENV_CSESIDX)

# ---------- 工具函数 ----------
def get_common_headers(jwt: str) -> dict:
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "x-server-timeout": "1800",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }

def urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def kq_encode(s: str) -> str:
    b = bytearray()
    for ch in s:
        v = ord(ch)
        if v > 255:
            b.append(v & 255)
            b.append(v >> 8)
        else:
            b.append(v)
    return urlsafe_b64encode(bytes(b))

def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
    payload = {
        "iss": "https://business.gemini.google",
        "aud": "https://biz-discoveryengine.googleapis.com",
        "sub": f"csesidx/{csesidx}",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }
    # 驼峰命名，防止 markdown 转义导致的 SyntaxError
    headerBase64  = kq_encode(json.dumps(header, separators=(",", ":")))
    payloadBase64 = kq_encode(json.dumps(payload, separators=(",", ":")))
    message       = f"{headerBase64}.{payloadBase64}"
    
    sig = hmac.new(key_bytes, message.encode(), hashlib.sha256).digest()
    return f"{message}.{urlsafe_b64encode(sig)}"

# ---------- JWT 管理 (使用 creds.csesidx) ----------
async def fetch_jwt(creds: UserCredentials) -> str:
    cookie = f"__Secure-C_SES={creds.secure_c_ses}"
    if creds.host_c_oses:
        cookie += f"; __Host-C_OSES={creds.host_c_oses}"
    
    # 使用传入的 csesidx
    r = await http_client.get(
        "https://business.gemini.google/auth/getoxsrf",
        params={"csesidx": creds.csesidx}, 
        headers={
            "cookie": cookie,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            "referer": "https://business.gemini.google/"
        },
    )
    if r.status_code != 200:
        logger.error(f"❌ getoxsrf 失败: {r.status_code} {r.text[:100]}")
        raise HTTPException(401, "Cookie expired or invalid")
    
    txt = r.text[4:] if r.text.startswith(")]}'") else r.text
    data = json.loads(txt)
    key_bytes = base64.urlsafe_b64decode(data["xsrfToken"] + "==")
    
    # 传递 csesidx 给 create_jwt
    return create_jwt(key_bytes, data["keyId"], creds.csesidx)

# ---------- Session & File 管理 ----------
async def create_google_session(creds: UserCredentials) -> str:
    jwt = await fetch_jwt(creds)
    headers = get_common_headers(jwt)
    body = {
        "configId": creds.config_id,
        "additionalParams": {"token": "-"},
        "createSessionRequest": {
            "session": {"name": "", "displayName": ""}
        }
    }
    
    logger.debug("🌐 申请新 Session...")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession",
        headers=headers,
        json=body,
    )
    if r.status_code != 200:
        logger.error(f"❌ createSession 失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, "createSession failed")
    sess_name = r.json()["session"]["name"]
    return sess_name

async def upload_context_file(creds: UserCredentials, session_name: str, mime_type: str, base64_content: str) -> str:
    jwt = await fetch_jwt(creds)
    headers = get_common_headers(jwt)
    
    ext = mime_type.split('/')[-1] if '/' in mime_type else "bin"
    fileName = f"upload_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"
    body = {
        "configId": creds.config_id,
        "additionalParams": {"token": "-"},
        "addContextFileRequest": {
            "name": session_name,
            "fileName": fileName,
            "mimeType": mime_type,
            "fileContents": base64_content
        }
    }
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile",
        headers=headers,
        json=body,
    )
    if r.status_code != 200:
        logger.error(f"❌ 上传文件失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, f"Upload failed: {r.text}")
    
    data = r.json()
    return data.get("addContextFileResponse", {}).get("fileId")

# ---------- 消息处理逻辑 ----------
def get_conversation_key(messages: List[dict]) -> str:
    if not messages: return "empty"
    first_msg = messages[0].copy()
    if isinstance(first_msg.get("content"), list):
        text_part = "".join([x["text"] for x in first_msg["content"] if x["type"] == "text"])
        first_msg["content"] = text_part
    key_str = json.dumps(first_msg, sort_keys=True)
    return hashlib.md5(key_str.encode()).hexdigest()

def parse_last_message(messages: List[Dict]):
    if not messages: return "", []
    last_msg = messages[-1]
    content = last_msg.content
    text_content = ""
    images = []
    if isinstance(content, str):
        text_content = content
    elif isinstance(content, list):
        for part in content:
            if part.get("type") == "text":
                text_content += part.get("text", "")
            elif part.get("type") == "image_url":
                url = part.get("image_url", {}).get("url", "")
                match = re.match(r"data:(image/[^;]+);base64,(.+)", url)
                if match:
                    images.append({"mime": match.group(1), "data": match.group(2)})
    return text_content, images

def build_full_context_text(messages: List[Dict]) -> str:
    prompt = ""
    for msg in messages:
        role = "User" if msg.role in ["user", "system"] else "Assistant"
        contentStr = ""
        if isinstance(msg.content, str):
            contentStr = msg.content
        elif isinstance(msg.content, list):
            for part in msg.content:
                if part.get("type") == "text":
                    contentStr += part.get("text", "")
                elif part.get("type") == "image_url":
                    contentStr += "[图片]"
        prompt += f"{role}: {contentStr}\n\n"
    return prompt

# ---------- OpenAI 兼容接口 ----------
app = FastAPI(title="Gemini-Business OpenAI Gateway")

class Message(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]

class ChatRequest(BaseModel):
    model: str = "gemini-auto"
    messages: List[Message]
    stream: bool = False
    temperature: Optional[float] = 0.7
    top_p: Optional[float] = 1.0

def create_chunk(id: str, created: int, model: str, delta: dict, finish_reason: Union[str, None]) -> str:
    chunk = {
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}]
    }
    return json.dumps(chunk)

# [新增] 首页路由，防止访问域名报错 Not Found
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head>
            <title>Gemini Business API</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; }
                .container { text-align: center; padding: 2rem; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                h1 { color: #1a73e8; }
                code { background: #eee; padding: 0.2rem 0.4rem; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Gemini Business API is Running! 🚀</h1>
                <p>Status: <b>Active</b></p>
                <p>Chat Endpoint: <code>/v1/chat/completions</code></p>
                <p>Models Endpoint: <code>/v1/models</code></p>
            </div>
        </body>
    </html>
    """

@app.get("/v1/models")
async def list_models():
    models = []
    for model_id in MODEL_MAPPING.keys():
        models.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google"
        })
    return {"object": "list", "data": models}

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest, creds: UserCredentials = Depends(parse_credentials)):
    if req.model not in MODEL_MAPPING:
        raise HTTPException(status_code=404, detail=f"Model '{req.model}' not found.")
    lastText, currentImages = parse_last_message(req.messages)
    convKey = get_conversation_key([m.dict() for m in req.messages])
    cached = SESSION_CACHE.get(convKey)
    
    if cached:
        googleSession = cached["session_id"]
        textToSend = lastText
        SESSION_CACHE[convKey]["updated_at"] = time.time()
        isRetryMode = False
    else:
        googleSession = await create_google_session(creds)
        textToSend = build_full_context_text(req.messages)
        SESSION_CACHE[convKey] = {"session_id": googleSession, "updated_at": time.time()}
        isRetryMode = True

    chatId = f"chatcmpl-{uuid.uuid4()}"
    createdTime = int(time.time())

    async def response_wrapper():
        retryCount = 0
        maxRetries = 2
        currentText = textToSend
        currentRetryMode = isRetryMode
        currentFileIds = []
        
        while retryCount <= maxRetries:
            try:
                currentSession = SESSION_CACHE[convKey]["session_id"]
                
                if currentImages and not currentFileIds:
                    for img in currentImages:
                        fid = await upload_context_file(creds, currentSession, img["mime"], img["data"])
                        currentFileIds.append(fid)

                if currentRetryMode:
                    currentText = build_full_context_text(req.messages)

                async for chunk in stream_chat_generator(
                    creds,
                    currentSession, 
                    currentText, 
                    currentFileIds, 
                    req.model, 
                    chatId, 
                    createdTime, 
                    req.stream
                ):
                    yield chunk
                break 
            except (httpx.ConnectError, httpx.ReadTimeout, ssl.SSLError, HTTPException) as e:
                retryCount += 1
                if retryCount <= maxRetries:
                    try:
                        newSess = await create_google_session(creds)
                        SESSION_CACHE[convKey] = {"session_id": newSess, "updated_at": time.time()}
                        currentRetryMode = True 
                        currentFileIds = [] 
                    except Exception as create_err:
                        if req.stream: yield f"data: {json.dumps({'error': {'message': 'Recovery Failed'}})}\n\n"
                        return
                else:
                    if req.stream: yield f"data: {json.dumps({'error': {'message': str(e)}})}\n\n"
                    return

    if req.stream:
        return StreamingResponse(response_wrapper(), media_type="text/event-stream")
    
    fullContent = ""
    async for chunk_str in response_wrapper():
        if chunk_str.startswith("data: [DONE]"): break
        if chunk_str.startswith("data: "):
            try:
                data = json.loads(chunk_str[6:])
                delta = data["choices"][0]["delta"]
                if "content" in delta: fullContent += delta["content"]
            except: pass

    return {
        "id": chatId,
        "object": "chat.completion",
        "created": createdTime,
        "model": req.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": fullContent}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }

async def stream_chat_generator(creds: UserCredentials, session: str, text_content: str, file_ids: List[str], model_name: str, chat_id: str, created_time: int, is_stream: bool):
    jwt = await fetch_jwt(creds)
    headers = get_common_headers(jwt)
    
    body = {
        "configId": creds.config_id,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": session,
            "query": {"parts": [{"text": text_content}]},
            "fileIds": file_ids,
            "answerGenerationMode": "NORMAL",
            "toolsSpec": {"toolRegistry": "default_tool_registry"},
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Asia/Shanghai"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    target_model_id = MODEL_MAPPING.get(model_name)
    if target_model_id:
        body["streamAssistRequest"]["assistGenerationConfig"] = {"modelId": target_model_id}

    if is_stream:
        chunk = create_chunk(chat_id, created_time, model_name, {"role": "assistant"}, None)
        yield f"data: {chunk}\n\n"

    logger.info(f"📤 发送消息... Session: {session[-10:] if session else 'None'}")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist",
        headers=headers,
        json=body,
    )
    
    if r.status_code != 200:
        logger.error(f"❌ HTTP错误: {r.status_code} {r.text}")
        raise HTTPException(status_code=r.status_code, detail=f"Upstream Error {r.text}")

    # === 调试打印 ===
    log_text = r.text if len(r.text) < 1000 else r.text[:500] + "..."
    logger.info(f"🔍 Google 返回内容: {log_text}")

    try:
        data_list = r.json()
    except Exception:
        logger.error("❌ JSON 解析失败")
        raise HTTPException(status_code=502, detail="Invalid JSON response")
        
    hasContent = False
    for data in data_list:
        if "error" in data:
            logger.error(f"⚠️ 发现业务错误: {data['error']}")
        
        for reply in data.get("streamAssistResponse", {}).get("answer", {}).get("replies", []):
            text = reply.get("groundedContent", {}).get("content", {}).get("text", "")
            if text:
                hasContent = True
                chunk = create_chunk(chat_id, created_time, model_name, {"content": text}, None)
                if is_stream:
                    yield f"data: {chunk}\n\n"
    
    if not hasContent:
        # 显式报错给客户端
        err_msg = "**[错误: Google 返回空响应。请检查 Logs 中的 'Google 返回内容'，通常是 Cookie 失效或不匹配]**"
        if is_stream:
            yield f"data: {create_chunk(chat_id, created_time, model_name, {'content': err_msg}, None)}\n\n"

    if is_stream:
        final_chunk = create_chunk(chat_id, created_time, model_name, {}, "stop")
        yield f"data: {final_chunk}\n\n"
        yield "data: [DONE]\n\n"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
