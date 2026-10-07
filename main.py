"""HTTP 入口：把信封加密服务暴露为本地 API。

调用方身份由服务端确认：请求头只携带令牌
  X-Caller-Token: 服务端预置的调用方令牌
服务端按令牌在本地身份注册表中查出名称与权限；
客户端自报的任何名称/权限一律不被信任。
令牌无法识别 -> 401；身份合法但权限不够 -> 403。

预置身份来自环境变量 EKR_IDENTITIES（JSON），缺省使用 README 中的本地开发身份。
"""

import base64
import json
import os

import uvicorn
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth import Caller, IdentityRegistry, Permission
from app.errors import ErrorCode, KeyManagementError
from app.models import Envelope
from app.service import EnvelopeCryptoService

app = FastAPI(title="envelope-key-rotation")
service = EnvelopeCryptoService()
registry = IdentityRegistry()

# 本地开发缺省身份（生产环境应通过 EKR_IDENTITIES 覆盖）
_DEFAULT_IDENTITIES = {
    "admin-token": {"name": "admin", "permissions": [p.value for p in Permission]},
    "writer-token": {"name": "writer", "permissions": ["ENCRYPT"]},
    "reader-token": {"name": "reader", "permissions": ["DECRYPT"]},
}


def _seed_identities() -> None:
    raw = os.environ.get("EKR_IDENTITIES")
    spec = json.loads(raw) if raw else _DEFAULT_IDENTITIES
    for token, info in spec.items():
        registry.provision(
            token, info["name"], frozenset(Permission(p) for p in info["permissions"])
        )


_seed_identities()


def _caller(token: str | None) -> Caller:
    """服务端确认调用方身份；客户端自报信息一律不参与鉴权。"""
    return registry.authenticate(token)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(data: str) -> bytes:
    return base64.b64decode(data)


class KeyIn(BaseModel):
    version: int
    material_b64: str


class EncryptIn(BaseModel):
    plaintext_b64: str


class ReencryptIn(BaseModel):
    record_ids: list[int]
    target_version: int


class EnvelopeOut(BaseModel):
    version: int
    wrapped_dek_b64: str
    wrap_nonce_b64: str
    nonce_b64: str
    ciphertext_b64: str
    record_id: int | None = None


def _out(env: Envelope) -> EnvelopeOut:
    return EnvelopeOut(
        version=env.version,
        wrapped_dek_b64=_b64e(env.wrapped_dek),
        wrap_nonce_b64=_b64e(env.wrap_nonce),
        nonce_b64=_b64e(env.nonce),
        ciphertext_b64=_b64e(env.ciphertext),
        record_id=env.record_id,
    )


_STATUS_BY_CODE = {
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.PERMISSION_DENIED: 403,
}


@app.exception_handler(KeyManagementError)
async def on_business_error(_request, exc: KeyManagementError):
    status = _STATUS_BY_CODE.get(exc.code, 400)
    return JSONResponse(
        status_code=status,
        content={"code": exc.code.value, "message": str(exc)},
    )


@app.post("/keys/register", status_code=201)
def register(body: KeyIn, x_caller_token: str | None = Header(default=None)):
    caller = _caller(x_caller_token)
    caller.require(Permission.ROTATE)
    key = service.keyring.register(body.version, _b64d(body.material_b64))
    return {"version": key.version, "state": key.state.value}


@app.post("/keys/{version}/activate")
def activate(version: int, x_caller_token: str | None = Header(default=None)):
    caller = _caller(x_caller_token)
    caller.require(Permission.ROTATE)
    key = service.keyring.activate(version)
    return {"version": key.version, "state": key.state.value}


@app.post("/keys/rotate", status_code=201)
def rotate(body: KeyIn, x_caller_token: str | None = Header(default=None)):
    service.rotate(_caller(x_caller_token), body.version, _b64d(body.material_b64))
    return {"rotated_to": body.version}


@app.post("/keys/{version}/deactivate")
def deactivate(version: int, x_caller_token: str | None = Header(default=None)):
    service.deactivate(_caller(x_caller_token), version)
    return {"deactivated": version}


@app.post("/keys/{version}/retire")
def retire(version: int, x_caller_token: str | None = Header(default=None)):
    service.retire(_caller(x_caller_token), version)
    return {"retired": version}


@app.get("/keys/{version}/stats")
def stats(version: int, x_caller_token: str | None = Header(default=None)):
    return service.version_stats(_caller(x_caller_token), version)


@app.post("/encrypt", response_model=EnvelopeOut)
def encrypt(body: EncryptIn, x_caller_token: str | None = Header(default=None)):
    env = service.encrypt(_caller(x_caller_token), _b64d(body.plaintext_b64))
    return _out(env)


@app.post("/decrypt")
def decrypt(body: EnvelopeOut, x_caller_token: str | None = Header(default=None)):
    env = Envelope(
        version=body.version,
        wrapped_dek=_b64d(body.wrapped_dek_b64),
        wrap_nonce=_b64d(body.wrap_nonce_b64),
        nonce=_b64d(body.nonce_b64),
        ciphertext=_b64d(body.ciphertext_b64),
    )
    plaintext = service.decrypt(_caller(x_caller_token), env)
    return {"plaintext_b64": _b64e(plaintext)}


@app.post("/reencrypt")
def reencrypt(body: ReencryptIn, x_caller_token: str | None = Header(default=None)):
    return service.reencrypt(_caller(x_caller_token), body.record_ids, body.target_version)


@app.get("/")
def read_root():
    return {"service": "envelope-key-rotation", "active": _safe_active()}


def _safe_active():
    try:
        return service.keyring.active_version().version
    except KeyManagementError:
        return None


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
