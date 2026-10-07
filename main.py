"""HTTP 入口：把信封加密服务暴露为本地 API。

调用方身份由服务端按凭据解析，客户端自报的身份/权限一律不被采纳：
  X-Caller-Token: 服务端预先登记的调用方凭据
  - 未携带或无法识别 -> 401 UNAUTHENTICATED
  - 能识别但权限不够 -> 403 PERMISSION_DENIED
本地开发默认凭据见 _build_registry()；生产环境应替换为外部身份源。
"""

import base64

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


def _build_registry() -> IdentityRegistry:
    """本地开发用的服务端身份表；客户端无法通过请求内容改变解析结果。"""
    registry = IdentityRegistry()
    registry.register("dev-admin-token", "admin", frozenset(Permission))
    registry.register("dev-writer-token", "writer", frozenset({Permission.ENCRYPT}))
    registry.register("dev-reader-token", "reader", frozenset({Permission.DECRYPT}))
    return registry


registry = _build_registry()


def _caller(token: str | None) -> Caller:
    """只认服务端登记的凭据；识别失败抛 UNAUTHENTICATED（映射为 401）。"""
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


class EnvelopeOut(BaseModel):
    version: int
    wrapped_dek_b64: str
    wrap_nonce_b64: str
    nonce_b64: str
    ciphertext_b64: str


class RecordIn(BaseModel):
    record_id: str
    plaintext_b64: str


class ReencryptIn(BaseModel):
    record_ids: list[str]
    target_version: int


def _out(env: Envelope) -> EnvelopeOut:
    return EnvelopeOut(
        version=env.version,
        wrapped_dek_b64=_b64e(env.wrapped_dek),
        wrap_nonce_b64=_b64e(env.wrap_nonce),
        nonce_b64=_b64e(env.nonce),
        ciphertext_b64=_b64e(env.ciphertext),
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
    _caller(x_caller_token).require(Permission.ROTATE)
    key = service.keyring.register(body.version, _b64d(body.material_b64))
    return {"version": key.version, "state": key.state.value}


@app.post("/keys/{version}/activate")
def activate(version: int, x_caller_token: str | None = Header(default=None)):
    _caller(x_caller_token).require(Permission.ROTATE)
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


@app.get("/keys/{version}/usage")
def usage(version: int, x_caller_token: str | None = Header(default=None)):
    stats = service.usage(_caller(x_caller_token), version)
    return {
        "version": version,
        "encrypt_count": stats.encrypt_count,
        "decrypt_count": stats.decrypt_count,
        "last_used_at": stats.last_used_at,
    }


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


@app.post("/records", status_code=201)
def store_record(body: RecordIn, x_caller_token: str | None = Header(default=None)):
    service.store_record(_caller(x_caller_token), body.record_id, _b64d(body.plaintext_b64))
    return {"stored": body.record_id}


@app.get("/records/{record_id}")
def read_record(record_id: str, x_caller_token: str | None = Header(default=None)):
    plaintext = service.read_record(_caller(x_caller_token), record_id)
    return {"record_id": record_id, "plaintext_b64": _b64e(plaintext)}


@app.post("/records/reencrypt")
def reencrypt(body: ReencryptIn, x_caller_token: str | None = Header(default=None)):
    count = service.reencrypt_records(_caller(x_caller_token), body.record_ids, body.target_version)
    return {"reencrypted": count, "target_version": body.target_version}


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
