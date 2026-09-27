"""HTTP 入口：把信封加密服务暴露为本地 API。

调用方身份通过请求头传入：
  X-Caller-Name: 调用方名称
  X-Caller-Permissions: 逗号分隔的权限列表，如 "ENCRYPT,DECRYPT"
"""

import base64

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.auth import Caller, Permission
from app.errors import KeyManagementError
from app.models import Envelope
from app.service import EnvelopeCryptoService

app = FastAPI(title="envelope-key-rotation")
service = EnvelopeCryptoService()


def _caller(name: str, permissions: str) -> Caller:
    perms = frozenset(Permission(p) for p in permissions.split(",") if p)
    return Caller(name, perms)


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


def _out(env: Envelope) -> EnvelopeOut:
    return EnvelopeOut(
        version=env.version,
        wrapped_dek_b64=_b64e(env.wrapped_dek),
        wrap_nonce_b64=_b64e(env.wrap_nonce),
        nonce_b64=_b64e(env.nonce),
        ciphertext_b64=_b64e(env.ciphertext),
    )


@app.exception_handler(KeyManagementError)
async def on_business_error(_request, exc: KeyManagementError):
    raise HTTPException(status_code=400, detail={"code": exc.code.value, "message": str(exc)})


@app.post("/keys/register", status_code=201)
def register(body: KeyIn, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    caller = _caller(x_caller_name, x_caller_permissions)
    caller.require(Permission.ROTATE)
    key = service.keyring.register(body.version, _b64d(body.material_b64))
    return {"version": key.version, "state": key.state.value}


@app.post("/keys/{version}/activate")
def activate(version: int, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    caller = _caller(x_caller_name, x_caller_permissions)
    caller.require(Permission.ROTATE)
    key = service.keyring.activate(version)
    return {"version": key.version, "state": key.state.value}


@app.post("/keys/rotate", status_code=201)
def rotate(body: KeyIn, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    service.rotate(_caller(x_caller_name, x_caller_permissions), body.version, _b64d(body.material_b64))
    return {"rotated_to": body.version}


@app.post("/keys/{version}/deactivate")
def deactivate(version: int, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    service.deactivate(_caller(x_caller_name, x_caller_permissions), version)
    return {"deactivated": version}


@app.post("/encrypt", response_model=EnvelopeOut)
def encrypt(body: EncryptIn, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    env = service.encrypt(_caller(x_caller_name, x_caller_permissions), _b64d(body.plaintext_b64))
    return _out(env)


@app.post("/decrypt")
def decrypt(body: EnvelopeOut, x_caller_name: str = Header(), x_caller_permissions: str = Header()):
    env = Envelope(
        version=body.version,
        wrapped_dek=_b64d(body.wrapped_dek_b64),
        wrap_nonce=_b64d(body.wrap_nonce_b64),
        nonce=_b64d(body.nonce_b64),
        ciphertext=_b64d(body.ciphertext_b64),
    )
    plaintext = service.decrypt(_caller(x_caller_name, x_caller_permissions), env)
    return {"plaintext_b64": _b64e(plaintext)}


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
