"""本地密钥管理与信封加密服务（FastAPI）。

接口（均需通过 X-Api-Key 头鉴权）：
- POST /keys/rotate        生成并启用新主密钥版本      需要 ROTATE
- POST /keys/{v}/disable   停用指定版本                需要 DISABLE
- GET  /keys               查看各版本状态              任意已认证调用方
- POST /encrypt            信封加密                    需要 ENCRYPT
- POST /decrypt            按信封记录版本解密          需要 DECRYPT
"""

from __future__ import annotations

import base64
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from app.crypto import Envelope
from app.errors import ErrorReason, KeyManagementError
from app.keystore import KeyState
from app.service import Caller, EnvelopeService, Permission

# 本地演示用的调用方注册表：api_key -> 主体及权限
_PRINCIPALS: dict[str, Caller] = {
    "key-admin": Caller(
        "admin", frozenset({Permission.ROTATE, Permission.DISABLE})
    ),
    "key-writer": Caller(
        "writer", frozenset({Permission.ENCRYPT})
    ),
    "key-reader": Caller(
        "reader", frozenset({Permission.DECRYPT})
    ),
    "key-all": Caller(
        "all", frozenset(iter(Permission))
    ),
}

service = EnvelopeService()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 启动时登记第一个主密钥版本，保证加密开箱可用
    service.rotate(Caller("bootstrap", frozenset(iter(Permission))))
    yield


app = FastAPI(title="envelope-key-rotation", lifespan=lifespan)

_HTTP_STATUS = {
    ErrorReason.PERMISSION_DENIED: status.HTTP_403_FORBIDDEN,
    ErrorReason.KEY_NOT_FOUND: status.HTTP_404_NOT_FOUND,
    ErrorReason.DUPLICATE_VERSION: status.HTTP_409_CONFLICT,
    ErrorReason.VERSION_ROLLBACK: status.HTTP_409_CONFLICT,
    ErrorReason.KEY_DISABLED: status.HTTP_409_CONFLICT,
    ErrorReason.KEY_ALREADY_ACTIVE: status.HTTP_409_CONFLICT,
    ErrorReason.NO_ACTIVE_KEY: status.HTTP_409_CONFLICT,
    ErrorReason.TAMPERED_CIPHERTEXT: status.HTTP_400_BAD_REQUEST,
    ErrorReason.VERSION_MISMATCH: status.HTTP_400_BAD_REQUEST,
    ErrorReason.MALFORMED_ENVELOPE: status.HTTP_400_BAD_REQUEST,
}


@app.exception_handler(KeyManagementError)
def _km_error_handler(_, exc: KeyManagementError):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=_HTTP_STATUS.get(exc.reason, 400),
        content={"error": exc.reason.value, "detail": str(exc)},
    )


def authenticate(x_api_key: str | None = Header(default=None)) -> Caller:
    caller = _PRINCIPALS.get(x_api_key or "")
    if caller is None:
        raise HTTPException(status_code=401, detail="无效或缺失的 X-Api-Key")
    return caller


def require(*perms: Permission):
    def checker(caller: Caller = Depends(authenticate)) -> Caller:
        missing = [p.value for p in perms if p not in caller.permissions]
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"调用方 {caller.name!r} 缺少权限 {missing}",
            )
        return caller

    return checker


class PlaintextIn(BaseModel):
    plaintext: str


class CiphertextIn(BaseModel):
    envelope: str  # base64 编码的信封字节


@app.post("/keys/rotate")
def rotate(caller: Caller = Depends(require(Permission.ROTATE))):
    kv = service.rotate(caller)
    return {"version": kv.version, "state": kv.state.value}


@app.post("/keys/{version}/disable")
def disable(version: int, caller: Caller = Depends(require(Permission.DISABLE))):
    kv = service.disable(caller, version)
    return {"version": kv.version, "state": kv.state.value}


@app.get("/keys")
def list_keys(_: Caller = Depends(authenticate)):
    with service.keystore.lock:
        versions = service.keystore.snapshot()
        active = [kv for kv in versions if kv.state is KeyState.ACTIVE]
        return {
            "latest_active": max((kv.version for kv in active), default=None),
            "versions": [{"version": kv.version, "state": kv.state.value} for kv in versions],
        }


@app.post("/encrypt")
def encrypt(body: PlaintextIn, caller: Caller = Depends(require(Permission.ENCRYPT))):
    env = service.encrypt(caller, body.plaintext.encode("utf-8"))
    return {
        "key_version": env.key_version,
        "envelope": base64.b64encode(env.to_bytes()).decode("ascii"),
    }


@app.post("/decrypt")
def decrypt(body: CiphertextIn, caller: Caller = Depends(require(Permission.DECRYPT))):
    try:
        raw = base64.b64decode(body.envelope, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"envelope 不是合法 base64: {exc}") from exc
    env = Envelope.from_bytes(raw)
    plaintext = service.decrypt(caller, env)
    return {"key_version": env.key_version, "plaintext": plaintext.decode("utf-8")}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
