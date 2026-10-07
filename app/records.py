"""密文台账：登记服务产出的每一条信封密文，支撑退役判定与批量重加密。

- 每条记录有唯一 record_id，记录其信封与所属密钥版本；
- 退役判定依赖 `count_by_version`：某版本仍有记录在册即视为"仍在使用中"；
- 批量重加密通过 `replace` 把记录整体换到新版本信封之下。
"""

from __future__ import annotations

import threading

from .errors import ErrorCode, KeyManagementError
from .models import Envelope


class CiphertextStore:
    """内存密文台账（线程安全）。"""

    def __init__(self) -> None:
        self._records: dict[int, Envelope] = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def put(self, envelope: Envelope) -> int:
        """登记一条信封密文，返回 record_id。"""
        with self._lock:
            record_id = self._next_id
            self._next_id += 1
            self._records[record_id] = envelope
            return record_id

    def get(self, record_id: int) -> Envelope:
        with self._lock:
            try:
                return self._records[record_id]
            except KeyError:
                raise KeyManagementError(
                    ErrorCode.RECORD_NOT_FOUND, f"记录 {record_id} 不存在"
                ) from None

    def replace(self, record_id: int, envelope: Envelope) -> None:
        """把记录整体替换为新信封（重加密提交时使用）。"""
        with self._lock:
            if record_id not in self._records:
                raise KeyManagementError(
                    ErrorCode.RECORD_NOT_FOUND, f"记录 {record_id} 不存在"
                )
            self._records[record_id] = envelope

    def count_by_version(self, version: int) -> int:
        """该版本当前在册的密文条数；>0 即"版本仍在使用中"。"""
        with self._lock:
            return sum(1 for e in self._records.values() if e.version == version)

    def snapshot(self) -> dict[int, Envelope]:
        """返回台账快照（重加密批量读取用，避免逐条加锁）。"""
        with self._lock:
            return dict(self._records)
