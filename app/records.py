"""密文记录仓库：跟踪哪些记录引用了哪个密钥版本。

退役判定与批量重加密都依赖这份索引；与 KeyRing 共用同一把锁，
保证"查引用 -> 退役"与"读记录 -> 重加密 -> 换版本"各自原子完成。
"""

from __future__ import annotations

from .errors import ErrorCode, KeyManagementError
from .models import Envelope


class RecordStore:
    """内存记录仓库：record_id -> Envelope。"""

    def __init__(self) -> None:
        self._records: dict[str, Envelope] = {}

    def put(self, record_id: str, envelope: Envelope) -> None:
        self._records[record_id] = envelope

    def get(self, record_id: str) -> Envelope:
        try:
            return self._records[record_id]
        except KeyError:
            raise KeyManagementError(
                ErrorCode.RECORD_NOT_FOUND, f"记录 {record_id!r} 不存在"
            ) from None

    def delete(self, record_id: str) -> None:
        self._records.pop(record_id, None)

    def ids(self) -> list[str]:
        return list(self._records)

    def versions_in_use(self) -> set[int]:
        """当前仍被至少一条记录引用的版本集合。"""
        return {env.version for env in self._records.values()}
