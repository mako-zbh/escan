"""数据库日志处理器 — 将 pipeline 日志实时写入 scan_logs 表。"""

import logging
import threading

from ..database.connection import get_cursor
from ..database.dao import insert_scan_log


class DBLogHandler(logging.Handler):
    """线程安全的数据库日志处理器。

    用法:
        handler = DBLogHandler(task_id)
        logger.addHandler(handler)
        ... 执行扫描 ...
        logger.removeHandler(handler)
        handler.flush_remaining()
    """

    def __init__(self, task_id: str, level=logging.INFO):
        super().__init__(level=level)
        self.task_id = task_id
        self._lock = threading.Lock()
        self.setFormatter(logging.Formatter(
            "%(message)s"  # 仅消息，级别由 level 字段区分
        ))

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            if not msg.strip():
                return
            with self._lock:
                with get_cursor() as cur:
                    if cur is not None:
                        insert_scan_log(
                            cur,
                            self.task_id,
                            getattr(record, "scan_step", None),
                            record.levelname,
                            msg,
                        )
        except Exception:
            self.handleError(record)

    def flush_remaining(self):
        """处理器被移除后，确保剩余日志写入。"""
        pass  # 每条 emit 即时写入，无需额外 flush
