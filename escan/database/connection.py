"""数据库连接池 — psycopg2 ThreadedConnectionPool，线程安全。

未配置 DB_PASSWORD 时所有函数返回 None，系统照常运行。
"""

from contextlib import contextmanager

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

from ..config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from ..logging_config import get_logger

logger = get_logger("database")

_pool: ThreadedConnectionPool | None = None
_checked = False


def _is_configured() -> bool:
    return bool(DB_HOST)


def _ensure_pool() -> ThreadedConnectionPool | None:
    """懒初始化连接池，DB 未配置时返回 None。"""
    global _pool, _checked

    if _checked:
        return _pool

    _checked = True
    if not _is_configured():
        logger.debug("数据库未配置（DB_PASSWORD 为空），跳过")
        return None

    try:
        kwargs = dict(
            minconn=1, maxconn=5,
            host=DB_HOST, port=DB_PORT,
            dbname=DB_NAME, user=DB_USER,
        )
        if DB_PASSWORD:
            kwargs["password"] = DB_PASSWORD
        _pool = ThreadedConnectionPool(**kwargs)
        logger.info("数据库连接池已就绪: %s:%s/%s", DB_HOST, DB_PORT, DB_NAME)
    except Exception as e:
        logger.warning("数据库连接失败: %s，功能可用但数据不入库", e)
        return None

    return _pool


def get_connection():
    """从连接池获取连接，DB 未配置时返回 None。"""
    pool = _ensure_pool()
    if pool is None:
        return None
    try:
        return pool.getconn()
    except Exception as e:
        logger.warning("获取数据库连接失败: %s", e)
        return None


def put_connection(conn):
    """归还连接到池。"""
    pool = _ensure_pool()
    if pool is not None and conn is not None:
        try:
            pool.putconn(conn)
        except Exception:
            pass


@contextmanager
def get_cursor(autocommit: bool = False):
    """数据库 cursor 上下文管理器。

    自动 commit/rollback + 归还连接。DB 未配置时 yield None。

    Usage::

        with get_cursor() as cur:
            if cur is not None:
                cur.execute("SELECT ...")
    """
    conn = get_connection()
    if conn is None:
        yield None
        return

    conn.autocommit = autocommit
    try:
        with conn.cursor() as cur:
            yield cur
        if not autocommit:
            conn.commit()
    except Exception:
        if not autocommit:
            conn.rollback()
        raise
    finally:
        put_connection(conn)
