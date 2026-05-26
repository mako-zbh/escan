"""通用重试装饰器 — 指数退避，支持配置重试次数和异常类型"""

import time
import functools
from ..logging_config import get_logger

logger = get_logger("utils.retry")


def retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 60.0,
    retryable: tuple = (Exception,),
):
    """指数退避重试装饰器。

    Args:
        max_retries:   最大重试次数
        base_delay:    首次重试等待秒数
        backoff_factor: 退避乘数（2 表示 1s → 2s → 4s → 8s）
        max_delay:     最大等待秒数上限
        retryable:     可重试的异常类型元组
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable as e:
                    last_error = e
                    if attempt < max_retries:
                        delay = min(base_delay * (backoff_factor**attempt), max_delay)
                        logger.warning(
                            "%s 失败 (第 %d/%d 次): %s，%0.1fs 后重试",
                            func.__name__,
                            attempt + 1,
                            max_retries,
                            e,
                            delay,
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "%s 重试 %d 次后仍失败: %s",
                            func.__name__,
                            max_retries,
                            e,
                        )
            raise last_error  # type: ignore

        return wrapper

    return decorator
