"""SSE 事件流管理器 — 实时推送扫描进度和日志。"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import defaultdict

from ..logging_config import get_logger

logger = get_logger("web.sse")


class SSEManager:
    """管理每个 task_id 的 SSE 消息队列，支持 publish/subscribe 模型。

    同时提供 async publish() 和线程安全 publish_sync() 两种发布方式。
    """

    def __init__(self):
        self._queues: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()  # 线程安全锁

    async def subscribe(self, task_id: str) -> asyncio.Queue:
        """订阅一个任务的 SSE 事件流，返回专用队列。"""
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue(maxsize=200)
            self._queues[task_id].append(q)
            return q

    async def unsubscribe(self, task_id: str, queue: asyncio.Queue) -> None:
        """取消订阅。"""
        async with self._lock:
            try:
                self._queues[task_id].remove(queue)
            except ValueError:
                pass

    async def publish(self, task_id: str, event: str, data: dict) -> None:
        """向所有订阅者广播一个 SSE 事件（协程安全）。"""
        payload = {"event": event, "data": data}
        async with self._lock:
            queues = list(self._queues.get(task_id, []))
        for q in queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def publish_sync(self, task_id: str, event: str, data: dict) -> None:
        """线程安全的同步发布 — 后台线程直接调用，无需事件循环。"""
        payload = {"event": event, "data": data}
        with self._sync_lock:
            queues = list(self._queues.get(task_id, []))
        for q in queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def close_task_sync(self, task_id: str) -> None:
        """线程安全的关闭任务 — 后台线程直接调用。"""
        with self._sync_lock:
            queues = self._queues.pop(task_id, [])
        for q in queues:
            try:
                q.put_nowait({"event": "done", "data": {"message": "scan completed"}})
            except asyncio.QueueFull:
                pass

    async def close_task(self, task_id: str) -> None:
        """关闭一个任务的所有连接。"""
        async with self._lock:
            queues = self._queues.pop(task_id, [])
        for q in queues:
            await q.put({"event": "done", "data": {"message": "scan completed"}})


sse_manager = SSEManager()


async def sse_progress_generator(task_id: str):
    """SSE 异步生成器 — 扫描进度流。"""
    queue = await sse_manager.subscribe(task_id)
    try:
        # 发送初始连接事件
        yield f"event: connected\ndata: {json.dumps({'task_id': task_id})}\n\n"

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                # 心跳保持连接
                yield ": keepalive\n\n"
                continue

            if msg.get("event") == "done":
                yield f"event: done\ndata: {json.dumps(msg['data'])}\n\n"
                break

            yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'], ensure_ascii=False)}\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        await sse_manager.unsubscribe(task_id, queue)


async def sse_log_generator(task_id: str):
    """SSE 异步生成器 — 扫描日志流。"""
    queue = await sse_manager.subscribe(f"{task_id}:logs")
    try:
        yield f"event: connected\ndata: {json.dumps({'task_id': task_id})}\n\n"

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue

            if msg.get("event") == "done":
                yield f"event: done\ndata: {json.dumps(msg['data'])}\n\n"
                break

            yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'], ensure_ascii=False)}\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        await sse_manager.unsubscribe(f"{task_id}:logs", queue)
