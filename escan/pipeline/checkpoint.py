"""扫描断点管理 — 支持中断后恢复。

- 文件层：output/pipeline/<timestamp>/checkpoint.json
- 数据库层：checkpoint_snapshots 表
- 双写：文件 + DB 同步写入；DB 不可用时仅写文件
- 加载优先级：DB → 文件 → 推断（从已有文件反推）
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from ..logging_config import get_logger

logger = get_logger("pipeline.checkpoint")

_STEPS = [1, 2, 3, 4]
_STEP_NAMES = {1: "step1", 2: "step2", 3: "step3", 4: "step4"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _checkpoint_path(out_dir: Path) -> Path:
    return out_dir / "checkpoint.json"


# --- 文件读写 ---

def load_checkpoint_file(out_dir: Path) -> dict | None:
    """从 checkpoint.json 读取断点。"""
    cp_path = _checkpoint_path(out_dir)
    if not cp_path.is_file():
        return None
    try:
        return json.loads(cp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("checkpoint.json 损坏，将重新推断")
        return None


def save_checkpoint_file(out_dir: Path, data: dict) -> None:
    """写入 checkpoint.json。"""
    cp_path = _checkpoint_path(out_dir)
    cp_path.parent.mkdir(parents=True, exist_ok=True)
    cp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# --- DB 读写 ---

def _sync_to_db(data: dict) -> None:
    """将断点状态同步到数据库。"""
    from ..database.connection import get_cursor
    from ..database.dao import upsert_checkpoint

    task_id = data.get("task_id")
    if not task_id:
        return  # 无 task_id 时跳过 DB（如 categorized-incremental）
    with get_cursor() as cur:
        if cur is not None:
            upsert_checkpoint(
                cur, task_id, data.get("output_dir", ""),
                data.get("scan_type", "categorized"),
                data.get("engine", "fofa"),
                data,
            )


def load_checkpoint_from_db(task_id: str) -> dict | None:
    """从数据库加载断点。"""
    from ..database.connection import get_cursor
    from ..database.dao import load_checkpoint_from_db as db_load

    with get_cursor() as cur:
        if cur is None:
            return None
        state = db_load(cur, task_id)
        return state


# --- 核心 API ---

def init_checkpoint(out_dir: Path, scan_type: str, engine: str,
                    poc_path: str, task_id: str | None = None,
                    region: str = "") -> dict:
    """新建断点，所有步骤标记为 pending。"""
    data = {
        "scan_type": scan_type,
        "engine": engine,
        "poc_path": poc_path,
        "task_id": task_id,
        "region": region,
        "output_dir": str(out_dir),
        "step1": "pending",
        "step2": "pending",
        "step3": "pending",
        "step4": "pending",
        "step4_templates": [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    save_checkpoint_file(out_dir, data)
    _sync_to_db(data)
    logger.info("断点初始化: %s (%s/%s)", out_dir.name, scan_type, engine)
    return data


def load_checkpoint(out_dir: Path, task_id: str | None = None) -> dict | None:
    """加载断点：DB → 文件 → 推断。"""
    # 1. 优先 DB
    if task_id:
        db_data = load_checkpoint_from_db(task_id)
        if db_data:
            logger.info("断点加载 (DB): %s", task_id)
            return db_data

    # 2. 文件
    file_data = load_checkpoint_file(out_dir)
    if file_data:
        logger.info("断点加载 (文件): %s", out_dir.name)
        return file_data

    # 3. 推断
    return None


def save_checkpoint(out_dir: Path, data: dict) -> None:
    """保存断点：双写文件 + DB。"""
    data["updated_at"] = _now()
    save_checkpoint_file(out_dir, data)
    _sync_to_db(data)


def mark_step_started(out_dir: Path, task_id: str | None, step: int) -> None:
    """标记步骤开始执行。"""
    data = load_checkpoint_file(out_dir)
    if not data:
        return
    key = _STEP_NAMES[step]
    if data.get(key) == "completed":
        return  # 已完成的不重置
    data[key] = "in_progress"
    save_checkpoint(out_dir, data)


def mark_step_completed(out_dir: Path, task_id: str | None, step: int) -> None:
    """标记步骤已完成。"""
    data = load_checkpoint_file(out_dir)
    if not data:
        return
    data[_STEP_NAMES[step]] = "completed"
    save_checkpoint(out_dir, data)
    logger.info("Step %d 完成, 断点已保存", step)


def mark_step4_template_done(out_dir: Path, task_id: str | None,
                              template_name: str) -> None:
    """Step 4 中标记单个模板已完成。"""
    data = load_checkpoint_file(out_dir)
    if not data:
        return
    done = data.setdefault("step4_templates", [])
    if template_name not in done:
        done.append(template_name)
        save_checkpoint(out_dir, data)


def get_resume_step(cp: dict) -> int | None:
    """返回第一个未完成的步骤编号 (1-4)，全部完成返回 None。"""
    for step in _STEPS:
        if cp.get(_STEP_NAMES[step]) != "completed":
            return step
    return None


def infer_checkpoint(out_dir: Path, scan_type: str, engine: str,
                     poc_path: str) -> dict:
    """从已有文件反推断点状态。"""

    def _any_file(pattern: str) -> bool:
        return any(out_dir.glob(pattern))

    cat_dir = out_dir / "categorized"

    step1_done = _any_file("categorized/*_assets.txt") if cat_dir.is_dir() else False
    step2_done = _any_file("categorized/*_results.txt") if cat_dir.is_dir() else False
    step3_done = _any_file("categorized/*_targets.txt") if cat_dir.is_dir() else False
    step4_done = (out_dir / "icp_results.txt").is_file()

    # 推断 step4_templates
    step4_templates = []
    icp_file = out_dir / "icp_results.txt"
    if icp_file.is_file():
        for line in icp_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("模板: "):
                step4_templates.append(line[4:].strip())

    def _status(done: bool) -> str:
        return "completed" if done else "pending"

    data = {
        "scan_type": scan_type,
        "engine": engine,
        "poc_path": poc_path,
        "task_id": None,
        "output_dir": str(out_dir),
        "step1": _status(step1_done),
        "step2": _status(step2_done),
        "step3": _status(step3_done),
        "step4": _status(step4_done),
        "step4_templates": step4_templates,
        "created_at": _now(),
        "updated_at": _now(),
    }
    logger.info("断点推断: step1=%s step2=%s step3=%s step4=%s",
                data["step1"], data["step2"], data["step3"], data["step4"])
    save_checkpoint_file(out_dir, data)
    return data
