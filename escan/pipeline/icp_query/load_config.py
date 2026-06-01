# -*- coding: utf-8 -*-
import os
import yaml


class Config:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, dict):
                value = Config(**value)
            setattr(self, key, value)

    def __repr__(self):
        return str(self.__dict__)

    def __getattr__(self, name):
        return None


def load_config(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)
    return Config(**data)


# 配置加载：优先读 ICP_QUERY_CONFIG 环境变量，回退到当前目录的 config.yml
_config_path = os.environ.get("ICP_QUERY_CONFIG", "")
if _config_path and os.path.isfile(_config_path):
    config = load_config(_config_path)
elif os.path.isfile("config.yml"):
    config = load_config("config.yml")
else:
    # 最后尝试相对于本文件所在目录
    _here = os.path.dirname(os.path.abspath(__file__))
    _cfg = os.path.join(_here, "config.yml")
    if os.path.isfile(_cfg):
        config = load_config(_cfg)
    else:
        raise FileNotFoundError(
            "ICP_Query 配置文件未找到。请设置 ICP_QUERY_CONFIG 环境变量或确保 config.yml 存在。"
        )
