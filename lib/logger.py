import pathlib
import sys
import time
import traceback
from typing import Union

from loguru import logger

from lib.send_message import send_message

relative_directory = pathlib.Path(__file__).parent.parent
result_save_dir = relative_directory.joinpath('logs')
log_path = result_save_dir.joinpath('status.log')
error_path = result_save_dir.joinpath('error.log')


class Filter:
    def __init__(self) -> None:
        self.level: Union[int, str] = "DEBUG"

    def __call__(self, record):
        module_name: str = record["name"]
        module = sys.modules.get(module_name)
        if module:
            module_name = getattr(module, "__module_name__", module_name)
        record["name"] = module_name.split(".")[0]
        levelno = (
            logger.level(self.level).no if isinstance(self.level, str) else self.level
        )
        return record["level"].no >= levelno


class ErrorFilter:
    def __init__(self):
        self.error_level_no = logger.level("ERROR").no

    def __call__(self, record):
        return record["level"].no < self.error_level_no


class NotifyExceptionSink:
    def __init__(self):
        pass

    def write(self, message):
        level = message.record["level"].name
        if level in ("FATAL", "ERROR"):
            exc_type = message.record["exception"].type
            exc_value = message.record["exception"].value
            tb = message.record["exception"].traceback
            trace_string = ''.join(traceback.format_exception(exc_type, exc_value, tb))
            if 'Timeout' in trace_string or 'Connection' in trace_string:
                return None
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            out_string = f"""Logger 报错提示！\n时间：{mtime}\n等级：{level}\n进程名：{message.record["process"].name}\n进程PID：{message.record["process"].id}\n模块：{message.record["module"]}\n详细信息：\n\n{trace_string}"""

            send_message(out_string)

    def flush(self):
        pass


sink = NotifyExceptionSink()

default_filter = Filter()

# 日志配置
# 终端日志输出格式
stdout_fmt = (
    '<cyan>{time:HH:mm:ss}</cyan> '
    '[<level>{level: <5}</level>] '
    '<blue>{module}</blue>:<cyan>{line}</cyan> - '
    '<level>{message}</level>'
)
# 日志文件记录格式
logfile_fmt = (
    '<light-green>{time:YYYY-MM-DD HH:mm:ss}</light-green> '
    '[<level>{level: <5}</level>] '
    '<cyan>{process.name}({process.id})</cyan> | '
    '<cyan>{thread.name: <18}({thread.id: <5})</cyan> | '
    '<blue>{module}</blue>.<blue>{function}</blue>:'
    '<blue>{line}</blue> - <level>{message}</level>'
)

logger.remove()
logger.level(name='TRACE', color='<cyan><bold>', icon='✏️')
logger.level(name='DEBUG', color='<blue><bold>', icon='🐞 ')
logger.level(name='INFOR', no=20, color='<green><bold>', icon='ℹ️')
logger.level(name='QUITE', no=25, color='<green><bold>', icon='🤫 ')
logger.level(name='ALERT', no=30, color='<yellow><bold>', icon='⚠️')
logger.level(name='ERROR', color='<red><bold>', icon='❌️')
logger.level(name='FATAL', no=50, color='<RED><bold>', icon='☠️')
# log日志里面不写入错误信息
# 设置日志位置
logger.add(sys.stderr, level='INFOR', format=stdout_fmt, backtrace=False, enqueue=True)
logger.add(
    log_path,
    filter=ErrorFilter(),
    rotation="12:00",
    level='INFOR',
    format=logfile_fmt,
    encoding='utf-8',
    backtrace=False,
    enqueue=True,
)
logger.add(
    error_path,
    filter='',
    rotation="12:00",
    level='ERROR',
    format=logfile_fmt,
    encoding='utf-8',
    backtrace=False,
    enqueue=True,
)
logger.add(sink, format="{message}")

if __name__ == "__main__":
    print(logfile_fmt)
