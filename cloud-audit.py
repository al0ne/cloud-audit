# coding=utf-8

from datetime import datetime, timedelta

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from lib.logger import logger
from plugins.aws_cloud import aws_audit
from plugins.tencent_cloud import tencent_audit


def cloud_audit() -> None:
    """
    执行云平台安全审计，检测AK/SK盗用风险。
    """
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=15)
    logger.info(f'开始执行云安全审计 开始时间：{start_time} 结束时间：{end_time}')
    tencent_audit(int(datetime.timestamp(start_time)), int(datetime.timestamp(end_time)))
    aws_audit(start_time, end_time)


# 创建前台调度器
scheduler = BlockingScheduler()

# 添加调度任务，间隔15分钟
scheduler.add_job(cloud_audit, trigger=CronTrigger(minute='*/15'), name='cloud_audit')

logger.info('程序已启动！请等待15分钟后循环执行审计命令')

# 启动调度器
scheduler.start()

if __name__ == "__main__":
    pass
