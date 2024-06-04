import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

# 可信的网段
while_cidr = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]

# Discord 通知地址
discord_webhook_url = os.getenv('discord_webhook_url')

# 企业微信 通知地址
weixin_webhook_url = os.getenv('weixin_webhook_url')

# 腾讯AK/SK监控
TencentAccessKey = os.getenv('TencentAccessKey')
TencentSecretKey = os.getenv('TencentSecretKey')
AlibabaAccessKey = os.getenv('AlibabaAccessKey')
AlibabaSecretKey = os.getenv('AlibabaSecretKey')

# 要监控的AK列表
AccesskeyList = os.getenv('AccesskeyList').split(',')

# AWS的AK/SK信息
aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

# AWS要关注的地域
aws_region = [
    "us-east-1",
    "us-east-2",
    "ap-northeast-1",
    "ap-southeast-1"
]

# AWS 要关注的事件
aws_event = [
    "ListUsers",  # 查看用户列表
    "ListBuckets",  # 查看AWS S3 桶的信息
    "DescribeInstances",  # 查看EC2 列表
    "DescribeDBInstances",  # 查看RDS数据库信息
    "CreateUser",  # 创建用户信息
    "AttachUserPolicy"  # 选择策略
]

if __name__ == "__main__":
    print(AccesskeyList)
