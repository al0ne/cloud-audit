# coding=utf-8

import requests

from config.setting import discord_webhook_url, weixin_webhook_url
from lib.logger import logger


def discord_send(content: str):
    """
    扫描到漏洞后自动微信通知
    :param content: 要发送的内容
    """
    data = {
        "username": "云安全助手",
        "embeds": [{
            "description": content,
            "title": "云平台告警提示！"
        }],
    }
    try:
        result = requests.post(discord_webhook_url, json=data, timeout=10)
        if result.status_code != 204:
            logger.info(f"webhook 发送失败：{result.status_code}---{result.text}")
    except Exception as e:
        logger.info(e)


def weixin_send(content: str):
    """
    企业微信推送
    :param content: 要推送的内容
    :return: None
    """
    headers = {"Content-Type": "application/json"}
    data = {
        "msgtype": "text",
        "text": {
            "content": content,  # 让群机器人发送的消息内容。
            "mentioned_list": [],
        }
    }

    try:
        r = requests.post(weixin_webhook_url, headers=headers, json=data).json()
        if r.get('errmsg') != 'ok':
            logger.warning(f'{content} 消息发送失败！')
    except Exception as e:
        logger.info(e)


def send_message(message: str):
    """
    发送消息
    :param message: 消息内容
    :return:
    """
    if discord_webhook_url:
        discord_send(message)
    if weixin_webhook_url:
        weixin_send(message)


if __name__ == "__main__":
    send_message('test')
