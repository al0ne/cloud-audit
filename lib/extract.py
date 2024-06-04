# coding=utf-8
from datetime import datetime

import pytz


def extract_dicts_with_sip(sip, list_of_dicts):
    """
    Extracts dictionaries from a list where the 'sip' key matches the specified value.

    :param sip: The value of 'sip' to match.
    :param list_of_dicts: List of dictionaries to search through.
    :return: A list of dictionaries where the 'sip' key matches the specified value.
    """
    return [d for d in list_of_dicts if d.get('SourceIPAddress') == sip]


def utc_to_china_tz(utc_time: str) -> datetime:
    """
    转换标准时区到中国+8时区
    :param utc_time:
    :return:
    """
    # 创建一个UTC时间对象
    utc_time = datetime.strptime(utc_time, "%Y-%m-%dT%H:%M:%SZ")
    utc_time = pytz.utc.localize(utc_time)

    # 创建一个中国时区对象
    china_tz = pytz.timezone('Asia/Shanghai')

    return utc_time.astimezone(china_tz).replace(tzinfo=None)


def datetime_to_utc(now):
    # 为本地时间添加时区信息（这里假设您的本地时区是东八区）
    local_time_with_tz = now.replace(tzinfo=pytz.timezone('Asia/Shanghai'))

    # 将时间转换为 UTC
    utc_time = local_time_with_tz.astimezone(pytz.utc)

    # 将时间格式化为 YYYY-MM-DDThh:mm:ssZ
    formatted_time = utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return formatted_time


if __name__ == "__main__":
    print(datetime_to_utc(datetime.now()))
