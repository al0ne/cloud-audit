# coding=utf-8

import base64
import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from tencentcloud.cloudaudit.v20190319 import cloudaudit_client, models
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile

from config.setting import TencentAccessKey, TencentSecretKey, AccesskeyList
from config.setting import while_cidr
from data.audit_rules import command_black
from lib.extract import extract_dicts_with_sip
from lib.list_accesskey import ListAccessKeys
from lib.logger import logger
from lib.send_message import send_message


text_title = '###腾讯云平台疑似入侵行为告警###'

def cvm_command_check(event: dict):
    """
    重点监控腾讯云command执行的命令里面是否存在攻击特征！
    :param event: 传输的数据
    :return:
    """
    CloudAuditEvent = json.loads(event.get('CloudAuditEvent'))
    command = base64.b64decode(json.loads(CloudAuditEvent.get("requestParameters")).get("Content")).decode('utf-8')
    for k, v in command_black.items():
        if re.search(command, v):
            region = CloudAuditEvent.get('eventRegion')
            userAgent = CloudAuditEvent.get('userAgent')
            eventTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(CloudAuditEvent.get('eventTime')))
            sourceIPAddress = CloudAuditEvent.get('sourceIPAddress')
            cvm_name = CloudAuditEvent.get('resourceName')
            eventName = CloudAuditEvent.get('eventName')
            accountId = CloudAuditEvent.get('userIdentity').get('accountId')
            secretId = CloudAuditEvent.get('userIdentity').get('secretId')
            message = f"{text_title} \n\n时间：{eventTime}\n账号ID：{accountId}\nregion：{region}\nAccessKey ID:{secretId}\n" \
                      f"机器名称：{cvm_name}\n\n执行动作：{eventName}\n源IP：{sourceIPAddress}\nUser-Agent：{userAgent}\n命中规则：{k}\n" \
                      f"执行命令：{command}\n\n"
            send_message(message)


def add_user_check(event):
    EventTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(event.get('EventTime'))))
    EventNameCn = f"{event.get('EventNameCn')}，并且不在公司网段中"
    SecretId = event.get('SecretId')
    AccountID = event.get('AccountID')
    SourceIPAddress = event.get('SourceIPAddress')
    CloudAuditEvent = json.loads(event.get('CloudAuditEvent'))
    userAgent = CloudAuditEvent.get('userAgent')
    Region = CloudAuditEvent.get('eventRegion')
    requestParameters = json.loads(CloudAuditEvent.get('requestParameters'))
    Remark = requestParameters.get('Remark')
    Name = requestParameters.get('Name')

    sip_verify = False

    for cidr in while_cidr:
        if ipaddress.ip_address(SourceIPAddress) in ipaddress.ip_network(cidr):
            sip_verify = True

    if not sip_verify:
        message = f"{text_title} \n\n时间：{EventTime}\n账号ID：{AccountID}\nRegion：{Region}\nAccessKey ID:{SecretId}\n" \
                  f"执行动作：{EventNameCn}\nIP地址：{SourceIPAddress}\nUser-Agent：{userAgent}\n\n" \
                  f"账号名称：{Name}\n账号备注：{Remark}\n\n"
        send_message(message)


def get_resource_name(db_list: list, sip: str, action: str):
    """

    :param action:
    :param db_list: 获取访问的实例名称集合
    :param sip: 攻击者源IP
    :return:
    """

    name_list = []
    for i in db_list:
        if i.get('SourceIPAddress') == sip:
            if action == 'resource':
                name_list.append(i.get('ResourceTypeCn'))
            if action == 'region':
                name_list.append(i.get('EventRegion'))
    count = len(name_list)
    return list(set(name_list)), count


def get_resource_info(db_list, sip, region_name, resource_name, count):
    for i in db_list:
        if i.get('SourceIPAddress') == sip:
            AccessKey = i.get('SecretId')
            AccountID = i.get('AccountID')
            sourceIPAddress = i.get('SourceIPAddress')
            eventName = i.get('EventName')
            eventTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.get('eventTime')))
            message = f"{text_title} \n\n时间：{eventTime}\n账号ID：{AccountID}\nregion：{region_name}\nAccessKey ID:{AccessKey}\n" \
                      f"执行动作：{eventName}\n命中规则：短时间内来自：{sourceIPAddress} IP频繁枚举数据库列表 {resource_name} {count}次" \
                      f"\n\n疑似AK/SK泄漏，攻击者枚举。\n\n"
            send_message(message)
            break


def database_check(db_list):
    ip_counts = {}
    # 遍历列表
    for item in db_list:
        # 获取IP地址
        ip = item.get('SourceIPAddress')
        # 如果IP地址已经在字典中，增加它的计数
        if ip in ip_counts:
            ip_counts[ip] += 1
        # 否则，添加到字典并设置计数为1
        else:
            ip_counts[ip] = 1

    # 遍历字典
    for sip, count in ip_counts.items():
        # 如果IP地址出现的次数大于等于3，打印出来
        if count >= 3:
            resource_name, count = get_resource_name(db_list, sip, 'resource')
            region_name, _ = get_resource_name(db_list, sip, 'region')
            get_resource_info(db_list, sip, region_name, resource_name, count)


def cvm_check(cvm_list):
    ip_counts = {}
    sip_count = []
    # 遍历列表
    for item in cvm_list:
        # 获取IP地址
        ip = item.get('SourceIPAddress')
        # 如果IP地址已经在字典中，增加它的计数
        if ip in ip_counts:
            ip_counts[ip] += 1
        # 否则，添加到字典并设置计数为1
        else:
            ip_counts[ip] = 1

    # 遍历字典
    for sip, count in ip_counts.items():
        # 如果IP地址出现的次数大于等于3，打印出来
        if count >= 3:
            if sip not in sip_count:
                region_name, _ = get_resource_name(cvm_list, sip, 'region')
                event = extract_dicts_with_sip(sip, cvm_list)[0]
                AccessKey = event.get('SecretId')
                AccountID = event.get('AccountID')
                sourceIPAddress = event.get('SourceIPAddress')
                eventName = event.get('EventName')
                eventTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(event.get('EventTime'))))
                message = f"{text_title} \n\n时间：{eventTime}\n账号ID：{AccountID}\nregion：{region_name}\nAccessKey ID:{AccessKey}\n" \
                          f"执行动作：{eventName}\n命中规则：短时间内来自：{sourceIPAddress} IP频繁枚举CVM机器列表 {count} 次" \
                          f"\n\n疑似AK/SK泄漏，攻击者扫描地域枚举机器列表。\n\n"
                send_message(message)
            sip_count.append(sip)


def GetCallerIdentity(event: dict):
    EventTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(event.get('EventTime'))))
    SecretId = event.get('SecretId')
    AccountID = event.get('AccountID')
    SourceIPAddress = event.get('SourceIPAddress')
    CloudAuditEvent = json.loads(event.get('CloudAuditEvent'))
    userAgent = CloudAuditEvent.get('userAgent')
    Region = CloudAuditEvent.get('eventRegion')
    message = f"{text_title} \n\n时间：{EventTime}\n账号ID：{AccountID}\nRegion：{Region}\nAccessKey ID:{SecretId}\n" \
              f"IP地址：{SourceIPAddress}\nUser-Agent：{userAgent}\n执行动作：GetCallerIdentity\n" \
              f"备注：利用AK/SK获取当前调用者的身份信息,疑似AK/SK泄漏被攻击者利用\n"
    send_message(message)


def audit_log(response):
    db_list = []
    cvm_list = []
    for event in response.get('Events'):
        if event.get('EventName') in ('RunCommand', 'CreateCommand'):
            cvm_command_check(event)
        if event.get('EventName') in ('AddUser', 'DeleteUser'):
            add_user_check(event)
        if event.get('EventName') == 'DescribeDBInstances':
            db_list.append(event)
        if event.get('EventName') == 'DescribeInstances':
            cvm_list.append(event)
        if event.get('EventName') == 'GetCallerIdentity':
            GetCallerIdentity(event)

    database_check(db_list)

    cvm_check(cvm_list)


def CloudauditClient(event, page_size=50):
    """
    腾讯云审计平台
    :param event: 包含start_time, end_time, Accesskey
    :param page_size: 分页大小
    :return: None
    """

    start_time, end_time, Accesskey = event

    try:
        cred = credential.Credential(TencentAccessKey, TencentSecretKey)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cloudaudit.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cloudaudit_client.CloudauditClient(cred, "ap-beijing", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.DescribeEventsRequest()

        NextToken = ''

        # 根据ListOver与NextToken来进行翻页

        while True:
            time.sleep(0.3)
            params = {
                "MaxResults":
                    page_size,
                "StartTime":
                    start_time,
                "EndTime":
                    end_time,
                "LookupAttributes": [{
                    "AttributeKey": "AccessKeyId",
                    "AttributeValue": Accesskey
                }]
            }

            if NextToken:
                params['NextToken'] = NextToken

            req.from_json_string(json.dumps(params))

            # 返回的resp是一个DescribeEventsResponse的实例，与请求对象对应
            resp = json.loads(client.DescribeEvents(req).to_json_string())
            # 输出json格式的字符串回包
            audit_log(resp)

            if resp.get('ListOver'):
                break

            NextToken = resp.get('NextToken')

    except TencentCloudSDKException as err:
        logger.exception(err)


def tencent_audit(start_time: int, end_time: int) -> None:
    """
    腾讯云安全审计平台
    :param start_time: 日志开始时间戳
    :param end_time: 日志结束时间戳
    :return:
    """
    accesskey_list = []
    accesskey_list.extend(ListAccessKeys())
    accesskey_list.extend(AccesskeyList)
    accesskey_list = list(set(accesskey_list))

    with ThreadPoolExecutor(max_workers=len(accesskey_list)) as executor:
        # 创建任务列表
        tasks = {executor.submit(CloudauditClient, (start_time, end_time, accesskey)): accesskey for accesskey in
                 accesskey_list}
        for future in as_completed(tasks):
            try:
                future.result()
            except Exception as e:
                logger.exception(e)


if __name__ == "__main__":
    tencent_audit(1699977600, 1700064000)
