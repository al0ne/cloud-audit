import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import boto3

from config.setting import aws_region, aws_event, aws_access_key_id, aws_secret_access_key
from config.setting import while_cidr
from lib.extract import utc_to_china_tz
from lib.logger import logger
from lib.send_message import send_message

"""
botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the LookupEvents operation: User: arn:aws:iam::xxxxx:user/test is not authorized to perform: cloudtrail:LookupEvents because no identity-based policy allows the cloudtrail:LookupEvents action

账户必须要有AWSCloudTrail_ReadOnlyAccess权限才行

"""

text_title = '###AWS云平台疑似入侵行为告警###'


def ListBuckets(CloudTrailEvent: dict):
    """
    公网列Amazon S3 Bucket 信息
    :param CloudTrailEvent: AWS API响应数据
    :return: None
    """

    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')

    sip_verify = False

    for cidr in while_cidr:
        if ipaddress.ip_address(sourceIPAddress) in ipaddress.ip_network(cidr):
            sip_verify = True

    if 'aws-internal' not in userAgent and not sip_verify:
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n\n" \
                  f"请注意！有外部IP使用AWS AK/SK对S3执行ListBuckets，疑似被攻击者利用。\n\n"
        send_message(message)


def ListUsers(CloudTrailEvent: dict):
    """
    检测异常列用户信息，使用ak/sk查看执行ListUsers但是账号本身没有IAM权限。
    :param CloudTrailEvent:  AWS API响应数据
    :return: None
    """

    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')
    errorCode = CloudTrailEvent.get('errorCode')
    errorMessage = CloudTrailEvent.get('errorMessage')
    if errorCode == 'AccessDenied':
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n错误信息：{errorMessage}\n\n" \
                  f"请注意！有外部使用AWS AK/SK 查看用户，并且该账户没有对应IAM权限，疑似被攻击者利用。\n\n"
        send_message(message)


def CreateUser(CloudTrailEvent: dict):
    """
    检测异常使用AK/SK添加用户行为
    :param CloudTrailEvent: AWS json数据
    :return: None
    """

    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')
    CreateUserName = CloudTrailEvent.get('responseElements').get('user').get('userName')

    sip_verify = False

    for cidr in while_cidr:
        if ipaddress.ip_address(sourceIPAddress) in ipaddress.ip_network(cidr):
            sip_verify = True

    if not sip_verify:
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n" \
                  f"添加账号名称：{CreateUserName}\n\n请注意！有外部IP使用AWS AK/SK 添加用户，疑似被攻击者利用。\n\n"
        send_message(message)


def AttachUserPolicy(CloudTrailEvent: dict):
    """
    检测使用AK/SK添加给用户添加权限行为
    :param CloudTrailEvent: AWS json数据
    :return: None
    """
    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')
    CreateUserName = CloudTrailEvent.get('requestParameters').get('userName')
    policyArn = CloudTrailEvent.get('requestParameters').get('policyArn')

    if 'AdministratorAccess' in policyArn:
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n" \
                  f"账号名称：{CreateUserName}\n添加权限：{policyArn}\n\n" \
                  f"请注意！有外部IP利用AK/SK进行IAM权限提升，疑似被攻击者利用。\n"
        send_message(message)


def DescribeInstances(CloudTrailEvent: dict):
    """
    检测使用AK/SK列ec2信息
    :param CloudTrailEvent:
    :return: None
    """
    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')

    sip_verify = False

    for cidr in while_cidr:
        if ipaddress.ip_address(sourceIPAddress) in ipaddress.ip_network(cidr):
            sip_verify = True

    if not sip_verify and 'aws-internal' not in userAgent:
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n\n" \
                  f"检测到有外部IP请求列实例信息，请注意是否为攻击者利用！"
        send_message(message)


def DescribeDBInstances(CloudTrailEvent: dict):
    """
    使用AK/SK获取RDS实例
    :param CloudTrailEvent:
    :return: None
    """

    accessKeyId = CloudTrailEvent.get('userIdentity').get('accessKeyId')
    arn = CloudTrailEvent.get('userIdentity').get('arn')
    eventTime = utc_to_china_tz(CloudTrailEvent.get('eventTime'))
    eventName = CloudTrailEvent.get('eventName')
    awsRegion = CloudTrailEvent.get('awsRegion')
    sourceIPAddress = CloudTrailEvent.get('sourceIPAddress')
    userAgent = CloudTrailEvent.get('userAgent')

    sip_verify = False

    for cidr in while_cidr:
        if ipaddress.ip_address(sourceIPAddress) in ipaddress.ip_network(cidr):
            sip_verify = True

    if not sip_verify and 'aws-internal' not in userAgent:
        message = f"{text_title}\n时间：{eventTime}\n账号ID：{arn}\nRegion：{awsRegion}\nAccessKey ID:{accessKeyId}\n" \
                  f"执行动作：{eventName}\nIP地址：{sourceIPAddress}\nUser-Agent：{userAgent}\n\n" \
                  f"检测到有外部IP请求列RDS信息，请注意是否为攻击者利用！"
        send_message(message)


def cloudtrail(region_event_time):
    """
    调用AWS的cloudtrail获取信息
    :param region_event_time: region+event
    :return:
    """

    region_name, event_name, start_time, end_time = region_event_time

    # 创建 CloudTrail 客户端
    cloudtrail_client = boto3.client('cloudtrail', region_name=region_name, aws_access_key_id=aws_access_key_id,
                                     aws_secret_access_key=aws_secret_access_key)

    # 获取事件
    # https://us-east-1.console.aws.amazon.com/cloudtrail/service/lookupEvents?viewType=eventHistory&pageSize=50&&region=us-east-1
    # AWS CloudTrail 并不直接支持通过 Access Key ID 来检索事件。CloudTrail 事件历史功能允许您通过用户名来检索管理事件，但并不支持直接通过 Access Key ID 来进行搜索。

    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': event_name  # 举例，这里是查询启动实例的事件
            },
        ],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )

    # 打印事件
    for event in response['Events']:

        CloudTrailEvent = json.loads(event.get('CloudTrailEvent'))

        if CloudTrailEvent.get('eventName') == 'CreateUser':
            CreateUser(CloudTrailEvent)

        if CloudTrailEvent.get('eventName') == 'ListUsers':
            ListUsers(CloudTrailEvent)

        if CloudTrailEvent.get('eventName') == 'ListBuckets':
            ListBuckets(CloudTrailEvent)

        if CloudTrailEvent.get('eventName') == 'DescribeInstances':
            DescribeInstances(CloudTrailEvent)

        if CloudTrailEvent.get('eventName') == 'DescribeDBInstances':
            DescribeDBInstances(CloudTrailEvent)

        if CloudTrailEvent.get('eventName') == 'AttachUserPolicy':
            AttachUserPolicy(CloudTrailEvent)


def verify_aws_credentials() -> bool:
    """
    创建一个STS客户端，并尝试调用get_caller_identity方法。这个方法返回与提供的AK/SK相关联的AWS账户的详细信息。如果AK/SK不正确，它将抛出一个ClientError异常。
    """
    try:
        # 使用提供的凭证创建一个STS客户端
        sts_client = boto3.client('sts', aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

        # 尝试获取调用者的身份信息
        identity = sts_client.get_caller_identity()
        return True
    except Exception:
        return False


def aws_audit(start_time, end_time):

    if not verify_aws_credentials():
        logger.warning(f'AWS的AK ID {aws_access_key_id} 调用出现问题，请检查是否配置正确！')
        return None

    with ThreadPoolExecutor(max_workers=len(aws_region) * len(aws_event)) as executor:

        # 创建任务列表
        tasks = {executor.submit(cloudtrail, (region, event, start_time, end_time)): (region, event) for region in
                 aws_region for event
                 in aws_event}
        # 收集结果
        for future in as_completed(tasks):
            region, event = tasks[future]
            try:
                future.result()
            except Exception as e:
                logger.exception(e)


if __name__ == "__main__":
    aws_audit(datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=1))
