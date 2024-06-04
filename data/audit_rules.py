command_black = {
    '敏感操作审计': "mysqldump|crontab",
    '反弹shell检测': 'bash\s-i|nc\s',
    '黑客工具检测': 'nmap|masscan|hydra|frp|nps',
    '敏感文件操作': '/etc/passwd|/etc/shadow|sh_history|authorized_keys|/tmp',
    '疑似木马植入': 'curl |wget ',
    '信息采集': 'ifconfig|whoami|last|lastlog',
    'DNSlog': 'dnslog|ssrf|ceye.io',
    '窃取临时凭据': 'security-credentials'
}
