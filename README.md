# letsencrypt-dnspod
Let’s Encrypt使用dnspod进行验证

## 开始工作
```
 cp config.example.sh config.sh
 cp domains.example.txt domains.txt
```

编辑domains.txt，填入token、domain以及record

运行letsencrypt-dnspod.sh即可

config.sh不用修改亦可正常使用，如有需求请自行对应修改。

建议将此脚本放入计划任务

## 关于DNSPOD
token的设置在：DNSPOD -> 用户中心 -> 安全设置 -> API Token

快捷链接：https://www.dnspod.cn/console/user/security