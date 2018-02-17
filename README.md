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

## 使用

### Nginx

```
server {
	server_name www.example.com;

	rewrite ^ https://$server_name$request_uri? permanent;
}

server {
	listen 443;
	server_name www.example.com;

	ssl on;
	ssl_certificate /opt/letsencrypt/certs/example.com/fullchain.pem;
	ssl_certificate_key /opt/letsencrypt/certs/example.com/privkey.pem;
	ssl_session_timeout 5m;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA;
	ssl_session_cache shared:SSL:50m;
#	ssl_dhparam /tmp/server.dhparam;
	ssl_prefer_server_ciphers on;

#	location / {
#		proxy_pass  http://127.0.0.1:3000;
#		proxy_redirect     off;
#		proxy_set_header   Host             $host;
#		proxy_set_header   X-Real-IP        $remote_addr;
#		proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
#	}
}
```
