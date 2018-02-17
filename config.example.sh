#letsencrypt服务器设定
CA="https://acme-v01.api.letsencrypt.org/directory" #正式服务器
#CA="https://acme-staging.api.letsencrypt.org/directory" #测试服务器

#目录设定
TMPDIR=
ACCOUNTDIR=
CERTDIR=
DOMAINS_TXT=
LOCKFILE=

#其他设置
IP_VERSION=     #IPv4或者IPv6，不填默认4
CONTACT_EMAIL=  #联系人邮箱（可选，如果填写则将会在注册时提交）
RENEW_DAYS="30" #证书有效期，超过这个日期，执行时将会更新证书
KEY_ALGO=rsa    #可选类型：rsa|prime256v1|secp384r1
KEYSIZE="4096"  #RSA密钥长度（只有KEY_ALGO=rsa时候有效）
LICENSE="https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf"
