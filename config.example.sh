#login_token
export login_token='id,token'

#domain
export domain='example.com'

#record
export record='www'

#letsencrypt服务器设定
#CA="https://acme-v01.api.letsencrypt.org/directory" #正式服务器
CA="https://acme-staging.api.letsencrypt.org/directory" #测试服务器

#目录设定
TMPDIR=
ACCOUNTDIR=
CERTDIR=
DOMAINS_TXT=
LOCKFILE=

#其他设置
IP_VERSION=     #IPv4或者IPv6，不填默认4
KEYSIZE="4096"  #密钥长度

# Default values
LICENSE="https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"
DOMAINS_D=
HOOK_CHAIN="no"
RENEW_DAYS="30"
WELLKNOWN=
PRIVATE_KEY_RENEW="yes"
PRIVATE_KEY_ROLLOVER="no"
KEY_ALGO=rsa
OPENSSL_CNF="$(openssl version -d | cut -d\" -f2)/openssl.cnf"
CONTACT_EMAIL=
OCSP_MUST_STAPLE="no"