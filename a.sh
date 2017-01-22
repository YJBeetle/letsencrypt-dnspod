#!/usr/bin/env bash

read_xml_dom() {
    local IFS=\> #字段分割符改为>
    read -d \< ENTITY CONTENT #read分隔符改为<
    local ret=$?
    
    if [[ $ENTITY =~ ^[[:space:]]*$ ]] && [[ $CONTENT =~ ^[[:space:]]*$ ]]; then
        return $ret
    fi

    if [[ "$ENTITY" =~ ^\?xml[[:space:]]*(.*)\?$ ]]; then #使用正则去除问号和xml字符
        ENTITY=''
        return 0
    elif [[ "$ENTITY" = \!\[CDATA\[*\]\] ]]; then #CDATA
        CONTENT=${ENTITY}
        CONTENT=${CONTENT#*![CDATA[}
        CONTENT=${CONTENT%]]*}
        ENTITY="![CDATA]"
        return 0
    elif [[ "$ENTITY" = \!--*-- ]]; then #注释
        return 0
    else #普通节点
        if [[ "$ENTITY" = /* ]]; then #节点末尾
            DOMLVL=$[$DOMLVL - 1] #节点等级-1
            return 0
        elif [[ "$ENTITY" = */ ]]; then #节点没有子节点
            :
        elif [ ! "$ENTITY" = '' ]; then #新节点
            DOMLVL=$[$DOMLVL + 1] 
        fi
    fi

    return $ret
}

get_domain_id()
{
    login_token=$1
    domain=$2

    local DOMLVL=0 #初始化节点
    curl -k https://dnsapi.cn/Domain.List -d "login_token=$login_token" 2>/dev/null |
    while read_xml_dom; do
        if [ "$ENTITY" = 'item' ]; then
            itemlevel=$DOMLVL
            id=''
            name=''
        fi
        if [[ "$ENTITY" = '/item' ]] && [[ $DOMLVL < $itemlevel ]] ; then
            id=''
            name=''
        fi
        if [[ "$ENTITY" = 'id' ]] || [[ "$ENTITY" = 'name' ]]; then
            if [ "$ENTITY" = 'id' ]; then
                id=$CONTENT
            fi
            if [ "$ENTITY" = 'name' ]; then
                name=$CONTENT
            fi
            if [ "$name" = "$domain" ]; then
                echo $id;
                return 0;
            fi
        fi
    done
}

get_record_id()
{
    login_token=$1
    record=$2
    domain_id=$3

    local DOMLVL=0 #初始化节点
    curl -k https://dnsapi.cn/Record.List -d "login_token=$login_token&domain_id=$domain_id" 2>/dev/null |
    while read_xml_dom; do
        if [ "$ENTITY" = 'item' ]; then
            itemlevel=$DOMLVL
            id=''
            name=''
        fi
        if [[ "$ENTITY" = '/item' ]] && [[ $DOMLVL < $itemlevel ]] ; then
            id=''
            name=''
        fi
        if [[ "$ENTITY" = 'id' ]] || [[ "$ENTITY" = 'name' ]]; then
            if [ "$ENTITY" = 'id' ]; then
                id=$CONTENT
            fi
            if [ "$ENTITY" = 'name' ]; then
                name=$CONTENT
            fi
            if [ "$name" = "$record" ]; then
                echo $id;
                return 0;
            fi
        fi
    done
}

. ./config.sh

domain_id=$(get_domain_id $login_token $domain)
record_id=$(get_record_id $login_token $record $domain_id)
if [ "$record_id" = '' ]; then
    echo '没有找到记录'
fi

echo "$record_id"
