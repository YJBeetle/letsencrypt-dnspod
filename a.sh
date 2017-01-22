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
    domain=$1

    local DOMLVL=0 #初始化节点
    cat domain.xml |
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
    record=$1

    local DOMLVL=0 #初始化节点
    cat record.xml |
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

echo $(get_domain_id 'yjbeetle.com.cn')
echo $(get_record_id '_acme-challenge.home')
