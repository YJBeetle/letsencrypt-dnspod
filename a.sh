#!/usr/bin/env bash
#只适合解析简单xml，若属性值带有空格，注释中含有尖括号等，则无法解析
#下面情况可以正常解析
#0.<?xml version="1.0" encoding="utf-8"?>
#1.<test>Only For Test</test>
#2.<application
#      android:label="@string/app_name">
#3.<test/>
#4.<uses-permission android:name="android.permission.BLUETOOTH" />
#Attribute=Attribute Name
#VALUE=Attribute Value
#ELEMENT=Element Name
#CONTENT=Element Content

#接受一个int层级参数，层级从0开始
echo_tabs() {
    local tabs="";
    for((i = 0; i < $1; i++)); do
        tabs=$tabs'    ' #4个空格
    done
    echo -n "$tabs" #一定要加双引号
}

read_dom() {
    #备份IFS
    local oldIFS=$IFS

    local IFS=\> #字段分割符改为>
    read -d \< ENTITY CONTENT #read分隔符改为<
    local ret=$?
    local ELEMENT=''
    #第一次执行时，第一个字符为<.
    #所以read执行完毕，ENTITY和CONTENT都是空白符
    if [[ $ENTITY =~ ^[[:space:]]*$ ]] && [[ $CONTENT =~ ^[[:space:]]*$ ]]; then
        return $ret
    fi

    #第二次执行时，分为下面集中情况
    #0.<?xml version="1.0" encoding="utf-8"?>
    #此时read结果为?xml version="1.0" encoding="utf-8"?
    #CONTENT=若干空白符

    #1.<Size>1785</Size>
    #此时read结果为Size，所以ENTITY=Size，CONTENT='1785'
    #第三次read结为/Size，所以ENTITY=/Size，CONTENT=若干空白符

    #2.<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    #此时read结果为ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"，所以ENTITY=tListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"，CONTENT=同#1

    #3.<test/>
    #此时read结果为test/，所以ENTITY=test/，CONTENT=若干空白符

    #4.<test name="xyz" age="21"/>
    #此时read结果为test name="xyz" age="21"/，所以ENTITY=test name="xyz"/，CONTENT=若干空白符

    #5.<!--q1-->
    #此时read结果为!--q1--，所以ENTITY=!--q1--，CONTENT=''

    # ENTITY = ?xml version="1.0" encoding="utf-8"?
    #解析xml声明，并非普通节点，闭合方式与节点不同
    if [[ "$ENTITY" =~ ^\?xml[[:space:]]*(.*)\?$ ]]; then #使用正则去除问号和xml字符
        ENTITY=''
        ELEMENT='' #不是普通节点
        ATTRIBUTES="${BASH_REMATCH[1]}" #获取声明中的属性
    else #普通节点
        ELEMENT=${ENTITY%% *} #获取节点名称，如果ENTITY中有空格，则第一个空格前面部分即为节点名称
        ATTRIBUTES=${ENTITY#* } #获取节点所有属性，如果ENTITY中有空格，则第一个空格后面部分为所有属性(#2和#4，#4情况下，会多出/)
    fi

    if [[ "$ENTITY" = \!\[CDATA\[*\]\] ]]; then #不检查注释(#5)
        echo_tabs $[$tabCount - 1]
        echo CONTENT=${ELEMENT#*/} #删除/
        return 0
    fi

    if [[ "$ENTITY" = \!--*-- ]]; then #不检查注释(#5)
        return 0
    fi

    if [[ "$ELEMENT" = /* ]]; then #节点末尾 #1第三步
        tabCount=$[$tabCount - 1]
        echo_tabs $tabCount
        echo END ${ELEMENT#*/} #删除/
        return 0
    elif [[ "$ELEMENT" = */  ]] || [[ $ATTRIBUTES = */  ]]; then #3或#4
        empty=true #节点没有子节点，也没有value(自身为闭合标签)
        if [[ $ATTRIBUTES = */  ]]; then #如果是#4情况
            ATTRIBUTES=${ATTRIBUTES%*/} #将末尾的/删除，提取所有属性
        fi
        echo_tabs $tabCount
        echo -n ELEMENT=${ELEMENT%*/}' '
    elif [ ! "$ELEMENT" = '' ]; then #第一次执行时，ENTITY和CONTENT都是空串
        echo_tabs $tabCount
        echo -n ELEMENT="$ELEMENT"' ' #输出节点名
        tabCount=$[$tabCount + 1] #新节点
    else
        echo -n "XML declaration " #ELEMENT为空，不计算层级
    fi

    local empty=false #没有子节点，没有value
    IFS=$oldIFS #属性之间由空白符分割，恢复IFS，IFS默认为空格/换行/制表符
    local hasAttribute=false #节点是否有属性
    for a in $ATTRIBUTES; do #循环所有属性
        #echo ATTRIBUTES=$ATTRIBUTES '   -+-+-+-   '
        if [[ "$a" = *=* ]] #情况#2和#4
        then
            hasAttribute=true
            ATTRIBUTE_NAME=${a%%=*} #提取属性名
            ATTRIBUTE_VALUE=`tr -d '"' <<< ${a#*=}` #提取属性值并去掉双引号
            echo -n ATTRIBUTE=$ATTRIBUTE_NAME VALUE=$ATTRIBUTE_VALUE' ' #输出属性名/属性值
        fi
    done

    if [[ ! "$CONTENT" =~ ^[[:space:]]*$ ]]; then
        echo -n CONTENT=$CONTENT
    fi

    if [ "$empty" = true ]; then
        echo
        echo_tabs $tabCount
        echo -n END ${ELEMENT%/*} #删除/
#        echo -n ' (empty node)'
    fi

    echo
    return $ret
}

read_xml() {
    local tabCount=0 #用来格式化输出，计算节点层级
    while read_dom > /dev/null; do
        if [ "$ENTITY" = 'id' ]; then
            id=$CONTENT
        fi
        if [ "$ENTITY" = 'punycode' ]; then
            if [ "$CONTENT" = 'yjbeetle.com.cn' ]; then
                echo $id;
            fi
        fi
        :
    done < test.xml
}

read_xml
