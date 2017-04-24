#!/usr/bin/env bash

#==============基础函数==============

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

# Create (identifiable) temporary files
_mktemp() {
  # shellcheck disable=SC2068
  mktemp ${@:-} "${TMPDIR:-/tmp}/dehydrated-XXXXXX"
}

# Encode data as url-safe formatted base64
urlbase64() {
  # urlbase64: base64 encoded string with '+' replaced with '-' and '/' replaced with '_'
  openssl base64 -e | tr -d '\n\r' | _sed -e 's:=*$::g' -e 'y:+/:-_:'
}

# Different sed version for different os types...
_sed() {
  if [[ "${OSTYPE}" = "Linux" ]]; then
    sed -r "${@}"
  else
    sed -E "${@}"
  fi
}

# Remove newlines and whitespace from json
clean_json() {
  tr -d '\r\n' | _sed -e 's/ +/ /g' -e 's/\{ /{/g' -e 's/ \}/}/g' -e 's/\[ /[/g' -e 's/ \]/]/g'
}

# Get string value from json dictionary
get_json_string_value() {
  local filter
  filter=$(printf 's/.*"%s": *"\([^"]*\)".*/\\1/p' "$1")
  sed -n "${filter}"
}

rm_json_arrays() {
  local filter
  filter='s/\[[^][]*\]/null/g'
  # remove three levels of nested arrays
  sed -e "${filter}" -e "${filter}" -e "${filter}"
}

# Convert hex string to binary data
hex2bin() {
  # Remove spaces, add leading zero, escape as hex string and parse with printf
  printf -- "$(cat | _sed -e 's/[[:space:]]//g' -e 's/^(.(.{2})*)$/0\1/' -e 's/(.{2})/\\x\1/g')"
}

# OpenSSL writes to stderr/stdout even when there are no errors. So just
# display the output if the exit code was != 0 to simplify debugging.
_openssl() {
  set +e
  out="$(openssl "${@}" 2>&1)"
  res=$?
  set -e
  if [[ ${res} -ne 0 ]]; then
    echo "  + ERROR: failed to run $* (Exitcode: ${res})" >&2
    echo >&2
    echo "Details:" >&2
    echo "${out}" >&2
    echo >&2
    exit ${res}
  fi
}

# Send http(s) request with specified method
http_request() {
  tempcont="$(_mktemp)"

  if [[ -n "${IP_VERSION:-}" ]]; then
      ip_version="-${IP_VERSION}"
  fi

  set +e
  if [[ "${1}" = "head" ]]; then
    statuscode="$(curl ${ip_version:-} -s -w "%{http_code}" -o "${tempcont}" "${2}" -I)"
    curlret="${?}"
  elif [[ "${1}" = "get" ]]; then
    statuscode="$(curl ${ip_version:-} -s -w "%{http_code}" -o "${tempcont}" "${2}")"
    curlret="${?}"
  elif [[ "${1}" = "post" ]]; then
    statuscode="$(curl ${ip_version:-} -s -w "%{http_code}" -o "${tempcont}" "${2}" -d "${3}")"
    curlret="${?}"
  else
    set -e
    exiterr "未知请求方式: ${1}"
  fi
  set -e

  if [[ ! "${curlret}" = "0" ]]; then
    exiterr "连接服务器出错(方式：${1}，地址：${2}，返回${curlret})"
  fi

  if [[ ! "${statuscode:0:1}" = "2" ]]; then
    tempcontstr=$(cat "${tempcont}")
    rm -f "${tempcont}"
    exiterr "请求服务器出错(方式：${1}，地址：${2}，状态码：${statuscode})\n详情:\n${tempcontstr}"
  fi

  cat "${tempcont}"
  rm -f "${tempcont}"
}

# Send signed request
signed_request() {
  # Encode payload as urlbase64
  payload64="$(printf '%s' "${2}" | urlbase64)"

  # Retrieve nonce from acme-server
  nonce="$(http_request head "${CA}" | grep Replay-Nonce: | awk -F ': ' '{print $2}' | tr -d '\n\r')"

  # Build header with just our public key and algorithm information
  header='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}}'

  # Build another header which also contains the previously received nonce and encode it as urlbase64
  protected='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}, "nonce": "'"${nonce}"'"}'
  protected64="$(printf '%s' "${protected}" | urlbase64)"

  # Sign header with nonce and our payload with our private key and encode signature as urlbase64
  signed64="$(printf '%s' "${protected64}.${payload64}" | openssl dgst -sha256 -sign "${ACCOUNT_KEY}" | urlbase64)"

  # Send header + extended header + payload + signature to the acme-server
  data='{"header": '"${header}"', "protected": "'"${protected64}"'", "payload": "'"${payload64}"'", "signature": "'"${signed64}"'"}'

  http_request post "${1}" "${data}"
}

#==============DNSPOD==============

get_domain_id()
{
    login_token=$1
    domain=$2

    local DOMLVL=0 #初始化节点
    curl -k https://dnsapi.cn/Domain.List -d "login_token=$login_token" 2>/dev/null >./tmp/get_domain_id.xml
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
                id="$CONTENT"
            fi
            if [ "$ENTITY" = 'name' ]; then
                name="$CONTENT"
            fi
            if [ "$name" = "$domain" ]; then
                okid="$id";
            fi
        fi
        if [ "$ENTITY" = 'code' ]; then
            code="$CONTENT"
        fi
        if [ "$ENTITY" = 'message' ]; then
            message="$CONTENT"
        fi
    done < ./tmp/get_domain_id.xml

    if [ "$code" = '1' ]; then
        echo "$okid";
        return 0;
    else
        echo "$message";
        return $code;
    fi
}

get_record_id()
{
    login_token=$1
    domain_id=$2
    record=$3

    local DOMLVL=0 #初始化节点
    id=''
    name=''
    okid=''
    curl -k https://dnsapi.cn/Record.List -d "login_token=$login_token&domain_id=$domain_id" 2>/dev/null >./tmp/get_record_id.xml
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
                okid=$id;
            fi
        fi
        if [ "$ENTITY" = 'code' ]; then
            code=$CONTENT
        fi
        if [ "$ENTITY" = 'message' ]; then
            message="$CONTENT"
        fi
    done < ./tmp/get_record_id.xml

    if [ "$code" = '1' ]; then
        echo "$okid";
        return 0;
    else
        echo "$message";
        return $code;
    fi
}

create_record()
{
    login_token=$1
    domain_id=$2
    record=$3

    local DOMLVL=0 #初始化节点

    curl -k https://dnsapi.cn/Record.Create -d "login_token=$login_token&domain_id=$domain_id&sub_domain=$record&record_type=TXT&record_line=默认&value=null" 2>/dev/null >./tmp/create_record.xml
    while read_xml_dom; do
        if [ "$ENTITY" = 'id' ]; then
            id="$CONTENT"
        fi
        if [ "$ENTITY" = 'code' ]; then
            code=$CONTENT
        fi
        if [ "$ENTITY" = 'message' ]; then
            message="$CONTENT"
        fi
    done < ./tmp/create_record.xml

    if [ "$code" = '1' ]; then
        echo "$id";
        return 0;
    else
        echo "$message";
        return $code;
    fi
}

modify_record()
{
    login_token=$1
    domain_id=$2
    record_id=$3
    record=$4
    value=$5

    local DOMLVL=0 #初始化节点

    curl -k https://dnsapi.cn/Record.Modify -d "login_token=${login_token}&domain_id=${domain_id}&record_id=${record_id}&sub_domain=${record}&record_type=TXT&record_line=默认&value=${value}" 2>/dev/null >./tmp/modify_record.xml
    while read_xml_dom; do
        if [ "$ENTITY" = 'code' ]; then
            code=$CONTENT
        fi
        if [ "$ENTITY" = 'message' ]; then
            message="$CONTENT"
        fi
    done < ./tmp/modify_record.xml

    if [ "$code" = '1' ]; then
        return 0;
    else
        echo "$message";
        return $code;
    fi
}

#==============步骤==============

main()
{
  echo -n '读取配置...'
  loadcfg
  echo '[done]'

  echo -n '检查依赖...'
  check_dependencies
  echo '[done]'

  echo -n '初始化...'
  init
  echo '[done]'

  #检查帐号私钥
  echo -n '检查帐号私钥...'
  register_new_key="no" #用于判定是否是新生成的
  if [[ ! -e "${ACCOUNT_KEY}" ]]; then  #如果帐号私钥不存在则生成一个新的密钥（rsa密钥）
      echo '[null]'

      echo -n "生成新帐号密钥..."
      _openssl genrsa -out "${ACCOUNT_KEY}" "${KEYSIZE}"
      register_new_key="yes"
  fi
  openssl rsa -in "${ACCOUNT_KEY}" -check 2>/dev/null > /dev/null || exiterr "帐号私钥无效，请尝试删除account文件夹，重新生成帐号私钥"

  #从私钥获取公钥件并计算指纹
  pubExponent64="$(printf '%x' "$(openssl rsa -in "${ACCOUNT_KEY}" -noout -text | awk '/publicExponent/ {print $2}')" | hex2bin | urlbase64)"
  pubMod64="$(openssl rsa -in "${ACCOUNT_KEY}" -noout -modulus | cut -d'=' -f2 | hex2bin | urlbase64)"
  thumbprint="$(printf '{"e":"%s","kty":"RSA","n":"%s"}' "${pubExponent64}" "${pubMod64}" | openssl dgst -sha256 -binary | urlbase64)"

  echo '[done]'

  #如果刚刚密钥是新生成的，则必须在acme服务器注册
  if [[ "${register_new_key}" = "yes" ]]; then
      echo -n "在ACME服务器注册新帐号密钥..."
      [[ ! -z "${CA_NEW_REG}" ]] || exiterr "证书颁发机构不允许注册"
      
      if [[ -n "${CONTACT_EMAIL}" ]]; then  #如果提供了联系人的电子邮件，添加到注册请求
        request_str='{"resource": "new-reg", "contact":["mailto:'"${CONTACT_EMAIL}"'"], "agreement": "'"$LICENSE"'"}'
      else
        request_str='{"resource": "new-reg", "agreement": "'"$LICENSE"'"}'
      fi
      (signed_request "${CA_NEW_REG}" "${request_str}" > "${ACCOUNT_KEY_JSON}") || 
      (
        rm "${ACCOUNT_KEY}" "${ACCOUNT_KEY_JSON}"
        exiterr "注册帐号密钥错误"
      )
      echo '[done]'
  fi

  #dnspod请求
  echo -n '获取domain_id...'
  return=$(get_domain_id "$login_token" "$domain") || 
  {
      echo '[error]'
      exiterr "$return"
  }
  domain_id=$return
  echo "[$domain_id]"

  echo -n '获取record_id...'
  return=$(get_record_id "$login_token" "$domain_id" "_acme-challenge.$record") || 
  {
      echo '[error]'
      exiterr "$return"
  }
  record_id=$return
  if [ "$record_id" = '' ]; then
      echo '[null]'

      echo -n '没有找到对应record_id，创建新record并获取id...'
      return=$(create_record "$login_token" "$domain_id" "_acme-challenge.$record") || 
      {
          echo '[error]'
          exiterr "$return"
      }
      record_id=$return
      echo "[$record_id]"
  else
      echo "[$record_id]"
  fi



    

  HOOK="./hook.sh"
  CHALLENGETYPE="dns-01"
  PARAM_DOMAIN="${record}.${domain}"

  DOMAINS_TXT="${BASEDIR}/domains.txt"

  #开始生成证书
  ORIGIFS="${IFS}"
  IFS=$'\n'
  for line in $(<"${DOMAINS_TXT}" tr -d '\r' | tr '[:upper:]' '[:lower:]' | _sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g' -e 's/[[:space:]]+/ /g' | (grep -vE '^(#|$)' || true)); do
    IFS="${ORIGIFS}"
    domain="$(printf '%s\n' "${line}" | cut -d' ' -f1)"
    record="$(printf '%s\n' "${line}" | cut -s -d' ' -f2-)"
    morenames=$record
    cert="${CERTDIR}/${domain}/cert.pem"

    echo "处理[${domain} ${record}]"

    force_renew="no"
    if [[ -e "${cert}" ]]; then
      echo -n "检查变更..."

      certnames="$(openssl x509 -in "${cert}" -text -noout | grep DNS: | _sed 's/DNS://g' | tr -d ' ' | tr ',' '\n' | sort -u | tr '\n' ' ' | _sed 's/ $//')"
      givennames="$(echo "${record}"| tr ' ' '\n' | awk '{if($0=="@")print "'"${domain}"'";else print $0".'"${domain}"'"}' | sort -u | tr '\n' ' ' | _sed 's/ $//' | _sed 's/^ //')"

      if [[ "${certnames}" = "${givennames}" ]]; then
        echo "[unchanged]"
      else
        force_renew="yes"
        echo "[changed]"
      fi
    fi

    if [[ -e "${cert}" ]]; then
      echo -n "检查域名到期时间..."
      valid="$(openssl x509 -enddate -noout -in "${cert}" | cut -d= -f2- )"

      if openssl x509 -checkend $((RENEW_DAYS * 86400)) -noout -in "${cert}"; then
        echo "[${valid} 大于${RENEW_DAYS}天]"
      else
        force_renew="yes"
        echo "[${valid} 少于${RENEW_DAYS}天]"
      fi
    fi

    if [[ -e "${cert}" ]] && [[ "${force_renew}" = "yes" ]] || [[ ! -e "${cert}" ]]; then
      #开始签名域名
      altnames="$(echo "${record}"| tr ' ' '\n' | awk '{if($0=="@")print "'"${domain}"'";else print $0".'"${domain}"'"}' | tr '\n' ' ')"
      timestamp="$(date +%s)"

      echo "开始签名域名..."
      if [[ -z "${CA_NEW_AUTHZ}" ]] || [[ -z "${CA_NEW_CERT}" ]]; then
        exiterr "证书颁发机构不允许证书签名"
      fi

      if [[ ! -e "${CERTDIR}/${domain}" ]]; then
        echo -n "创建目录：${CERTDIR}/${domain}..."
        mkdir -p "${CERTDIR}/${domain}" || exiterr "创建失败${CERTDIR}/${domain}"
        echo "[done]"
      fi

      privkey="privkey.pem"
      if [[ ! -r "${CERTDIR}/${domain}/${privkey}" ]]; then  #如果老的私钥不存在或者不可写则生成新的私钥
        echo -n "生成私钥..."
        privkey="privkey-${timestamp}.pem"
        case "${KEY_ALGO}" in
          rsa) _openssl genrsa -out "${CERTDIR}/${domain}/${privkey}" "${KEYSIZE}";;
          prime256v1|secp384r1) _openssl ecparam -genkey -name "${KEY_ALGO}" -out "${CERTDIR}/${domain}/${privkey}";;
        esac
        echo "[done]"
      fi
      
      echo -n "生成cert.csr..."
      SAN=""
      for altname in ${altnames}; do
        SAN+="DNS:${altname}, "
      done
      SAN="${SAN%%, }"
      local tmp_openssl_cnf
      tmp_openssl_cnf="$(_mktemp)"
      cat "$(openssl version -d | cut -d\" -f2)/openssl.cnf" > "${tmp_openssl_cnf}"
      printf "[SAN]\nsubjectAltName=%s" "${SAN}" >> "${tmp_openssl_cnf}"
      openssl req -new -sha256 -key "${CERTDIR}/${domain}/${privkey}" -out "${CERTDIR}/${domain}/cert-${timestamp}.csr" -subj "/CN=${domain}/" -reqexts SAN -config "${tmp_openssl_cnf}"
      rm -f "${tmp_openssl_cnf}"
      echo "[done]"

      echo -n "生成cert.pem..."
      crt_path="${CERTDIR}/${domain}/cert-${timestamp}.pem"

#////////////////////////////////
      csr="$(cat "${CERTDIR}/${domain}/cert-${timestamp}.csr")"

      if [ -z "${altnames}" ]; then
        altnames="$( extract_altnames "${csr}" )"
      fi

      if [[ -z "${CA_NEW_AUTHZ}" ]] || [[ -z "${CA_NEW_CERT}" ]]; then
        _exiterr "Certificate authority doesn't allow certificate signing"
      fi

      local idx=0
      if [[ -n "${ZSH_VERSION:-}" ]]; then
        local -A challenge_altnames challenge_uris challenge_tokens keyauths deploy_args
      else
        local -a challenge_altnames challenge_uris challenge_tokens keyauths deploy_args
      fi

      # Request challenges
      for altname in ${altnames}; do
        # Ask the acme-server for new challenge token and extract them from the resulting json block
        echo " + Requesting challenge for ${altname}..."
        response="$(signed_request "${CA_NEW_AUTHZ}" '{"resource": "new-authz", "identifier": {"type": "dns", "value": "'"${altname}"'"}}' | clean_json)"

        challenge_status="$(printf '%s' "${response}" | rm_json_arrays | get_json_string_value status)"
        if [ "${challenge_status}" = "valid" ]; then
          echo " + Already validated!"
          continue
        fi

        challenges="$(printf '%s\n' "${response}" | sed -n 's/.*\("challenges":[^\[]*\[[^]]*]\).*/\1/p')"
        repl=$'\n''{' # fix syntax highlighting in Vim
        challenge="$(printf "%s" "${challenges//\{/${repl}}" | grep \""${CHALLENGETYPE}"\")"
        challenge_token="$(printf '%s' "${challenge}" | get_json_string_value token | _sed 's/[^A-Za-z0-9_\-]/_/g')"
        challenge_uri="$(printf '%s' "${challenge}" | get_json_string_value uri)"

        if [[ -z "${challenge_token}" ]] || [[ -z "${challenge_uri}" ]]; then
          _exiterr "Can't retrieve challenges (${response})"
        fi

        # Challenge response consists of the challenge token and the thumbprint of our public certificate
        keyauth="${challenge_token}.${thumbprint}"

        case "${CHALLENGETYPE}" in
          "dns-01")
            # Generate DNS entry content for dns-01 validation
            keyauth_hook="$(printf '%s' "${keyauth}" | openssl dgst -sha256 -binary | urlbase64)"
            ;;
        esac

        challenge_altnames[${idx}]="${altname}"
        challenge_uris[${idx}]="${challenge_uri}"
        keyauths[${idx}]="${keyauth}"
        challenge_tokens[${idx}]="${challenge_token}"
        # Note: assumes args will never have spaces!
        deploy_args[${idx}]="${altname} ${challenge_token} ${keyauth_hook}"
        idx=$((idx+1))
      done
      challenge_count="${idx}"

      # Wait for hook script to deploy the challenges if used
      if [[ ${challenge_count} -ne 0 ]]; then
        # shellcheck disable=SC2068
        [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" = "yes" ]] && . "${HOOK}" "deploy_challenge" ${deploy_args[@]}
      fi

      # Respond to challenges
      reqstatus="valid"
      idx=0
      if [ ${challenge_count} -ne 0 ]; then
        for altname in "${challenge_altnames[@]:0}"; do
          challenge_token="${challenge_tokens[${idx}]}"
          keyauth="${keyauths[${idx}]}"

          # Wait for hook script to deploy the challenge if used
          # shellcheck disable=SC2086
          [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && . "${HOOK}" "deploy_challenge" ${deploy_args[${idx}]}

          # Ask the acme-server to verify our challenge and wait until it is no longer pending
          echo " + Responding to challenge for ${altname}..."
          result="$(signed_request "${challenge_uris[${idx}]}" '{"resource": "challenge", "keyAuthorization": "'"${keyauth}"'"}' | clean_json)"

          reqstatus="$(printf '%s\n' "${result}" | get_json_string_value status)"

          while [[ "${reqstatus}" = "pending" ]]; do
            sleep 1
            result="$(http_request get "${challenge_uris[${idx}]}")"
            reqstatus="$(printf '%s\n' "${result}" | get_json_string_value status)"
          done

          # Wait for hook script to clean the challenge if used
          if [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && [[ -n "${challenge_token}" ]]; then
            # shellcheck disable=SC2086
            "${HOOK}" "clean_challenge" ${deploy_args[${idx}]}
          fi
          idx=$((idx+1))

          if [[ "${reqstatus}" = "valid" ]]; then
            echo " + Challenge is valid!"
          else
            [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && "${HOOK}" "invalid_challenge" "${altname}" "${result}"
          fi
        done
      fi

      # Wait for hook script to clean the challenges if used
      # shellcheck disable=SC2068
      if [[ ${challenge_count} -ne 0 ]]; then
        [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" = "yes" ]] && "${HOOK}" "clean_challenge" ${deploy_args[@]}
      fi

      if [[ "${reqstatus}" != "valid" ]]; then

        _exiterr "Challenge is invalid! (returned: ${reqstatus}) (result: ${result})"
      fi

      # Finally request certificate from the acme-server and store it in cert-${timestamp}.pem and link from cert.pem
      echo " + Requesting certificate..."
      csr64="$( <<<"${csr}" openssl req -outform DER | urlbase64)"
      crt64="$(signed_request "${CA_NEW_CERT}" '{"resource": "new-cert", "csr": "'"${csr64}"'"}' | openssl base64 -e)"
      crt="$( printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "${crt64}" )"

      # Try to load the certificate to detect corruption
      echo " + Checking certificate..."
      _openssl x509 -text <<<"${crt}"

      echo "${crt}" > "${crt_path}"

      unset challenge_token
      echo " + Done!"

#////////////////////////////////
      echo "[done]"

      # Create fullchain.pem
      echo -n "生成fullchain.pem..."
      cat "${crt_path}" > "${CERTDIR}/${domain}/fullchain-${timestamp}.pem"
      tmpchain="$(_mktemp)"
      http_request get "$(openssl x509 -in "${CERTDIR}/${domain}/cert-${timestamp}.pem" -noout -text | grep 'CA Issuers - URI:' | cut -d':' -f2-)" > "${tmpchain}"
      if grep -q "BEGIN CERTIFICATE" "${tmpchain}"; then
        mv "${tmpchain}" "${CERTDIR}/${domain}/chain-${timestamp}.pem"
      else
        openssl x509 -in "${tmpchain}" -inform DER -out "${CERTDIR}/${domain}/chain-${timestamp}.pem" -outform PEM
        rm "${tmpchain}"
      fi
      cat "${CERTDIR}/${domain}/chain-${timestamp}.pem" >> "${CERTDIR}/${domain}/fullchain-${timestamp}.pem"
      echo "[Done]"

      # Update symlinks
      echo -n "更新符号连接..."
      [[ "${privkey}" = "privkey.pem" ]] || ln -sf "privkey-${timestamp}.pem" "${CERTDIR}/${domain}/privkey.pem"
      ln -sf "chain-${timestamp}.pem" "${CERTDIR}/${domain}/chain.pem"
      ln -sf "fullchain-${timestamp}.pem" "${CERTDIR}/${domain}/fullchain.pem"
      ln -sf "cert-${timestamp}.csr" "${CERTDIR}/${domain}/cert.csr"
      ln -sf "cert-${timestamp}.pem" "${CERTDIR}/${domain}/cert.pem"
      echo "[Done]"

      unset challenge_token
    else
      echo "无须更新"
    fi
  done
}

loadcfg()
{
  #得到脚本所在目录
  SOURCE="${0}"
  while [ -h "$SOURCE" ]; do #循环解析符号链接
    DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" #如果是相对符号链接则应该合并
  done
  SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  BASEDIR="${SCRIPTDIR}"
  BASEDIR="${BASEDIR%%/}" #消除末尾斜杠
  [[ -d "${BASEDIR}" ]] || exiterr "BASEDIR获取错误: ${BASEDIR}" #获取完毕检查

  #读取配置文件
  . ${BASEDIR}/config.sh

  #CAHASH
  CAHASH="$(echo "${CA}" | urlbase64)"

  #临时文件夹
  [[ -z "${TMPDIR}" ]] && TMPDIR="${BASEDIR}/tmp"
  mkdir -p ${TMPDIR}
  #mktemp ${@:-} "${TMPDIR:-/tmp}/dehydrated-XXXXXX"

  #账户文件夹
  [[ -z "${ACCOUNTDIR}" ]] && ACCOUNTDIR="${BASEDIR}/accounts"
  mkdir -p "${ACCOUNTDIR}/${CAHASH}"
  ACCOUNT_KEY="${ACCOUNTDIR}/${CAHASH}/account_key.pem"
  ACCOUNT_KEY_JSON="${ACCOUNTDIR}/${CAHASH}/registration_info.json"

  #证书文件夹
  [[ -z "${CERTDIR}" ]] && CERTDIR="${BASEDIR}/certs"

  #domains.txt
  [[ -z "${DOMAINS_TXT}" ]] && DOMAINS_TXT="${BASEDIR}/domains.txt"

  #锁
  [[ -z "${LOCKFILE}" ]] && LOCKFILE="${BASEDIR}/lock"
  #检查和设定锁
  if [[ -n "${LOCKFILE}" ]]; then
    LOCKDIR="$(dirname "${LOCKFILE}")"
    [[ -w "${LOCKDIR}" ]] || exiterr "锁${LOCKFILE}的目录${LOCKDIR}不可写"
    ( set -C; date > "${LOCKFILE}" ) 2>/dev/null || exiterr "锁文件'${LOCKFILE}'存在"
    remove_lock() { rm -f "${LOCKFILE}"; }
    trap 'remove_lock' EXIT
  fi

  #OSTYPE获取
  OSTYPE="$(uname)"

  #IPversion检查
  if [[ -n "${IP_VERSION}" ]]; then
    [[ "${IP_VERSION}" = "4" || "${IP_VERSION}" = "6" ]] || exiterr "未知的IP版本 ${IP_VERSION}，请修改配置文件，在IP_VERSION输入4或者6。"
  fi

  #KEY_ALGO检查
  [[ "${KEY_ALGO}" =~ ^(rsa|prime256v1|secp384r1)$ ]] || exiterr "未知的公钥算法${KEY_ALGO}"

}

# Check for script dependencies
check_dependencies() {
  # just execute some dummy and/or version commands to see if required tools exist and are actually usable
  openssl version > /dev/null 2>&1 || exiterr "This script requires an openssl binary."
  _sed "" < /dev/null > /dev/null 2>&1 || exiterr "This script requires sed with support for extended (modern) regular expressions."
  command -v grep > /dev/null 2>&1 || exiterr "This script requires grep."
  _mktemp -u > /dev/null 2>&1 || exiterr "This script requires mktemp."
  diff -u /dev/null /dev/null || exiterr "This script requires diff."

  # curl returns with an error code in some ancient versions so we have to catch that
  set +e
  curl -V > /dev/null 2>&1
  retcode="$?"
  set -e
  if [[ ! "${retcode}" = "0" ]] && [[ ! "${retcode}" = "2" ]]; then
    exiterr "This script requires curl."
  fi
}

init() {
  #获取CA URLs
  CA_DIRECTORY="$(http_request get "${CA}")"
  CA_NEW_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-cert)" &&
  CA_NEW_AUTHZ="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-authz)" &&
  CA_NEW_REG="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-reg)" &&
  CA_REVOKE_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value revoke-cert)" ||
  exiterr "检索ACME/CA-URLs出现问题, 检查配置文件CA是否指向entrypoint的directory."
}

clean()
{
  :
  #清理
  #rm -rf ${TMPDIR}
}

exiterr() { #错误并退出
  echo "ERROR: ${1}" >&2
  clean
  exit 1
}

#====================================dehydrated
#!/usr/bin/env bash

# dehydrated by lukas2511
# Source: https://github.com/lukas2511/dehydrated
#
# This script is licensed under The MIT License (see LICENSE for more information).

set -e
set -u
set -o pipefail
[[ -n "${ZSH_VERSION:-}" ]] && set -o SH_WORD_SPLIT && set +o FUNCTION_ARGZERO
umask 077 # paranoid umask, we're creating private keys


# Print error message and exit with error
_exiterr() {
  echo "ERROR: ${1}" >&2
  exit 1
}

# Extracts all subject names from a CSR
# Outputs either the CN, or the SANs, one per line
extract_altnames() {
  csr="${1}" # the CSR itself (not a file)

  if ! <<<"${csr}" openssl req -verify -noout 2>/dev/null; then
    _exiterr "Certificate signing request isn't valid"
  fi

  reqtext="$( <<<"${csr}" openssl req -noout -text )"
  if <<<"${reqtext}" grep -q '^[[:space:]]*X509v3 Subject Alternative Name:[[:space:]]*$'; then
    # SANs used, extract these
    altnames="$( <<<"${reqtext}" grep -A1 '^[[:space:]]*X509v3 Subject Alternative Name:[[:space:]]*$' | tail -n1 )"
    # split to one per line:
    # shellcheck disable=SC1003
    altnames="$( <<<"${altnames}" _sed -e 's/^[[:space:]]*//; s/, /\'$'\n''/g' )"
    # we can only get DNS: ones signed
    if grep -qv '^DNS:' <<<"${altnames}"; then
      _exiterr "Certificate signing request contains non-DNS Subject Alternative Names"
    fi
    # strip away the DNS: prefix
    altnames="$( <<<"${altnames}" _sed -e 's/^DNS://' )"
    echo "${altnames}"

  else
    # No SANs, extract CN
    altnames="$( <<<"${reqtext}" grep '^[[:space:]]*Subject:' | _sed -e 's/.* CN=([^ /,]*).*/\1/' )"
    echo "${altnames}"
  fi
}

#====================================dehydrated






main
clean

exit 0
