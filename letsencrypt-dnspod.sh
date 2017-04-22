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
    record=$2
    domain_id=$3

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
    record=$2
    domain_id=$3

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

#==============步骤==============

init()
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

  OSTYPE="$(uname)"
  
}

# Check for script dependencies
check_dependencies() {
  # just execute some dummy and/or version commands to see if required tools exist and are actually usable
  openssl version > /dev/null 2>&1 || _exiterr "This script requires an openssl binary."
  _sed "" < /dev/null > /dev/null 2>&1 || _exiterr "This script requires sed with support for extended (modern) regular expressions."
  command -v grep > /dev/null 2>&1 || _exiterr "This script requires grep."
  _mktemp -u > /dev/null 2>&1 || _exiterr "This script requires mktemp."
  diff -u /dev/null /dev/null || _exiterr "This script requires diff."

  # curl returns with an error code in some ancient versions so we have to catch that
  set +e
  curl -V > /dev/null 2>&1
  retcode="$?"
  set -e
  if [[ ! "${retcode}" = "0" ]] && [[ ! "${retcode}" = "2" ]]; then
    _exiterr "This script requires curl."
  fi
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


# Create (identifiable) temporary files
_mktemp() {
  # shellcheck disable=SC2068
  mktemp ${@:-} "${TMPDIR:-/tmp}/dehydrated-XXXXXX"
}


store_configvars() {
  __KEY_ALGO="${KEY_ALGO}"
  __OCSP_MUST_STAPLE="${OCSP_MUST_STAPLE}"
  __PRIVATE_KEY_RENEW="${PRIVATE_KEY_RENEW}"
  __KEYSIZE="${KEYSIZE}"
  __CHALLENGETYPE="${CHALLENGETYPE}"
  __HOOK="${HOOK}"
  __WELLKNOWN="${WELLKNOWN}"
  __HOOK_CHAIN="${HOOK_CHAIN}"
  __OPENSSL_CNF="${OPENSSL_CNF}"
  __RENEW_DAYS="${RENEW_DAYS}"
  __IP_VERSION="${IP_VERSION}"
}

reset_configvars() {
  KEY_ALGO="${__KEY_ALGO}"
  OCSP_MUST_STAPLE="${__OCSP_MUST_STAPLE}"
  PRIVATE_KEY_RENEW="${__PRIVATE_KEY_RENEW}"
  KEYSIZE="${__KEYSIZE}"
  CHALLENGETYPE="${__CHALLENGETYPE}"
  HOOK="${__HOOK}"
  WELLKNOWN="${__WELLKNOWN}"
  HOOK_CHAIN="${__HOOK_CHAIN}"
  OPENSSL_CNF="${__OPENSSL_CNF}"
  RENEW_DAYS="${__RENEW_DAYS}"
  IP_VERSION="${__IP_VERSION}"
}

# Setup default config values, search for and load configuration files
load_config() {

  [[ -z "${WELLKNOWN}" ]] && WELLKNOWN="/var/www/dehydrated"

  HOOK="./hook.sh"
  CHALLENGETYPE="dns-01"



  [[ "${KEY_ALGO}" =~ ^(rsa|prime256v1|secp384r1)$ ]] || _exiterr "Unknown public key algorithm ${KEY_ALGO}... can not continue."
  if [[ -n "${IP_VERSION}" ]]; then
    [[ "${IP_VERSION}" = "4" || "${IP_VERSION}" = "6" ]] || _exiterr "Unknown IP version ${IP_VERSION}... can not continue."
  fi


  store_configvars
}

# Initialize system
init_system() {
  load_config

  # Lockfile handling (prevents concurrent access)
  if [[ -n "${LOCKFILE}" ]]; then
    LOCKDIR="$(dirname "${LOCKFILE}")"
    [[ -w "${LOCKDIR}" ]] || _exiterr "Directory ${LOCKDIR} for LOCKFILE ${LOCKFILE} is not writable, aborting."
    ( set -C; date > "${LOCKFILE}" ) 2>/dev/null || _exiterr "Lock file '${LOCKFILE}' present, aborting."
    remove_lock() { rm -f "${LOCKFILE}"; }
    trap 'remove_lock' EXIT
  fi

  # Get CA URLs
  CA_DIRECTORY="$(http_request get "${CA}")"
  CA_NEW_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-cert)" &&
  CA_NEW_AUTHZ="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-authz)" &&
  CA_NEW_REG="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-reg)" &&
  # shellcheck disable=SC2015
  CA_REVOKE_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value revoke-cert)" ||
  _exiterr "Problem retrieving ACME/CA-URLs, check if your configured CA points to the directory entrypoint."

  # Export some environment variables to be used in hook script
  export WELLKNOWN BASEDIR CERTDIR CONFIG

  # Checking for private key ...
  register_new_key="no"
  if [[ -n "${PARAM_ACCOUNT_KEY:-}" ]]; then
    # a private key was specified from the command line so use it for this run
    echo "Using private key ${PARAM_ACCOUNT_KEY} instead of account key"
    ACCOUNT_KEY="${PARAM_ACCOUNT_KEY}"
    ACCOUNT_KEY_JSON="${PARAM_ACCOUNT_KEY}.json"
  else
    # Check if private account key exists, if it doesn't exist yet generate a new one (rsa key)
    if [[ ! -e "${ACCOUNT_KEY}" ]]; then
      echo "+ Generating account key..."
      _openssl genrsa -out "${ACCOUNT_KEY}" "${KEYSIZE}"
      register_new_key="yes"
    fi
  fi
  openssl rsa -in "${ACCOUNT_KEY}" -check 2>/dev/null > /dev/null || _exiterr "Account key is not valid, can not continue."

  # Get public components from private key and calculate thumbprint
  pubExponent64="$(printf '%x' "$(openssl rsa -in "${ACCOUNT_KEY}" -noout -text | awk '/publicExponent/ {print $2}')" | hex2bin | urlbase64)"
  pubMod64="$(openssl rsa -in "${ACCOUNT_KEY}" -noout -modulus | cut -d'=' -f2 | hex2bin | urlbase64)"

  thumbprint="$(printf '{"e":"%s","kty":"RSA","n":"%s"}' "${pubExponent64}" "${pubMod64}" | openssl dgst -sha256 -binary | urlbase64)"

  # If we generated a new private key in the step above we have to register it with the acme-server
  if [[ "${register_new_key}" = "yes" ]]; then
    echo "+ Registering account key with ACME server..."
    [[ ! -z "${CA_NEW_REG}" ]] || _exiterr "Certificate authority doesn't allow registrations."
    # If an email for the contact has been provided then adding it to the registration request
    FAILED=false
    if [[ -n "${CONTACT_EMAIL}" ]]; then
      (signed_request "${CA_NEW_REG}" '{"resource": "new-reg", "contact":["mailto:'"${CONTACT_EMAIL}"'"], "agreement": "'"$LICENSE"'"}' > "${ACCOUNT_KEY_JSON}") || FAILED=true
    else
      (signed_request "${CA_NEW_REG}" '{"resource": "new-reg", "agreement": "'"$LICENSE"'"}' > "${ACCOUNT_KEY_JSON}") || FAILED=true
    fi
    if [[ "${FAILED}" = "true" ]]; then
      echo
      echo
      echo "Error registering account key. See message above for more information."
      rm "${ACCOUNT_KEY}" "${ACCOUNT_KEY_JSON}"
      exit 1
    fi
  fi

}


# Print error message and exit with error
_exiterr() {
  echo "ERROR: ${1}" >&2
  exit 1
}

# Remove newlines and whitespace from json
clean_json() {
  tr -d '\r\n' | _sed -e 's/ +/ /g' -e 's/\{ /{/g' -e 's/ \}/}/g' -e 's/\[ /[/g' -e 's/ \]/]/g'
}


# Convert hex string to binary data
hex2bin() {
  # Remove spaces, add leading zero, escape as hex string and parse with printf
  printf -- "$(cat | _sed -e 's/[[:space:]]//g' -e 's/^(.(.{2})*)$/0\1/' -e 's/(.{2})/\\x\1/g')"
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
    _exiterr "Unknown request method: ${1}"
  fi
  set -e

  if [[ ! "${curlret}" = "0" ]]; then
    _exiterr "Problem connecting to server (${1} for ${2}; curl returned with ${curlret})"
  fi

  if [[ ! "${statuscode:0:1}" = "2" ]]; then
    echo "  + ERROR: An error occurred while sending ${1}-request to ${2} (Status ${statuscode})" >&2
    echo >&2
    echo "Details:" >&2
    cat "${tempcont}" >&2
    echo >&2
    echo >&2

    # An exclusive hook for the {1}-request error might be useful (e.g., for sending an e-mail to admins)
    if [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]]; then
      errtxt=`cat ${tempcont}`
      "${HOOK}" "request_failure" "${statuscode}" "${errtxt}" "${1}"
    fi

    rm -f "${tempcont}"

    # Wait for hook script to clean the challenge if used
    if [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && [[ -n "${challenge_token:+set}" ]]; then
      "${HOOK}" "clean_challenge" '' "${challenge_token}" "${keyauth}"
    fi

    # remove temporary domains.txt file if used
    [[ -n "${PARAM_DOMAIN:-}" && -n "${DOMAINS_TXT:-}" ]] && rm "${DOMAINS_TXT}"
    exit 1
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

# Create certificate for domain(s) and outputs it FD 3
sign_csr() {
  csr="${1}" # the CSR itself (not a file)

  if { true >&3; } 2>/dev/null; then
    : # fd 3 looks OK
  else
    _exiterr "sign_csr: FD 3 not open"
  fi

  shift 1 || true
  altnames="${*:-}"
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
      "http-01")
        # Store challenge response in well-known location and make world-readable (so that a webserver can access it)
        printf '%s' "${keyauth}" > "${WELLKNOWN}/${challenge_token}"
        chmod a+r "${WELLKNOWN}/${challenge_token}"
        keyauth_hook="${keyauth}"
        ;;
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
    [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" = "yes" ]] && "${HOOK}" "deploy_challenge" ${deploy_args[@]}
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
      [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && "${HOOK}" "deploy_challenge" ${deploy_args[${idx}]}

      # Ask the acme-server to verify our challenge and wait until it is no longer pending
      echo " + Responding to challenge for ${altname}..."
      result="$(signed_request "${challenge_uris[${idx}]}" '{"resource": "challenge", "keyAuthorization": "'"${keyauth}"'"}' | clean_json)"

      reqstatus="$(printf '%s\n' "${result}" | get_json_string_value status)"

      while [[ "${reqstatus}" = "pending" ]]; do
        sleep 1
        result="$(http_request get "${challenge_uris[${idx}]}")"
        reqstatus="$(printf '%s\n' "${result}" | get_json_string_value status)"
      done

      [[ "${CHALLENGETYPE}" = "http-01" ]] && rm -f "${WELLKNOWN}/${challenge_token}"

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
    # Clean up any remaining challenge_tokens if we stopped early
    if [[ "${CHALLENGETYPE}" = "http-01" ]] && [[ ${challenge_count} -ne 0 ]]; then
      while [ ${idx} -lt ${#challenge_tokens[@]} ]; do
        rm -f "${WELLKNOWN}/${challenge_tokens[${idx}]}"
        idx=$((idx+1))
      done
    fi

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

  echo "${crt}" >&3

  unset challenge_token
  echo " + Done!"
}

# Create certificate for domain(s)
sign_domain() {
  domain="${1}"
  altnames="${*}"
  timestamp="$(date +%s)"

  echo " + Signing domains..."
  if [[ -z "${CA_NEW_AUTHZ}" ]] || [[ -z "${CA_NEW_CERT}" ]]; then
    _exiterr "Certificate authority doesn't allow certificate signing"
  fi

  # If there is no existing certificate directory => make it
  if [[ ! -e "${CERTDIR}/${domain}" ]]; then
    echo " + Creating new directory ${CERTDIR}/${domain} ..."
    mkdir -p "${CERTDIR}/${domain}" || _exiterr "Unable to create directory ${CERTDIR}/${domain}"
  fi

  privkey="privkey.pem"
  # generate a new private key if we need or want one
  if [[ ! -r "${CERTDIR}/${domain}/privkey.pem" ]] || [[ "${PRIVATE_KEY_RENEW}" = "yes" ]]; then
    echo " + Generating private key..."
    privkey="privkey-${timestamp}.pem"
    case "${KEY_ALGO}" in
      rsa) _openssl genrsa -out "${CERTDIR}/${domain}/privkey-${timestamp}.pem" "${KEYSIZE}";;
      prime256v1|secp384r1) _openssl ecparam -genkey -name "${KEY_ALGO}" -out "${CERTDIR}/${domain}/privkey-${timestamp}.pem";;
    esac
  fi
  # move rolloverkey into position (if any)
  if [[ -r "${CERTDIR}/${domain}/privkey.pem" && -r "${CERTDIR}/${domain}/privkey.roll.pem" && "${PRIVATE_KEY_RENEW}" = "yes" && "${PRIVATE_KEY_ROLLOVER}" = "yes" ]]; then
    echo " + Moving Rolloverkey into position....  "
    mv "${CERTDIR}/${domain}/privkey.roll.pem" "${CERTDIR}/${domain}/privkey-tmp.pem"
    mv "${CERTDIR}/${domain}/privkey-${timestamp}.pem" "${CERTDIR}/${domain}/privkey.roll.pem"
    mv "${CERTDIR}/${domain}/privkey-tmp.pem" "${CERTDIR}/${domain}/privkey-${timestamp}.pem"
  fi
  # generate a new private rollover key if we need or want one
  if [[ ! -r "${CERTDIR}/${domain}/privkey.roll.pem" && "${PRIVATE_KEY_ROLLOVER}" = "yes" && "${PRIVATE_KEY_RENEW}" = "yes" ]]; then
    echo " + Generating private rollover key..."
    case "${KEY_ALGO}" in
      rsa) _openssl genrsa -out "${CERTDIR}/${domain}/privkey.roll.pem" "${KEYSIZE}";;
      prime256v1|secp384r1) _openssl ecparam -genkey -name "${KEY_ALGO}" -out "${CERTDIR}/${domain}/privkey.roll.pem";;
    esac
  fi
  # delete rolloverkeys if disabled
  if [[ -r "${CERTDIR}/${domain}/privkey.roll.pem" && ! "${PRIVATE_KEY_ROLLOVER}" = "yes" ]]; then
    echo " + Removing Rolloverkey (feature disabled)..."
    rm -f "${CERTDIR}/${domain}/privkey.roll.pem"
  fi

  # Generate signing request config and the actual signing request
  echo " + Generating signing request..."
  SAN=""
  for altname in ${altnames}; do
    SAN+="DNS:${altname}, "
  done
  SAN="${SAN%%, }"
  local tmp_openssl_cnf
  tmp_openssl_cnf="$(_mktemp)"
  cat "${OPENSSL_CNF}" > "${tmp_openssl_cnf}"
  printf "[SAN]\nsubjectAltName=%s" "${SAN}" >> "${tmp_openssl_cnf}"
  if [ "${OCSP_MUST_STAPLE}" = "yes" ]; then
    printf "\n1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05" >> "${tmp_openssl_cnf}"
  fi
  openssl req -new -sha256 -key "${CERTDIR}/${domain}/${privkey}" -out "${CERTDIR}/${domain}/cert-${timestamp}.csr" -subj "/CN=${domain}/" -reqexts SAN -config "${tmp_openssl_cnf}"
  rm -f "${tmp_openssl_cnf}"

  crt_path="${CERTDIR}/${domain}/cert-${timestamp}.pem"
  # shellcheck disable=SC2086
  sign_csr "$(< "${CERTDIR}/${domain}/cert-${timestamp}.csr" )" ${altnames} 3>"${crt_path}"

  # Create fullchain.pem
  echo " + Creating fullchain.pem..."
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

  # Update symlinks
  [[ "${privkey}" = "privkey.pem" ]] || ln -sf "privkey-${timestamp}.pem" "${CERTDIR}/${domain}/privkey.pem"

  ln -sf "chain-${timestamp}.pem" "${CERTDIR}/${domain}/chain.pem"
  ln -sf "fullchain-${timestamp}.pem" "${CERTDIR}/${domain}/fullchain.pem"
  ln -sf "cert-${timestamp}.csr" "${CERTDIR}/${domain}/cert.csr"
  ln -sf "cert-${timestamp}.pem" "${CERTDIR}/${domain}/cert.pem"

  # Wait for hook script to clean the challenge and to deploy cert if used
  export KEY_ALGO
  [[ -n "${HOOK}" ]] && "${HOOK}" "deploy_cert" "${domain}" "${CERTDIR}/${domain}/privkey.pem" "${CERTDIR}/${domain}/cert.pem" "${CERTDIR}/${domain}/fullchain.pem" "${CERTDIR}/${domain}/chain.pem" "${timestamp}"

  unset challenge_token
  echo " + Done!"
}

# Usage: --cron (-c)
# Description: Sign/renew non-existant/changed/expiring certificates.
command_sign_domains() {
  init_system

  if [[ -n "${PARAM_DOMAIN:-}" ]]; then
    DOMAINS_TXT="$(_mktemp)"
    printf -- "${PARAM_DOMAIN}" > "${DOMAINS_TXT}"
  elif [[ -e "${DOMAINS_TXT}" ]]; then
    if [[ ! -r "${DOMAINS_TXT}" ]]; then
      _exiterr "domains.txt found but not readable"
    fi
  else
    _exiterr "domains.txt not found and --domain not given"
  fi

  # Generate certificates for all domains found in domains.txt. Check if existing certificate are about to expire
  ORIGIFS="${IFS}"
  IFS=$'\n'
  for line in $(<"${DOMAINS_TXT}" tr -d '\r' | tr '[:upper:]' '[:lower:]' | _sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g' -e 's/[[:space:]]+/ /g' | (grep -vE '^(#|$)' || true)); do
    reset_configvars
    IFS="${ORIGIFS}"
    domain="$(printf '%s\n' "${line}" | cut -d' ' -f1)"
    morenames="$(printf '%s\n' "${line}" | cut -s -d' ' -f2-)"
    cert="${CERTDIR}/${domain}/cert.pem"

    force_renew="${PARAM_FORCE:-no}"

    if [[ -z "${morenames}" ]];then
      echo "Processing ${domain}"
    else
      echo "Processing ${domain} with alternative names: ${morenames}"
    fi

    # read cert config
    # for now this loads the certificate specific config in a subshell and parses a diff of set variables.
    # we could just source the config file but i decided to go this way to protect people from accidentally overriding
    # variables used internally by this script itself.
    if [[ -n "${DOMAINS_D}" ]]; then
      certconfig="${DOMAINS_D}/${domain}"
    else
      certconfig="${CERTDIR}/${domain}/config"
    fi

    if [ -f "${certconfig}" ]; then
      echo " + Using certificate specific config file!"
      ORIGIFS="${IFS}"
      IFS=$'\n'
      for cfgline in $(
        beforevars="$(_mktemp)"
        aftervars="$(_mktemp)"
        set > "${beforevars}"
        # shellcheck disable=SC1090
        . "${certconfig}"
        set > "${aftervars}"
        diff -u "${beforevars}" "${aftervars}" | grep -E '^\+[^+]'
        rm "${beforevars}"
        rm "${aftervars}"
      ); do
        config_var="$(echo "${cfgline:1}" | cut -d'=' -f1)"
        config_value="$(echo "${cfgline:1}" | cut -d'=' -f2-)"
        case "${config_var}" in
          KEY_ALGO|OCSP_MUST_STAPLE|PRIVATE_KEY_RENEW|PRIVATE_KEY_ROLLOVER|KEYSIZE|CHALLENGETYPE|HOOK|WELLKNOWN|HOOK_CHAIN|OPENSSL_CNF|RENEW_DAYS)
            echo "   + ${config_var} = ${config_value}"
            declare -- "${config_var}=${config_value}"
            ;;
          _) ;;
          *) echo "   ! Setting ${config_var} on a per-certificate base is not (yet) supported"
        esac
      done
      IFS="${ORIGIFS}"
    fi
    #verify_config

    if [[ -e "${cert}" ]]; then
      printf " + Checking domain name(s) of existing cert..."

      certnames="$(openssl x509 -in "${cert}" -text -noout | grep DNS: | _sed 's/DNS://g' | tr -d ' ' | tr ',' '\n' | sort -u | tr '\n' ' ' | _sed 's/ $//')"
      givennames="$(echo "${domain}" "${morenames}"| tr ' ' '\n' | sort -u | tr '\n' ' ' | _sed 's/ $//' | _sed 's/^ //')"

      if [[ "${certnames}" = "${givennames}" ]]; then
        echo " unchanged."
      else
        echo " changed!"
        echo " + Domain name(s) are not matching!"
        echo " + Names in old certificate: ${certnames}"
        echo " + Configured names: ${givennames}"
        echo " + Forcing renew."
        force_renew="yes"
      fi
    fi

    if [[ -e "${cert}" ]]; then
      echo " + Checking expire date of existing cert..."
      valid="$(openssl x509 -enddate -noout -in "${cert}" | cut -d= -f2- )"

      printf " + Valid till %s " "${valid}"
      if openssl x509 -checkend $((RENEW_DAYS * 86400)) -noout -in "${cert}"; then
        printf "(Longer than %d days). " "${RENEW_DAYS}"
        if [[ "${force_renew}" = "yes" ]]; then
          echo "Ignoring because renew was forced!"
        else
          # Certificate-Names unchanged and cert is still valid
          echo "Skipping renew!"
          [[ -n "${HOOK}" ]] && "${HOOK}" "unchanged_cert" "${domain}" "${CERTDIR}/${domain}/privkey.pem" "${CERTDIR}/${domain}/cert.pem" "${CERTDIR}/${domain}/fullchain.pem" "${CERTDIR}/${domain}/chain.pem"
          continue
        fi
      else
        echo "(Less than ${RENEW_DAYS} days). Renewing!"
      fi
    fi

    # shellcheck disable=SC2086
    if [[ "${PARAM_KEEP_GOING:-}" = "yes" ]]; then
      sign_domain ${line} &
      wait $! || true
    else
      sign_domain ${line}
    fi
  done

  # remove temporary domains.txt file if used
  [[ -n "${PARAM_DOMAIN:-}" ]] && rm -f "${DOMAINS_TXT}"

  exit 0
}







echo -n '初始化...'
init
echo '[done]'

echo -n '检查依赖...'
check_dependencies
echo '[done]'


echo -n '获取domain_id...'
return=$(get_domain_id "$login_token" "$domain") || 
{
    echo '[error]'
    exiterr "$return"
}
domain_id=$return
echo "[$domain_id]"

echo -n '获取record_id...'
return=$(get_record_id "$login_token" "_acme-challenge.$record" "$domain_id") || 
{
    echo '[error]'
    exiterr "$return"
}
record_id=$return
if [ "$record_id" = '' ]; then
    echo '[null]'

    echo -n '没有找到对应record_id，创建新record并获取id...'
    return=$(create_record "$login_token" "_acme-challenge.$record" "$domain_id") || 
    {
        echo '[error]'
        exiterr "$return"
    }
    record_id=$return
    echo "[$record_id]"
else
    echo "[$record_id]"
fi





export domain_id
export record_id




PARAM_DOMAIN="${record}.${domain}"
command_sign_domains




clean
exit 0
