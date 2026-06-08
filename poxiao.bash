#!/usr/bin/env bash
# 破晓 Bash Tab 补全

_poxiao_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan discover subdomain recon poc stealth util monitor verify report check"

    # 第一个参数: 命令补全
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    # 命令参数补全
    local cmd="${COMP_WORDS[1]}"
    case ${cmd} in
        scan)
            COMPREPLY=( $(compgen -W "-f --file --depth -c --concurrency --timeout --no-sensitive -o --output" -- ${cur}) )
            ;;
        poc)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "scan list history" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "scan" ]]; then
                COMPREPLY=( $(compgen -W "-t --templates --tags --severity -c --concurrency --timeout -o --output --stealth --proxies --qps --domain-qps --loop --interval --history" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "list" ]]; then
                COMPREPLY=( $(compgen -W "-t --templates --tags --severity" -- ${cur}) )
            fi
            ;;
        stealth)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "proxy-test check-waf gen-ua" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "gen-ua" ]]; then
                COMPREPLY=( $(compgen -W "-n --count --category" -- ${cur}) )
            fi
            ;;
        util)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "encode decode hash jwt-decode auto" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "encode" || "${COMP_WORDS[2]}" == "decode" ]]; then
                COMPREPLY=( $(compgen -W "base64 base32 base58 hex url url-full double-url html html-entity unicode rot13 morse" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "hash" ]]; then
                COMPREPLY=( $(compgen -W "md5 sha1 sha256 sha512" -- ${cur}) )
            fi
            ;;
        monitor)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "serve import stats" -- ${cur}) )
            fi
            ;;
        recon)
            COMPREPLY=( $(compgen -W "--quick --shodan-key --fofa-key --fofa-email -o --output --timeout" -- ${cur}) )
            ;;
        subdomain)
            COMPREPLY=( $(compgen -W "--no-crtsh --no-brute --no-alive -o --output" -- ${cur}) )
            ;;
        verify)
            COMPREPLY=( $(compgen -W "--from-scan" -- ${cur}) )
            ;;
    esac
    return 0
}

complete -F _poxiao_completions poxiao

