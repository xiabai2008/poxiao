#!/usr/bin/env python3
"""
破晓 Tab 补全脚本
==================
支持 Bash/Zsh/Fish 的命令自动补全

安装方法:
  Bash:  eval "$(python poxiao_completion.py bash)"
  Zsh:   eval "$(python poxiao_completion.py zsh)"
  Fish:  python poxiao_completion.py fish > ~/.config/fish/completions/poxiao.fish
"""

import sys


# ── 命令和子命令定义 ─────────────────────────────────

COMMANDS = {
    "scan": {
        "args": ["-f", "--file", "--depth", "-c", "--concurrency", "--timeout", "--no-sensitive", "-o", "--output"],
        "values": {"--depth": ["normal", "full"]},
    },
    "discover": {
        "args": ["-f", "--file", "-o", "--output", "--search"],
    },
    "subdomain": {
        "args": ["--no-crtsh", "--no-brute", "--no-alive", "-o", "--output"],
    },
    "recon": {
        "args": ["--quick", "--shodan-key", "--fofa-key", "--fofa-email", "-o", "--output", "--timeout"],
    },
    "poc": {
        "subcommands": {
            "scan": {
                "args": ["-t", "--templates", "--tags", "--severity", "-c", "--concurrency",
                         "--timeout", "-o", "--output", "--stealth", "--proxies", "--qps",
                         "--domain-qps", "--loop", "--interval", "--history"],
                "values": {"--severity": ["critical", "high", "medium", "low", "info"]},
            },
            "list": {
                "args": ["-t", "--templates", "--tags", "--severity"],
                "values": {"--severity": ["critical", "high", "medium", "low", "info"]},
            },
            "history": {
                "args": ["--findings", "--only-new"],
            },
        },
    },
    "stealth": {
        "subcommands": {
            "proxy-test": {
                "args": ["--timeout", "-c", "--concurrency"],
            },
            "check-waf": {
                "args": ["--timeout"],
            },
            "gen-ua": {
                "args": ["-n", "--count", "--category"],
                "values": {"--category": ["random", "chrome", "firefox", "safari", "edge", "mobile", "cn"]},
            },
        },
    },
    "util": {
        "subcommands": {
            "encode": {
                "values": {"type": ["base64", "base32", "base58", "hex", "url", "url-full",
                                   "double-url", "html", "html-entity", "unicode", "rot13", "morse"]},
            },
            "decode": {
                "values": {"type": ["base64", "base32", "base58", "hex", "url", "url-full",
                                   "double-url", "html", "html-entity", "unicode", "rot13", "morse"]},
            },
            "hash": {
                "values": {"type": ["md5", "sha1", "sha256", "sha512"]},
            },
            "jwt-decode": {},
            "auto": {},
        },
    },
    "monitor": {
        "subcommands": {
            "serve": {},
            "import": {},
            "stats": {},
        },
    },
    "verify": {
        "args": ["--from-scan"],
    },
    "report": {
        "args": ["-o", "--output"],
    },
    "check": {
        "args": ["-c", "--concurrency"],
    },
}


def generate_bash():
    """生成 Bash 补全脚本"""
    script = '''#!/usr/bin/env bash
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
'''
    return script


def generate_zsh():
    """生成 Zsh 补全脚本"""
    script = '''#compdef poxiao
# 破晓 Zsh Tab 补全

_poxiao() {
    local -a commands
    commands=(
        'scan:扫描目标'
        'discover:公司名→域名发现'
        'subdomain:子域名收集'
        'recon:被动信息收集'
        'poc:POC模板漏洞扫描'
        'stealth:反封禁&代理池'
        'util:编解码工具'
        'monitor:资产监控'
        'verify:漏洞验证'
        'report:生成报告'
        'check:存活检测'
    )

    _arguments -C \\
        '1:command:->commands' \\
        '*::arg:->args'

    case $state in
        commands)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                poc)
                    _poxiao_poc
                    ;;
                stealth)
                    _poxiao_stealth
                    ;;
                util)
                    _poxiao_util
                    ;;
                monitor)
                    _poxiao_monitor
                    ;;
                scan)
                    _arguments \\
                        '(-f --file)'{-f,--file}'[目标文件]' \\
                        '--depth[扫描深度]:depth:(normal full)' \\
                        '(-c --concurrency)'{-c,--concurrency}'[并发数]' \\
                        '--timeout[超时秒数]' \\
                        '--no-sensitive[跳过敏感路径]' \\
                        '(-o --output)'{-o,--output}'[输出目录]'
                    ;;
                recon)
                    _arguments \\
                        '--quick[快速模式]' \\
                        '--shodan-key[Shodan API Key]' \\
                        '(-o --output)'{-o,--output}'[输出路径]' \\
                        '--timeout[超时秒数]'
                    ;;
                subdomain)
                    _arguments \\
                        '--no-crtsh[跳过crt.sh]' \\
                        '--no-brute[跳过DNS爆破]' \\
                        '--no-alive[跳过存活验证]' \\
                        '(-o --output)'{-o,--output}'[输出文件]'
                    ;;
                verify)
                    _arguments \\
                        '--from-scan[从扫描结果验证]'
                    ;;
            esac
            ;;
    esac
}

_poxiao_poc() {
    local -a subcmds
    subcmds=(
        'scan:扫描目标'
        'list:列出模板'
        'history:查看历史'
    )
    _arguments -C '1:subcommand:->subcmds' '*::arg:->subargs'
    case $state in
        subcmds)
            _describe 'subcommand' subcmds
            ;;
        subargs)
            case $words[1] in
                scan)
                    _arguments \\
                        '(-t --templates)'{-t,--templates}'[模板目录]' \\
                        '--tags[标签过滤]' \\
                        '--severity[严重级别]:severity:(critical high medium low info)' \\
                        '(-c --concurrency)'{-c,--concurrency}'[并发数]' \\
                        '--timeout[超时秒数]' \\
                        '(-o --output)'{-o,--output}'[输出路径]' \\
                        '--stealth[隐匿模式]' \\
                        '--proxies[代理文件]' \\
                        '--loop[持续扫描]' \\
                        '--interval[扫描间隔]' \\
                        '--history[历史对比]'
                    ;;
                list)
                    _arguments \\
                        '(-t --templates)'{-t,--templates}'[模板目录]' \\
                        '--tags[标签过滤]' \\
                        '--severity[严重级别]:severity:(critical high medium low info)'
                    ;;
                history)
                    _arguments \\
                        '--findings[显示详情]' \\
                        '--only-new[仅新增]'
                    ;;
            esac
            ;;
    esac
}

_poxiao_stealth() {
    local -a subcmds
    subcmds=(
        'proxy-test:测试代理'
        'check-waf:检测WAF'
        'gen-ua:生成UA'
    )
    _arguments -C '1:subcommand:->subcmds' '*::arg:->subargs'
    case $state in
        subcmds)
            _describe 'subcommand' subcmds
            ;;
        subargs)
            case $words[1] in
                gen-ua)
                    _arguments \\
                        '(-n --count)'{-n,--count}'[数量]' \\
                        '--category[类型]:category:(random chrome firefox safari edge mobile cn)'
                    ;;
                check-waf)
                    _arguments '--timeout[超时秒数]'
                    ;;
                proxy-test)
                    _arguments \\
                        '--timeout[超时秒数]' \\
                        '(-c --concurrency)'{-c,--concurrency}'[并发数]'
                    ;;
            esac
            ;;
    esac
}

_poxiao_util() {
    local -a subcmds
    subcmds=(
        'encode:编码'
        'decode:解码'
        'hash:哈希'
        'jwt-decode:JWT解码'
        'auto:自动识别'
    )
    _arguments -C '1:subcommand:->subcmds' '*::arg:->subargs'
    case $state in
        subcmds)
            _describe 'subcommand' subcmds
            ;;
        subargs)
            case $words[1] in
                encode|decode)
                    _arguments '1:type:(base64 base32 base58 hex url url-full double-url html html-entity unicode rot13 morse)' '2:text:'
                    ;;
                hash)
                    _arguments '1:type:(md5 sha1 sha256 sha512)' '2:text:'
                    ;;
                jwt-decode)
                    _arguments '1:token:'
                    ;;
                auto)
                    _arguments '1:text:'
                    ;;
            esac
            ;;
    esac
}

_poxiao_monitor() {
    local -a subcmds
    subcmds=(
        'serve:启动Web面板'
        'import:导入扫描结果'
        'stats:查看统计'
    )
    _describe 'subcommand' subcmds
}

_poxiao "$@"
'''
    return script


def generate_fish():
    """生成 Fish 补全脚本"""
    script = '''# 破晓 Fish Tab 补全

# 主命令
complete -c poxiao -f
complete -c poxiao -n '__fish_use_subcommand' -a scan -d '扫描目标'
complete -c poxiao -n '__fish_use_subcommand' -a discover -d '公司名→域名发现'
complete -c poxiao -n '__fish_use_subcommand' -a subdomain -d '子域名收集'
complete -c poxiao -n '__fish_use_subcommand' -a recon -d '被动信息收集'
complete -c poxiao -n '__fish_use_subcommand' -a poc -d 'POC模板漏洞扫描'
complete -c poxiao -n '__fish_use_subcommand' -a stealth -d '反封禁&代理池'
complete -c poxiao -n '__fish_use_subcommand' -a util -d '编解码工具'
complete -c poxiao -n '__fish_use_subcommand' -a monitor -d '资产监控'
complete -c poxiao -n '__fish_use_subcommand' -a verify -d '漏洞验证'
complete -c poxiao -n '__fish_use_subcommand' -a report -d '生成报告'
complete -c poxiao -n '__fish_use_subcommand' -a check -d '存活检测'

# poc 子命令
complete -c poxiao -n '__fish_seen_subcommand_from poc' -a scan -d '扫描目标'
complete -c poxiao -n '__fish_seen_subcommand_from poc' -a list -d '列出模板'
complete -c poxiao -n '__fish_seen_subcommand_from poc' -a history -d '查看历史'

# stealth 子命令
complete -c poxiao -n '__fish_seen_subcommand_from stealth' -a proxy-test -d '测试代理'
complete -c poxiao -n '__fish_seen_subcommand_from stealth' -a check-waf -d '检测WAF'
complete -c poxiao -n '__fish_seen_subcommand_from stealth' -a gen-ua -d '生成UA'

# util 子命令
complete -c poxiao -n '__fish_seen_subcommand_from util' -a encode -d '编码'
complete -c poxiao -n '__fish_seen_subcommand_from util' -a decode -d '解码'
complete -c poxiao -n '__fish_seen_subcommand_from util' -a hash -d '哈希'
complete -c poxiao -n '__fish_seen_subcommand_from util' -a jwt-decode -d 'JWT解码'
complete -c poxiao -n '__fish_seen_subcommand_from util' -a auto -d '自动识别'

# monitor 子命令
complete -c poxiao -n '__fish_seen_subcommand_from monitor' -a serve -d '启动Web面板'
complete -c poxiao -n '__fish_seen_subcommand_from monitor' -a import -d '导入结果'
complete -c poxiao -n '__fish_seen_subcommand_from monitor' -a stats -d '查看统计'

# 编码类型
complete -c poxiao -n '__fish_seen_subcommand_from encode decode' -a 'base64 base32 base58 hex url url-full double-url html html-entity unicode rot13 morse'
complete -c poxiao -n '__fish_seen_subcommand_from hash' -a 'md5 sha1 sha256 sha512'

# severity 参数
complete -c poxiao -l severity -a 'critical high medium low info'

# category 参数
complete -c poxiao -l category -a 'random chrome firefox safari edge mobile cn'
'''
    return script


if __name__ == "__main__":
    shell = sys.argv[1] if len(sys.argv) > 1 else "bash"

    if shell == "bash":
        print(generate_bash())
    elif shell == "zsh":
        print(generate_zsh())
    elif shell == "fish":
        print(generate_fish())
    else:
        print("用法: python poxiao_completion.py [bash|zsh|fish]")
        print("  bash:  eval \"$(python poxiao_completion.py bash)\"")
        print("  zsh:   eval \"$(python poxiao_completion.py zsh)\"")
        print("  fish:  python poxiao_completion.py fish > ~/.config/fish/completions/poxiao.fish")
