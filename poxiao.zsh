#compdef poxiao
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

    _arguments -C \
        '1:command:->commands' \
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
                    _arguments \
                        '(-f --file)'{-f,--file}'[目标文件]' \
                        '--depth[扫描深度]:depth:(normal full)' \
                        '(-c --concurrency)'{-c,--concurrency}'[并发数]' \
                        '--timeout[超时秒数]' \
                        '--no-sensitive[跳过敏感路径]' \
                        '(-o --output)'{-o,--output}'[输出目录]'
                    ;;
                recon)
                    _arguments \
                        '--quick[快速模式]' \
                        '--shodan-key[Shodan API Key]' \
                        '(-o --output)'{-o,--output}'[输出路径]' \
                        '--timeout[超时秒数]'
                    ;;
                subdomain)
                    _arguments \
                        '--no-crtsh[跳过crt.sh]' \
                        '--no-brute[跳过DNS爆破]' \
                        '--no-alive[跳过存活验证]' \
                        '(-o --output)'{-o,--output}'[输出文件]'
                    ;;
                verify)
                    _arguments \
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
                    _arguments \
                        '(-t --templates)'{-t,--templates}'[模板目录]' \
                        '--tags[标签过滤]' \
                        '--severity[严重级别]:severity:(critical high medium low info)' \
                        '(-c --concurrency)'{-c,--concurrency}'[并发数]' \
                        '--timeout[超时秒数]' \
                        '(-o --output)'{-o,--output}'[输出路径]' \
                        '--stealth[隐匿模式]' \
                        '--proxies[代理文件]' \
                        '--loop[持续扫描]' \
                        '--interval[扫描间隔]' \
                        '--history[历史对比]'
                    ;;
                list)
                    _arguments \
                        '(-t --templates)'{-t,--templates}'[模板目录]' \
                        '--tags[标签过滤]' \
                        '--severity[严重级别]:severity:(critical high medium low info)'
                    ;;
                history)
                    _arguments \
                        '--findings[显示详情]' \
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
                    _arguments \
                        '(-n --count)'{-n,--count}'[数量]' \
                        '--category[类型]:category:(random chrome firefox safari edge mobile cn)'
                    ;;
                check-waf)
                    _arguments '--timeout[超时秒数]'
                    ;;
                proxy-test)
                    _arguments \
                        '--timeout[超时秒数]' \
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

