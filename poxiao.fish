# 破晓 Fish Tab 补全

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

