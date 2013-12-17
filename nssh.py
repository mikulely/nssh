#!/usr/bin/env python2.7
#! -*- coding:utf-8 -*-
# nssh.py - ssh wrappered with expect, auto-login without sshkey.
# Copyright (C) 2013 Ren jiaying <renjiaying@intra.nsfocus.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
ssh wrappered with expect, auto-login without sshkey.

For usage and a list of options, try this:

$ python2.7 nssh.py -h

The default config file 'nssh.yaml' is distributed with nssh.py, you
should copy it to '~/.nssh.yaml' and fill up your config. For more details,
check the 'Setup' section of README out.

If you want to load another config file, you can specify it with -f
option. Like this:

$ python2.7 nssh.py host_ip -f /path/to/your_nssh.yaml

"""
__version__ = '0.1'


from contextlib import contextmanager
from optparse import OptionParser
import os
import sys


import pexpect
import requests
import yaml


g_nssh_config = dict()


def is_known_host_p(host_ip):
    """Check whether HOST_IP's password is already stored in config file."""
    is_known_host_f = False

    host_list = get_nssh_config_item('host_list')
    for host in host_list:
        if host_ip == host['ip']:
            is_known_host_f = True
        else:
            is_known_host_f = False

    if is_known_host_f:
        return True
    else:
        return False


def get_known_host_passwd(host_ip):
    """Return HOST_IP's password from nssh config file."""
    host_list = get_nssh_config_item('host_list')
    for host in host_list:
        if host_ip == host['ip']:
            return host['passwd']


def load_nssh_config(config_file):
    """Load CONFIG_FILE to global variable G_NSSH_CONFIG."""
    global g_nssh_config

    if os.path.isfile(config_file):
        with open(config_file, 'r') as yaml_file:
            g_nssh_config = yaml.safe_load(yaml_file)
    else:
        sys.exit("%s does not exist.\n Create it yourself."
                 "There's a template in the nssh git repo that you can refer."
                 % config_file)


def get_nssh_config_item(config_item):
    """Get CONFIG_ITEM from global variable G_NSSH_CONFIG."""
    if config_item in g_nssh_config:
        return g_nssh_config[config_item]
    else:
        sys.exit("You need to config %s in your nssh config file."
                 % config_item)


def get_termsize():
    """
    Get terminal size from the cmd `stty size`.

    Horrible non-portable hack to get the terminal size to transmit
    to the child process spawned by pexpect.
    @see https://github.com/bdelliott/sshpass/blob/master/sshpass.py

    """
    (rows, cols) = os.popen("stty size").read().split()  # works on Mac OS X
                                                         #+ and ArchLinux. YMMV
    rows = int(rows)
    cols = int(cols)
    return (rows, cols)


def need_onepass_p(info_raw):
    """Check whether onepass is needed by search 'Serial' in INFO_RAW."""
    if 'Serial' in info_raw:
        return True
    else:
        return False


def fetch_onepass(user_name, user_passwd, serial_num, status_code, reason):
    """Get onetime password from auth server."""
    auth_server_url = get_nssh_config_item('auth_url')

    auth_form = {
        'username': user_name,
        'passwd': user_passwd,
        'hardcode': serial_num,
        'prodcode': status_code,
        'reason': reason
    }

    responed = requests.post(auth_server_url, data=auth_form)
    if responed.status_code == requests.codes.ok:
        responed_html = responed.content

        for tag in responed_html.split('</b>'):
            if "<b>" in tag:
                onepass_capitalized = tag[tag.find("<b>") + len("<b>"):]
                # Caution! 密码认证时是区分大小写的.调试了很久有木有.T_T
                return onepass_capitalized.lower()
    else:
        sys.exit("auth errors.")


def get_serial_and_status(ssh_process):
    """Get serial_num and status_code from the SSH_PROCESS."""
    # Caution! before 属性中的字串可能一行也可能多行
    info_raw = ssh_process.before.strip().split('\r\n')[-1]
    serial_pair, status_pair = info_raw.split()

    serial_num = serial_pair.split(":")[1]
    status_code = status_pair.split(":")[1]

    return (serial_num, status_code)


def are_validate_args_p(args):
    """Check ARGS validation."""
    if len(args) != 1:
        return False
    else:
        return True


@contextmanager
def timeout_handler():
    """Handle pexpect timeout exception."""
    try:
        yield
    except pexpect.TIMEOUT as timeout:
        sys.exit("Ops, %s" % str(timeout))
    except OSError:
        sys.exit("Unproper input/output.")


def nssh_login(account, host_ip, host_port):
    """Use ssh to login HOST_IP PORT with ACCOUNT."""
    login_cmd = "ssh -p%d %s@%s " % (host_port, account, host_ip)
    ssh_process = pexpect.spawn(login_cmd)

    (rows, cols) = get_termsize()
    ssh_process.setwinsize(rows, cols)  # set the child to the
                                        #+ size of the user's term
    cmd_prompt = "[>#\$]"

    firstime_login_server = ("Are you sure you want to "
                             "continue connecting (yes/no)?")
    passwd_needed_server = "Password:"
    permission_needed_server = "Permission denied"
    nopass_server = "[>#\$]"
    sshd_unabled_server = "Connection refused"
    no_router_to_server = "No route to host"

    firstime_login = 0
    need_passwd = 1
    not_need_passwd = 2
    need_permission = 3
    sshd_unabled = 4
    no_router = 5

    with timeout_handler():
        expect_status = ssh_process.expect([
            firstime_login_server,
            passwd_needed_server,
            nopass_server,
            permission_needed_server,
            sshd_unabled_server,
            no_router_to_server
        ])
        if expect_status == need_permission:
            sys.exit("Permission denied on %s.\n"
                     "Maybe you need to uncomment 'PasswordAuthentication yes'"
                     "in /etc/ssh/ssh_config.\n"
                     "Or your password need to be updated.\n"
                     % host_ip)

        if expect_status == sshd_unabled:
            sys.exit("Sshd disabled on %s.\n"
                     "Enable it before login again.\n"
                     % host_ip)

        if expect_status == no_router:
            sys.exit("No router to %s.\n" % host_ip)

        # 1. 对于首次登陆的设备,需要先保存公钥
        if expect_status == firstime_login:
            ssh_process.sendline('yes')
            after_trust_status = ssh_process.expect([
                pexpect.EOF,
                passwd_needed_server,
                nopass_server
            ])
            if after_trust_status == not_need_passwd:
                # 1.1 没设密码的设备,直接登陆即可
                ssh_process.sendline()
                ssh_process.interact()
                # 1.2 需要密码登陆的设备
            if after_trust_status == need_passwd:
                if need_onepass_p(ssh_process.before):
                    # 1.2.1 需要一次一密的设备,需要生成密码
                    serial_num, status_code = get_serial_and_status(ssh_process)

                    onepass = fetch_onepass(get_nssh_config_item('name'),
                                            get_nssh_config_item('passwd'),
                                            serial_num,
                                            status_code,
                                            get_nssh_config_item('reason'))

                    ssh_process.sendline(onepass)
                    ssh_process.expect([cmd_prompt])
                    ssh_process.sendline(get_nssh_config_item('after_login_cmd'))
                    ssh_process.interact()
                else:
                    if is_known_host_p(host_ip):
                        # 1.2.2 需要普通密码登陆的设备,但是已经保存了密码的设备
                        stored_passwd = get_known_host_passwd(host_ip)
                        ssh_process.sendline(stored_passwd)
                        ssh_process.interact()
                    else:
                        # 1.2.3 需要普通密码登陆的设备,又没有保存密码的设备,让用户输入
                        ssh_process.sendline()
                        ssh_process.interact()
        # 2. 对于之前登陆过的设备,不需要处理公钥
        if expect_status == not_need_passwd:
            # 2.1 没设密码的设备,直接登陆即可
            ssh_process.sendline()
            ssh_process.interact()

        if expect_status == need_passwd and need_onepass_p(ssh_process.before):
            # 2.2.1 需要一次一密的设备,需要生成密码
            serial_num, status_code = get_serial_and_status(ssh_process)

            onepass = fetch_onepass(get_nssh_config_item('name'),
                                    get_nssh_config_item('passwd'),
                                    serial_num,
                                    status_code,
                                    get_nssh_config_item('reason'))
            ssh_process.sendline(onepass)
            # 在登陆后执行必要的操作,显示设备类型
            ssh_process.expect([cmd_prompt])
            ssh_process.sendline(get_nssh_config_item('after_login_cmd'))
            ssh_process.interact()
        else:
            if is_known_host_p(host_ip):
                # 2.2.2 需要普通密码登陆的设备,但是已经保存了密码的设备
                stored_passwd = get_known_host_passwd(host_ip)
                ssh_process.sendline(stored_passwd)
                ssh_process.interact()
            else:
                # 2.2.3 需要普通密码登陆的设备,又没有保存密码的设备,让用户输入
                ssh_process.sendline()
                ssh_process.interact()


def get_nssh_cli_parser(prog='nssh', version=__version__):
    """Return nssh cli parser and set nssh cli options."""
    cli_parser = OptionParser(prog=prog,
                              version=version,
                              usage="nssh [options] [user@]host_ip",
                              description="Description: "
                              "ssh wrappered with expect, "
                              "auto-login without sshkey.",
                              epilog="patches are welcomed. "
                              "<renjiaying@intra.nsfocus.com>")

    cli_parser.add_option("-f", "--file",
                          dest="filename",
                          help="read account settings from file, "
                          "default one is ~/.nssh.yaml.",
                          metavar="FILE",
                          default=os.path.expanduser("~/.nssh.yaml"))

    cli_parser.add_option("-p", "--port",
                          dest="port",
                          type="int",
                          help="specify the ssh port, default one is 22.",
                          metavar="n",
                          default=22
                          )
    return cli_parser


def main():
    """
    nssh takes three steps to fire up, which you can see below.

    1. Parse CLI arguments.
    2. Load config file.
    3. Fire login up.

    """
    # 1. parse CLI arguments.
    cli_parser = get_nssh_cli_parser()

    (opts, args) = cli_parser.parse_args()

    if are_validate_args_p(args):
        # 2. load config file.
        load_nssh_config(opts.filename)

        # 3. fire ssh login.
        host_str = args[0]
        if host_str.find("@") != -1:
            (account, host_ip) = host_str.split("@")
            host_port = opts.port
        else:
            host_ip = args[0]
            account = get_nssh_config_item('default_login_account')
            if opts.port == get_nssh_config_item('default_ssh_port'):
                host_port = get_nssh_config_item('device_ssh_port')

        nssh_login(account, host_ip, host_port)
    else:
        cli_parser.print_usage()
        sys.exit(1)

if __name__ == '__main__':
    main()
