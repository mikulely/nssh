#!/usr/bin/env python2.7
#! -*- coding:utf-8 -*-

''' ssh wrapper with expect, auto-login without sshkey '''

import sys
import os
from optparse import OptionParser

import pexpect
import requests
import yaml

__author__ = "Ren Jiaying"
__email__ = "renjiaying@intra.nsfocus.com"
__maintainer__ = "Ren Jiaying"
__email__ = "renjiaying@intra.nsfocus.com"
__status__ = "Stable"

g_config = dict()


def is_a_known_host_p(host_ip):
    """
    Check whether HOST_IP's password is already stored in config file.
    """
    known_host_flag = False
    host_list = get_config_item('host_list')
    for host in host_list:
        if host_ip == host['ip']:
            known_host_flag = True
        else:
            known_host_flag = False
    if known_host_flag:
        return True
    else:
        return False


def get_known_host_passwd(host_ip):
    """
    Return HOST_IP's password from nssh config file.
    """
    host_list = get_config_item('host_list')
    for host in host_list:
        if host_ip == host['ip']:
            return host['passwd']


def load_config(config_file):
    """
    Load CONFIG_FILE to global var G_CONFIG, default file is ~/.nssh.yaml.
    """
    global g_config

    if os.path.isfile(config_file):
        yaml_file = open(config_file, 'r')
        g_config = yaml.safe_load(yaml_file)
        yaml_file.close()
    else:
        sys.exit('%s dose not exist.\n Create it yourself.' % config_file)


def get_config_item(config_item):
    """
    Get CONFIG_ITEM from global var G_CONFIG.
    """
    if config_item in g_config:
        return g_config[config_item]
    else:
        sys.exit("You need to config %s in your nssh.yaml file." % config_item)


def get_termsize():
    '''
    Horrible non-portable hack to get the terminal size to transmit
    to the child process spawned by pexpect.
    @see https://github.com/bdelliott/sshpass/blob/master/sshpass.py
    '''
    (rows, cols) = os.popen("stty size").read().split()  # works on Mac OS X
                                                         #+ and ArchLinux. YMMV
    rows = int(rows)
    cols = int(cols)
    return (rows, cols)


def get_onepass(user_name, user_passwd, serial_num, status_code, reason):
    """
    Get onetime passwd from auth server.
    """
    passwd_server_url = get_config_item('auth_url')

    form_info = {
        'username': user_name,
        'passwd': user_passwd,
        'hardcode': serial_num,
        'prodcode': status_code,
        'reason': reason
    }

    responed = requests.post(passwd_server_url, data=form_info)
    if responed.status_code == requests.codes.ok:
        responed_html = responed.content

        for tag in responed_html.split('</b>'):
            if "<b>" in tag:
                capitaled_onepass = tag[tag.find("<b>")+len("<b>"):]
                # Caution! 密码认证时是区分大小写的.调试了很久有木有.T_T
                return capitaled_onepass.lower()
    else:
        sys.exit("auth errors.")


def get_info_from_ssh(ssh_process):
    """
    Get serial_num and status_code from the SSH_PROCESS.
    """
    # Caution! before 属性中的字串可能一行也可能多行
    raw_info = ssh_process.before.strip().split('\r\n')
    info_chunk = raw_info[-1]
    serial_pair, status_pair = info_chunk.split()

    serial_num = serial_pair.split(":")[1]
    status_code = status_pair.split(":")[1]

    return serial_num, status_code


def onepass_needed_p(info_chunk):
    """
    Find 'Serial' in INFO_CHUNK to check whether onepass is needed.
    """
    if 'Serial' in info_chunk:
        return True
    else:
        return False


def args_are_validate_p(parser, args):
    """
    Check ARGS validation with PARSER.
    """
    if len(args) != 1:
        parser.print_usage()
        sys.exit(1)
    else:
        return True


def login(account, host_ip, host_port):
    """
    SSH Login HOST_IP PORT with ACCOUNT.
    """
    login_cmd = "ssh -p%d %s@%s " % (host_port, account, host_ip)
    child_process = pexpect.spawn(login_cmd)

    (rows, cols) = get_termsize()
    child_process.setwinsize(rows, cols)  # set the child to the
                                          #+ size of the user's term

    firstime_login_server = "Are you sure you want to continue connecting (yes/no)?"
    passwd_needed_server = "Password:"
    permission_needed_server = "Permission denied"
    cmd_prompt = nopass_server = "[>#\$]"

    first_launched = 0
    need_passwd = 1
    not_need_passwd = 2
    need_permission = 3

    try:
        expect_status = child_process.expect([
            firstime_login_server,
            passwd_needed_server,
            nopass_server,
            permission_needed_server
        ])
        if expect_status == need_permission:
            sys.exit("Permission denied on %s. Can't login" % host_ip)

        # 1. 对于首次登陆的设备,需要先保存公钥
        if expect_status == first_launched:
            child_process.sendline('yes')
            after_trust_status = child_process.expect([
                pexpect.EOF,
                passwd_needed_server,
                nopass_server
            ])
            if after_trust_status == not_need_passwd:
                # 1.1 没设密码的设备,直接登陆即可
                child_process.sendline()
                child_process.interact()
                # 1.2 需要密码登陆的设备
            if after_trust_status == need_passwd:
                if onepass_needed_p(child_process.before):
                    # 1.2.1 需要一次一密的设备,需要生成密码
                    serial_num, status_code = get_info_from_ssh(child_process)

                    onepass = get_onepass(get_config_item('name'),
                                          get_config_item('passwd'),
                                          serial_num,
                                          status_code,
                                          get_config_item('reason'))

                    child_process.sendline(onepass)
                    child_process.expect([cmd_prompt])
                    child_process.sendline(get_config_item('after_login_cmd'))
                    child_process.interact()
                else:
                    if is_a_known_host_p(host_ip):
                        # 1.2.2 需要普通密码登陆的设备,但是已经保存了密码的设备
                        stored_passwd = get_known_host_passwd(host_ip)
                        child_process.sendline(stored_passwd)
                        child_process.interact()
                    else:
                        # 1.2.3 需要普通密码登陆的设备,又没有保存密码的设备,让用户输入
                        child_process.sendline()
                        child_process.interact()
        # 2. 对于之前登陆过的设备,不需要处理公钥
        if expect_status == not_need_passwd:
            # 2.1 没设密码的设备,直接登陆即可
            child_process.sendline()
            child_process.interact()

        if expect_status == need_passwd and onepass_needed_p(child_process.before):
            # 2.2.1 需要一次一密的设备,需要生成密码
            serial_num, status_code = get_info_from_ssh(child_process)

            onepass = get_onepass(get_config_item('name'),
                                  get_config_item('passwd'),
                                  serial_num,
                                  status_code,
                                  get_config_item('reason'))
            child_process.sendline(onepass)
            # 在登陆后执行必要的操作,显示设备类型
            child_process.expect([cmd_prompt])
            child_process.sendline(get_config_item('after_login_cmd'))
            child_process.interact()
        else:
            if is_a_known_host_p(host_ip):
                # 2.2.2 需要普通密码登陆的设备,但是已经保存了密码的设备
                stored_passwd = get_known_host_passwd(host_ip)
                child_process.sendline(stored_passwd)
                child_process.interact()
            else:
                # 2.2.3 需要普通密码登陆的设备,又没有保存密码的设备,让用户输入
                child_process.sendline()
                child_process.interact()
    except pexpect.TIMEOUT:
        sys.exit("timeout.")


def main():
    """
    1. parse CLI arguments.
    2. load config file.
    3. fire ssh login.
    """
    cli_parser = OptionParser(
        description="Description: ssh wrapper with auto-login enabled.",
        version='0.1',
        usage="nssh [options] [user@]host_ip",
        epilog="patches are welcomed. <renjiaying@intra.nsfocus.com>"
    )

    cli_parser.add_option("-f", "--file",
                          dest="filename",
                          help="read account settings from file, default one is ~/.nssh.yaml",
                          metavar="FILE",
                          default=os.path.join(os.path.expanduser("~"), '.nssh.yaml'))

    cli_parser.add_option("-p", "--port", dest="port",
                          help="specify the ssh port, default one is 22.",
                          default=22
                          )

    (opts, args) = cli_parser.parse_args()
    load_config(opts.filename)

    if args_are_validate_p(cli_parser, args):
        host_str = args[0]
        if host_str.find("@") != -1:
            (account, host_ip) = host_str.split("@")
            host_port = int(opts.port)
        else:
            host_ip = args[0]
            account = get_config_item('default_login_account')
            if int(opts.port) == get_config_item('default_ssh_port'):
                host_port = get_config_item('device_ssh_port')

        login(account, host_ip, host_port)

if __name__ == '__main__':
    main()
