import os
import subprocess

import generic.parameters as parameters
import ldap
from flask import session


def create_new_user(username, password, sudoers, email):
    if sudoers is None:
        create_user_cmd = ['/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/python/latest/bin/python3', '/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/cluster_manager/ldap_manager.py', 'add-user', '-u', username, '-p', password, '-e', email]
    else:
        create_user_cmd = ['/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/python/latest/bin/python3', '/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/cluster_manager/ldap_manager.py', 'add-user', '-u', username, '-p', password, '-e', email, '--admin']
    create_new_user_exit_code = subprocess.call(create_user_cmd)
    return {'cmd': ' '.join(create_user_cmd), 'exit_code': create_new_user_exit_code}

def delete_user(username):
    delete_user_cmd = ['/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/python/latest/bin/python3', '/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/cluster_manager/ldap_manager.py', 'delete-user',
                       '-u', username]
    delete_user_cmd_exit_code = subprocess.call(delete_user_cmd)
    return {'cmd': ' '.join(delete_user_cmd), 'exit_code': delete_user_cmd_exit_code}

def get_all_users():
    all_ldap_users = {}
    ldap_host = parameters.get_parameter('ldap', 'host')
    user_search_base = "ou=People,dc=soca,dc=local"
    user_search_scope = ldap.SCOPE_SUBTREE
    user_filter = 'uid=*'
    con = ldap.initialize('ldap://{}'.format(ldap_host))
    users = con.search_s(user_search_base, user_search_scope, user_filter)

    for user in users:
        user_base = user[0]
        username = user[1]['uid'][0].decode('utf-8')
        all_ldap_users[username] = user_base

    return all_ldap_users


def verify_sudo_permissions(username):
    ldap_host = parameters.get_parameter('ldap', 'host')
    base_dn = parameters.get_parameter('ldap', 'base_dn')
    user_dn = 'uid={},ou=people,{}'.format(username, base_dn)
    con = ldap.initialize('ldap://{}'.format(ldap_host))
    try:
        # Check if user has sudo permissions
        sudoers_search_base = "ou=Sudoers,dc=soca,dc=local"
        sudoers_search_scope = ldap.SCOPE_SUBTREE
        sudoers_filter = 'cn=' + username
        is_sudo = con.search_s(sudoers_search_base, sudoers_search_scope, sudoers_filter)
        if is_sudo.__len__() > 0:
            return {'success': True,
                    'message': username + ' is a valid SUDO user'}
        else:
            return {'success': False,
                    'message': username + ' is not a SUDO user'}


    except ldap.INVALID_CREDENTIALS:
        return {'success': False,
                'message': 'Invalid credentials.'}

    except ldap.SERVER_DOWN:
        return {'success': False,
                'message': 'LDAP server is down.'}


def validate_ldap(username, password):
    ldap_host = parameters.get_parameter('ldap', 'host')
    base_dn = parameters.get_parameter('ldap', 'base_dn')
    user_dn = 'uid={},ou=people,{}'.format(username, base_dn)
    con = ldap.initialize('ldap://{}'.format(ldap_host))
    try:
        con.bind_s(user_dn, password, ldap.AUTH_SIMPLE)
        session['username'] = username
        # Check if user has sudo permissions
        sudoers_search_base = "ou=Sudoers,dc=soca,dc=local"
        sudoers_search_scope = ldap.SCOPE_SUBTREE
        sudoers_filter = 'cn=' + username
        is_sudo = con.search_s(sudoers_search_base, sudoers_search_scope, sudoers_filter)
        if is_sudo.__len__() > 0:
            session['sudoers'] = True
        else:
            session['sudoers'] = False

        return {'success': True,
                'message': ''}

    except ldap.INVALID_CREDENTIALS:
        return {'success': False,
                'message': 'Invalid credentials.'}

    except ldap.SERVER_DOWN:
        return {'success': False,
                'message': 'LDAP server is down.'}