import argparse
import hashlib
import os
import shutil
import sys
from base64 import b64encode as encode

import ldap

sys.path.append(os.path.dirname(__file__))
import configuration
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import subprocess
import datetime

def run_command(cmd):
    try:
        command = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = command.communicate()
        return stdout
    except subprocess.CalledProcessError as e:
        exit(1)


def find_ids():
    used_uid = []
    used_gid = []
    res = con.search_s(ldap_base,
                       ldap.SCOPE_SUBTREE,
                       'objectClass=posixAccount', ['uidNumber', 'gidNumber']
                       )
    # Any users/group created will start with uid/gid => 5000
    uid = 5000
    gid = 5000
    for a in res:
        uid_temp = int(a[1].get('uidNumber')[0])
        used_uid.append(uid_temp)
        if uid_temp > uid:
            uid = uid_temp

    for a in res:
        gid_temp = int(a[1].get('gidNumber')[0])
        used_gid.append(gid_temp)
        if gid_temp > gid:
            gid = gid_temp

    return {'next_uid': int(uid) + 1,
            'used_uid': used_uid,
            'next_gid': int(gid) + 1,
            'used_gid': used_gid}


def create_home(username):
    try:
        key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption())
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )
        private_key_str = private_key.decode('utf-8')
        public_key_str = public_key.decode('utf-8')
        # Create user directory structure and permissions
        user_path = user_home + '/' + username + '/.ssh'
        run_command('mkdir -p ' + user_path)
        shutil.copy('/etc/skel/.bashrc', user_path[:-4])
        shutil.copy('/etc/skel/.bash_profile', user_path[:-4])
        shutil.copy('/etc/skel/.bash_logout', user_path[:-4])
        shutil.chown(user_home + '/' + username + '/.bashrc', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.bash_profile', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.bash_logout', user=username, group=username)
        print(private_key_str, file=open(user_path + '/id_rsa', 'w'))
        print(public_key_str, file=open(user_path + '/id_rsa.pub', 'w'))
        print(public_key_str, file=open(user_path + '/authorized_keys', 'w'))
        shutil.chown(user_home + '/' + username, user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/authorized_keys', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/id_rsa', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/id_rsa.pub', user=username, group=username)
        os.chmod(user_home + '/' + username, 0o750)
        os.chmod(user_home + '/' + username + '/.ssh', 0o700)
        os.chmod(user_home + '/' + username + '/.ssh/id_rsa', 0o600)
        os.chmod(user_home + '/' + username + '/.ssh/authorized_keys', 0o600)
        return True
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        return e


def create_group(username, gid_number):
    dn_group = "cn=" + username + ",ou=group," + ldap_base
    attrs = [
        ('objectClass', ['top'.encode('utf-8'),
                         'posixGroup'.encode('utf-8')]),
        ('gidNumber', [str(gid_number).encode('utf-8')]),
        ('cn', [str(username).encode('utf-8')])
    ]

    try:
        con.add_s(dn_group, attrs)
        return True
    except Exception as e:
        return e


def create_user(username, password, sudoers, email=False, uid=False, gid=False):
    dn_user = "uid=" + username + ",ou=people," + ldap_base
    enc_passwd = bytes(password, 'utf-8')
    salt = os.urandom(16)
    sha = hashlib.sha1(enc_passwd)
    sha.update(salt)
    digest = sha.digest()
    b64_envelop = encode(digest + salt)
    passwd = '{{SSHA}}{}'.format(b64_envelop.decode('utf-8'))

    attrs = [
        ('objectClass', ['top'.encode('utf-8'),
                         'person'.encode('utf-8'),
                         'posixAccount'.encode('utf-8'),
                         'shadowAccount'.encode('utf-8'),
                         'inetOrgPerson'.encode('utf-8'),
                         'organizationalPerson'.encode('utf-8')]),
        ('uid', [str(username).encode('utf-8')]),
        ('uidNumber', [str(uid).encode('utf-8')]),
        ('gidNumber', [str(gid).encode('utf-8')]),
        ('cn', [str(username).encode('utf-8')]),
        ('sn', [str(username).encode('utf-8')]),
        ('loginShell', ['/bin/bash'.encode('utf-8')]),
        ('homeDirectory', (str(user_home) + '/' + str(username)).encode('utf-8')),
        ('userPassword', [passwd.encode('utf-8')])
    ]

    if email is not False:
        attrs.append(('mail', [email.encode('utf-8')]))

    try:
        con.add_s(dn_user, attrs)
        if sudoers is True:
            sudo = add_sudo(username)
            if sudo is True:
                print('Added user as sudoers')
            else:
                print('Unable to add user as sudoers: ' +str (sudo))
        return True
    except Exception as e:
        print('Unable to create new user: ' +str(e))
        return e


def add_sudo(username):
    dn_user = "cn=" + username + ",ou=Sudoers," + ldap_base
    attrs = [
        ('objectClass', ['top'.encode('utf-8'),
                         'sudoRole'.encode('utf-8')]),
        ('sudoHost', ['ALL'.encode('utf-8')]),
        ('sudoUser', [str(username).encode('utf-8')]),
        ('sudoCommand', ['ALL'.encode('utf-8')])
    ]

    try:
        con.add_s(dn_user, attrs)
        return True
    except Exception as e:
        return e


def delete_user(username):
    try:
        entries_to_delete = ["uid=" + username + ",ou=People," + ldap_base,
                             "cn=" + username + ",ou=Group," + ldap_base,
                             "cn=" + username + ",ou=Sudoers," + ldap_base]
        today = datetime.datetime.utcnow().strftime('%s')
        run_command('mv /data/home/' + username + ' /data/home/' + username + '_'+str(today))
        for entry in entries_to_delete:
            try:
                con.delete_s(entry)
            except ldap.NO_SUCH_OBJECT:
                pass

        return True
    except Exception as e:
        return e


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest="command")
    subparser_add_user = subparser.add_parser("add-user")
    subparser_add_user.add_argument('-u', '--username', nargs='?', required=True, help='LDAP username')
    subparser_add_user.add_argument('-p', '--password', nargs='?', required=True, help='User password')
    subparser_add_user.add_argument('-e', '--email', nargs='?', help='User email')
    subparser_add_user.add_argument('--uid', nargs='?', help='Specify custom Uid')
    subparser_add_user.add_argument('--gid', nargs='?', help='Specific custom Gid')
    subparser_add_user.add_argument('--admin', action='store_const', const=True, help='If flag is specified, user will be added to sudoers group')

    subparser_delete_user = subparser.add_parser("delete-user")
    subparser_delete_user.add_argument('-u', '--username', nargs='?', required=True, help='LDAP username')

    arg = parser.parse_args()
    ldap_action = arg.command
    # Soca Parameters
    aligo_configuration = configuration.get_aligo_configuration()
    ldap_base = aligo_configuration['LdapBase']
    user_home = '/data/home'
    slappasswd = '/sbin/slappasswd'
    root_dn = 'CN=admin,' + ldap_base
    root_pw = open('/root/OpenLdapAdminPassword.txt', 'r').read()
    ldap_args = '-ZZ -x -H "ldap://' + aligo_configuration['LdapHost'] + '" -D ' + root_dn + ' -y ' + root_pw
    con = ldap.initialize('ldap://' + aligo_configuration['LdapHost'])
    con.simple_bind_s(root_dn, root_pw)

    if ldap_action == 'delete-user':
        delete = delete_user(str(arg.username))

    elif ldap_action == 'add-user':
        if arg.email is not None:
            email = arg.email
        else:
            email = False

        # Get next available group/user ID
        ldap_ids = find_ids()
        if arg.gid is None:
            gid = ldap_ids['next_gid']
        else:
            gid = int(arg.gid)

        if arg.uid is None:
            uid = ldap_ids['next_uid']
        else:
            uid = int(arg.uid)

        add_user = create_user(str(arg.username), str(arg.password), arg.admin, email, uid, gid)
        if add_user is True:
            print('Created User: ' + str(arg.username) + ' id: ' + str(uid))
        else:
            print('Unable to create user:' + str(arg.username))
            sys.exit(1)

        add_group = create_group(str(arg.username), gid)
        if add_group is True:
            print('Created group successfully')
        else:
            print('Unable to create group:' + str(arg.username))
            sys.exit(1)

        add_home = create_home(str(arg.username))
        if add_home is True:
            print('Home directory created correctly')
        else:
            print('Unable to create Home structure:' + str(add_home))
            sys.exit(1)

    else:
        exit(1)

    con.unbind_s()
