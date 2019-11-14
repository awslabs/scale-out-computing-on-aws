from flask import send_file, session, Blueprint
import os
from generic import auth
import generic.parameters as parameters
import subprocess
get_ppk_key = Blueprint('get_ppk_key', __name__, template_folder='templates')


@get_ppk_key.route('/api/get_ppk_key', methods=['GET'])
@auth.login_required
def f():
    username = session['username']
    user_private_key_path = '/data/home/' + username + '/.ssh/id_rsa'
    generate_ppk = ['unix/puttygen', user_private_key_path, '-o', parameters.get_parameter('ssh', 'private_key_location')+'/' + username+'_soca_privatekey.ppk']
    subprocess.call(generate_ppk)
    os.chmod(parameters.get_parameter('ssh', 'private_key_location')+'/'+username+'_soca_privatekey.ppk', 0o700)
    return send_file(parameters.get_parameter('ssh', 'private_key_location')+'/'+username+'_soca_privatekey.ppk',
                     as_attachment=True,
                     attachment_filename=username+'_soca_privatekey.ppk')
