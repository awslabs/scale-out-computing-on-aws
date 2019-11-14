from flask import send_file, session, Blueprint
from generic import auth

get_pem_key = Blueprint('get_pem_key', __name__, template_folder='templates')


@get_pem_key.route('/api/get_pem_key', methods=['GET'])
@auth.login_required
def f():
    username = session['username']
    user_private_key_path = '/data/home/' + username + '/.ssh/id_rsa'
    return send_file(user_private_key_path,
                     as_attachment=True,
                     attachment_filename=username+'_soca_privatekey.pem')
