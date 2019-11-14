from flask import session, Blueprint, redirect, url_for, request, send_file, Response, flash
from generic import auth
from generic import dcv
from generic import parameters

dcv_management = Blueprint('dcv_management', __name__, template_folder='templates')


@dcv_management.route('/api/dcv_create_session', methods=['GET'])
@auth.login_required
def dcv_create_session():
    try:
        username = session['username']
        walltime = request.args.get('walltime')
        instance_type = request.args.get('instance_type')
        session_number = int(request.args.get('session_number'))
        if walltime is None or instance_type is None or session_number is None:
            return redirect('/remotedesktop')

        user_sessions = dcv.check_user_session(username)
        if user_sessions.__len__() >= parameters.authorized_dcv_session_count():
            print(username + ' is not authorized to launch more sessions. Delete existing DCV file or make sure user is not querying endpoint directly')
            return redirect('/remotedesktop')
        else:
            dcv.build_qsub(username, session_number, walltime, instance_type)
            return redirect('/remotedesktop')
    except Exception as e:
        flash('Error while trying to launch your session: Please verify you can submit job to the desktop queue (eg: verify budget restrictions for this queue)')
        return redirect('/remotedesktop')

@dcv_management.route('/api/dcv_close_session', methods=['GET'])
@auth.login_required
def dcv_close_session():
    username = session['username']
    session_number = int(request.args.get('session_number'))
    if session_number not in range(parameters.authorized_dcv_session_count() + 1):
        return redirect('/remotedesktop')

    dcv.clean_session(username, session_number)
    return redirect('/remotedesktop')


@dcv_management.route('/api/dcv_create_client_file', methods=['GET'])
@auth.login_required
def dcv_create_client_file():
    username = session['username']
    session_number = int(request.args.get('session_number'))
    if session_number not in range(parameters.authorized_dcv_session_count() + 1):
        return redirect('/remotedesktop')
    dcv_file = dcv.build_dcv_connect_client(username, session_number)
    return Response(
        dcv_file,
        mimetype='text/txt',
        headers={'Content-disposition': 'attachment; filename=' + username + '_soca_'+str(session_number)+'.dcv'})

