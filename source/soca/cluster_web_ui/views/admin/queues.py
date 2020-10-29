import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, post, delete
from models import ApiKeys
from decorators import login_required, admin_only

logger = logging.getLogger("application")
admin_queues = Blueprint('admin_queues', __name__, template_folder='templates')


@admin_queues.route('/admin/queues', methods=['GET'])
@login_required
@admin_only
def index():
    get_all_queues = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/queues",
                         headers={"X-SOCA-TOKEN": session["api_key"],
                                  "X-SOCA-USER": session["user"]},
                         verify=False)

    if get_all_queues.status_code == 200:
        all_queues = get_all_queues.json()["message"]
    else:
        flash("Unable to retrieve queues list due to " + str(get_all_queues.text), "error")
        all_queues = []

    return render_template('admin/queues.html', user=session['user'], all_queues=all_queues)


@admin_queues.route('/admin/queues/create', methods=['POST'])
@login_required
@admin_only
def create_new_queue():
    queue_name = str(request.form.get('queue_name'))
    queue_type = str(request.form.get('queue_type'))
    create_new_queue = post(config.Config.FLASK_ENDPOINT + "/api/scheduler/queue",
                            headers={"X-SOCA-TOKEN": session["api_key"],
                                     "X-SOCA-USER": session["user"]},
                            data={"name": queue_name, "type": queue_type},
                            verify=False)
    if create_new_queue.status_code == 200:
        flash("Queue " + queue_name + " has been created successfully", "success")
    else:
        flash("Unable to create new user. API returned error: " + str(create_new_queue.text), "error")
    return redirect('/admin/queues')


@admin_queues.route('/admin/queues/delete', methods=['POST'])
@login_required
@admin_only
def delete_queue():
    queue_name = str(request.form.get('queue_to_delete'))
    delete_queue = delete(config.Config.FLASK_ENDPOINT + "/api/scheduler/queue",
                             headers={"X-SOCA-TOKEN": session["api_key"],
                                      "X-SOCA-USER": session["user"]},
                             data={"name": queue_name},
                         verify=False
                         )
    if delete_queue.status_code == 200:
        flash('Queue ' + queue_name + ' has been deleted correctly', "success")
    else:
        flash('Could not delete queue: ' + queue_name + '. Check trace: ' + str(delete_queue.text), "error")

    return redirect('/admin/queues')