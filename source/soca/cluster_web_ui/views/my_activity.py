import logging
import config
import json
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, delete
from decorators import login_required
import datetime
import read_secretmanager

logger = logging.getLogger("application")
my_activity = Blueprint('my_activity', __name__, template_folder='templates')


@my_activity.route("/my_activity", methods=["GET"])
@login_required
def index():
    user = session['user']
    start = request.args.get('start')
    end = request.args.get('end')
    if not start or not end:
        timedelta = 90
        end = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        start = (datetime.datetime.utcnow() - datetime.timedelta(days=timedelta)).strftime('%Y-%m-%d')

    user_kibana_url = False
    elastic_search_endpoint = read_secretmanager.get_soca_configuration()['ESDomainEndpoint']
    job_index = "https://" + elastic_search_endpoint + "/_search?q=type:index-pattern%20AND%20index-pattern.title:" + config.Config.KIBANA_JOB_INDEX
    get_job_index = get(job_index, verify=False)
    index_id = False
    if get_job_index.status_code == 200:
        response = json.loads(get_job_index.text)
        if len(response["hits"]["hits"]) == 0:
            pass
        elif len(response["hits"]["hits"]) == 1:
            index_id = response["hits"]["hits"][0]["_id"].split(":")[-1]
        else:
            flash("More than 1 index has been detected when using the index name {}. Edit config.py and change KIBANA_JOB_INDEX to something more specific ".format(config.Config.KIBANA_JOB_INDEX), "error")

    elif get_job_index.status_code == 404:
        flash("Job index cannot be found on your ElasticSearch. Please create it first: https://awslabs.github.io/scale-out-computing-on-aws/analytics/monitor-cluster-activity/ to setup your index","error")
    else:
        flash("Unable to query Elastic Search indices. Make sure this host has permission to query: {}".format(job_index), "error")

    if index_id is False:
        flash("Unable to retrieve index ID for {}. To do the initial setup, follow instructions available on <a href='https://awslabs.github.io/scale-out-computing-on-aws/analytics/monitor-cluster-activity/' target='_blank'>https://awslabs.github.io/scale-out-computing-on-aws/analytics/monitor-cluster-activity/</a>".format(config.Config.KIBANA_JOB_INDEX))
        user_kibana_url = "https://" + elastic_search_endpoint + "/_plugin/kibana/"
    else:
        user_kibana_url = "https://"+elastic_search_endpoint+"/_plugin/kibana/app/kibana#/discover?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'"+start+"T00:00:00.000Z',to:'"+end+"T23:59:59.000Z'))&_a=(columns:!(_source),filters:!(),index:'"+index_id+"',interval:auto,query:(language:kuery,query:'user:"+user+"'),sort:!(!(start_iso,desc)))"

    return render_template('my_activity.html',
                           user_kibana_url=user_kibana_url,
                           user=user,
                           start=start,
                           client_ip=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                           end=end)

