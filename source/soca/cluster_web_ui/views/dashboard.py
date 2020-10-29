import logging
import config
from decorators import login_required
from flask import Blueprint, render_template
import read_secretmanager

logger = logging.getLogger("application")
dashboard = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard.route('/dashboard', methods=['GET'])
@login_required
def index():
    elastic_search_endpoint = read_secretmanager.get_soca_configuration()['ESDomainEndpoint']
    kibana_url = "https://" + elastic_search_endpoint + "/_plugin/kibana"
    return render_template("dashboard.html", kibana_url=kibana_url)