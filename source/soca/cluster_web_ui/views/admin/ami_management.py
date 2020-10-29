import logging
import botocore
import boto3
import datetime
from flask import render_template, Blueprint, request, redirect, session, flash
from models import db, AmiList
from decorators import login_required, admin_only
from sqlalchemy import exc
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("application")
admin_ami_management = Blueprint('ami_management', __name__, template_folder='templates')


def get_ami_info():
    ami_info = {}
    for session_info in AmiList.query.filter_by(is_active=True).all():
        ami_info[session_info.ami_label] = session_info.ami_id
    return ami_info


def get_region():
    session = boto3.session.Session()
    aws_region = session.region_name
    return aws_region


@admin_ami_management.route('/admin/ami_management/', methods=['GET'])
@login_required
@admin_only
def index():
    ami_infos = get_ami_info()
    user = session['user']
    return render_template('admin/ami_management.html', user = user, ami_infos=ami_infos, region_name=get_region())


@admin_ami_management.route('/admin/ami_management/create', methods=['POST'])
@login_required
@admin_only
def ami_create():
    ami_id = str(request.form.get("ami_id"))
    choose_os = request.form.get("os")
    ami_label = str(request.form.get("ami_label"))
    root_size = request.form.get("root_size")
    soca_labels = get_ami_info()
    aws_region = get_region()
    ec2_client = boto3.client('ec2', aws_region)
    # Register AMI to SOCA
    if ami_label not in soca_labels.keys():
        try:
            ec2_response = ec2_client.describe_images(ImageIds=[ami_id],
                                                      Filters=[{'Name': 'state', 'Values': ['available']}])
            if (len(ec2_response["Images"]) != 0):
                new_ami = AmiList(ami_id=ami_id,
                                  ami_type=choose_os.lower(),
                                  ami_label=ami_label,
                                  is_active=True,
                                  ami_root_disk_size=root_size,
                                  created_on=datetime.datetime.utcnow())
                try:
                        db.session.add(new_ami)
                        db.session.commit()
                        flash(f"{ami_id} registered successfully in SOCA as {ami_label}", "success")
                        logger.info(f"Creating AMI Label {ami_label} AMI ID {ami_id}")
                except SQLAlchemyError as e:
                        db.session.rollback()
                        flash(f"{ami_id} registration not successful", "error")
                        logger.error(f"Failed Creating AMI {ami_label} {ami_id} {e}")
            else:
                    flash(f"{ami_id} is not available in AWS account. If you just created it, make sure the state of the image is 'available' on the AWS console" )
                    logger.error(f"{ami_id} is not available in AWS account")
        except botocore.exceptions.ClientError as error:
            flash(f"Couldn't locate {ami_id} in AWS account. Make sure you do have permission to view it", "error")
            logger.error(f"Failed Creating AMI {ami_label} {ami_id} {error}")
    else:
        flash (f"Label {ami_label} already in use. Please enter a unique label", "error")
        logger.error(f"Label already in use {ami_label} {ami_id}")
    return redirect('/admin/ami_management')


@admin_ami_management.route('/admin/ami_management/delete', methods=['POST'])
@login_required
@admin_only
def ami_delete():
    ami_label = request.form.get("ami_label")
    for session_info in AmiList.query.filter_by(ami_label=ami_label):
        session_info.is_active = False
        session_info.deactivated_on = datetime.datetime.utcnow()
    try:
        db.session.commit()
        flash(ami_label + " ami deleted from SOCA", "success")
        logger.info(f"AMI Label {ami_label} deleted from SOCA")
        return redirect('/admin/ami_management')
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        flash(ami_label + " ami delete from SOCA failed", "error")
        logger.error(f"AMI Label {ami_label} delete failed {e}")
    return redirect('/admin/ami_management')