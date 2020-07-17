import base64
import os
import config
import requests
from flask import session
from jose import jwt
from requests import get

'''
To enable SSO auth via cognito, update COGNITO section on config.py
https://awslabs.github.io/scale-out-computing-on-aws/security/integrate-cognito-sso/
'''


def sso_authorization(code):
    authorization = 'Basic ' + base64.b64encode((config.Config.COGNITO_APP_ID + ':' + config.Config.COGNITO_APP_SECRET).encode()).decode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Authorization': authorization}

    data = {'grant_type': 'authorization_code',
            'client_id': config.Config.COGNITO_APP_ID,
            'code': code,
            'redirect_uri': config.Config.COGNITO_CALLBACK_URL}

    oauth_token = requests.post(config.Config.COGNITO_OAUTH_TOKEN_ENDPOINT, data=data, headers=headers).json()
    id_token = oauth_token['id_token']
    access_token = oauth_token['access_token']
    headers = jwt.get_unverified_headers(id_token)
    keys = requests.get(config.Config.COGNITO_JWS_KEYS_ENDPOINT).json().get('keys')
    key = list(filter(lambda k: k['kid'] == headers['kid'], keys)).pop()
    claims = jwt.decode(id_token, key, access_token=access_token, algorithms=[key['alg']], audience=config.Config.COGNITO_APP_ID)
    if claims:
        try:
            user = claims['email'].split('@')[0]
        except Exception as err:
            return {'success': False,
                    'message': 'Error reading SSO claims. ' + str(claims) + ' Err: ' + str(err)}

        # Simply check if user exist
        check_user = get(config.Config.FLASK_ENDPOINT + "/api/ldap/user",
                         headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                         params={"user": user},
                         verify=False)
        if check_user.status_code == 200:
            session['user'] = user

            return {'success': True,
                    'message': ''}
        else:
            return {'success': False,
                    'message': 'user_not_found'}
    else:
        return {'success': False,
                'message': 'SSO error. ' + str(claims)}