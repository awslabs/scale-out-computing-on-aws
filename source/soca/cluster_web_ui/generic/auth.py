from flask import session, redirect, request
from functools import wraps

def login_required(f):
    @wraps(f)
    def validate_account():
        if 'username' in session:
            return f()
        else:
           return redirect('/login')
    return validate_account

