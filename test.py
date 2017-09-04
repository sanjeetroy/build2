from flask import Flask, render_template, redirect, url_for, request,send_from_directory
from flask_bcrypt import Bcrypt

from datetime import datetime, timedelta
import jwt
import json
import sqlite3 as db
import random
import string
import time
import os
import os.path

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_MINUTES = 20

BASE_DIR = "/Users/sanjeet.roy/Desktop/webserver-1.2"
db_path = os.path.join(BASE_DIR, "testDB.db")

conn = db.connect(db_path,check_same_thread=False)
curs = conn.cursor()

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/Users/sanjeet.roy/Desktop/build2',template_folder = '/Users/sanjeet.roy/Desktop/build2')
bcrypt =  Bcrypt(app)

def get_jti():
    system_random = random.SystemRandom()
    jti_length = system_random.randint(16, 128)
    ascii_alphabet = string.ascii_letters + string.digits
    ascii_len = len(ascii_alphabet)
    jti = ''.join(ascii_alphabet[int(system_random.random() * ascii_len)] for _ in range(jti_length))
    return jti

def insert_jti(jti,status):
    curs.execute("insert into jtiTb values (?,?)", (jti,status))
    conn.commit()
    return

def logout_jti(jti):
    query = "update jtiTb set status= 'logged-out' where jti=?"
    curs.execute(query,(jti,))
    conn.commit()
    return

def check_user(name,input_pass):
    if name != '' and input_pass != '':
        query = "select pass from users where username=?";
        curs.execute(query,(name,))
        result = curs.fetchone()

        if result != None:
            retrieve_pass = result[0]
            if bcrypt.check_password_hash(retrieve_pass,input_pass):
                jti = get_jti()
                insert_jti(jti,"logged-in")

                payload = {
                    'user_id': name,
                    'exp': datetime.utcnow() + timedelta(minutes=JWT_EXP_DELTA_MINUTES),
                    'jti': jti
                }

                jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
                return jwt_token,True


    return '',False

@app.route('/<path:path>')
def send_js(path):
    print path
    return send_from_directory('/Users/sanjeet.roy/Desktop/build2',path)

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
    	token,useris_logged_in = check_user(request.form['username'],request.form['password'])
        #if request.form['username'] != 'admin' or request.form['password'] != 'admin':
        if useris_logged_in == False:
            error = 'Invalid Credentials. Please try again.'
        else:
            #return redirect(url_for('home'))
            #return redirect('/index.html')
            redirect_to_index = redirect('/index.html')
            response = app.make_response(redirect_to_index )
            response.set_cookie('access_token',value=token)
            return response

    return render_template('login.html', error=error)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    print "in logout"
    expire_token_value = 'deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
    try:
        access_token = request.cookies['access_token']
        print "receive cookie = ", access_token
        jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        print "token decoded Successfully"
        print "jit = ",jwt_token['jti']
        logout_jti(jwt_token['jti'])
        print "logged-out of DB"
    except:
        print 'Invalid Access Token Found'

    redirect_to_index = redirect('/')
    response = app.make_response(redirect_to_index )
    response.set_cookie('access_token',value=expire_token_value)
    return response

if __name__ == "__main__":
    app.run()
