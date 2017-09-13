from flask import Flask, render_template, redirect, url_for, request,send_from_directory,jsonify
from flask_bcrypt import Bcrypt

from datetime import datetime, timedelta
import jwt
import json
import sqlite3 as db
import random
import string
import os
import os.path

JWT_SECRET = ''
file_r = open('/Users/sanjeet.roy/.vsaq_secret.txt','r')
JWT_SECRET = file_r.readline()
file_r.close()

JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_MINUTES = 20

BASE_DIR = "/Users/sanjeet.roy/Desktop/webserver-1.2"
db_path = os.path.join(BASE_DIR, "testDB.db")

conn = db.connect(db_path,check_same_thread=False)
curs = conn.cursor()

# set the project root directory as the static folder, you can set others.
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_url_path=APP_ROOT,template_folder = APP_ROOT)
bcrypt =  Bcrypt(app)

answer_from = ''

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

def get_jti_status(jti):
    query = "select status from jtiTb where jti=?"
    curs.execute(query,(jti,))
    result = curs.fetchone()

    if result != None:
        return result[0]
    else:
        return 'logged-out'

def is_user_loggedin(jti):
    login_status = get_jti_status(jti)

    if login_status == 'logged-in':
        return True
    return False

def save_answer(emailId,questionnaireId,answer):
    already_exists = get_answer(emailId,questionnaireId)

    if already_exists == None:
        curs.execute("insert into questionnaire_answer values (?,?,?)", (emailId,questionnaireId,answer))
        conn.commit()
        print "Answer has been successfully saved."
        return
    else:
        query = "update questionnaire_answer set answer= ? where emailId=? and questionnaireId=?"
        curs.execute(query,(answer,emailId,questionnaireId,))
        conn.commit()
        print "Answer has been successfully saved."
        return

def get_answer(emailId,questionnaireId):
    query = "select answer from questionnaire_answer where emailId=? and questionnaireId = ?"
    curs.execute(query,(emailId,questionnaireId,))
    result = curs.fetchone()

    if result != None:
        return result[0]
    else:
        return None

@app.errorhandler(404)
def page_not_found(e):
    return 'This page isn\'t available',404
    
@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

@app.route('/<path:path>')
def send_js(path):
    print path
    # r = raw_input("please input....")
    return send_from_directory(APP_ROOT,path)

@app.route('/',methods=['GET'])
def home():
    error = None
    return render_template('login.html', error=error)

@app.route('/vsaq.html')
def vsaq():
    try:
        access_token = request.cookies['access_token']
        print "receive cookie = ", access_token
    except:
        return redirect('/')

    try:
        jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
    except jwt.InvalidTokenError:
        return redirect('/')
        
    print "token decoded Successfully"
    print "jit = ",jwt_token['jti']

    login_status = is_user_loggedin(jwt_token['jti'])
    if login_status == False:
        return redirect('/')

    return render_template('vsaq.html',)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        token,useris_logged_in = check_user(request.form['username'],request.form['password'])
        if useris_logged_in == False:
            error = 'Invalid Credentials. Please try again.'
        else:
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

@app.route('/submit', methods=['GET','POST'])
def submit():
    error = None
    if request.method == 'POST':
        try:
            
            try:
                access_token = request.cookies['access_token']
                print "receive cookie = ", access_token
            except:
                return '',401
            try:
                jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
            except jwt.InvalidTokenError:
                return '',401
            print "token decoded Successfully"
            print "jit = ",jwt_token['jti']

            login_status = is_user_loggedin(jwt_token['jti'])

            if login_status == True:
                req_id = request.values['id']
                req_answers = request.values['answers']
                req_xsrf = request.values['_xsrf_']
                print "req_answers = ",req_answers

                email = jwt_token['user_id']
                save_answer(email,req_id,req_answers)
                return '',200
            else:
                # return render_template('index.html', error=error)
                return '',401

        except Exception as e:
            print e
            print 'Invalid Access Token Found hey'
    return

@app.route('/load', methods=['GET','POST'])
def load():
    error = None
    if request.method == 'POST':
        try:
            try:
                access_token = request.cookies['access_token']
                print "receive cookie = ", access_token
            except:
                return '',401
            try:
                jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
            except jwt.InvalidTokenError:
                return '',401
            print "token decoded Successfully"
            print "jit = ",jwt_token['jti']

            login_status = is_user_loggedin(jwt_token['jti'])

            if login_status == True:
                req_id = request.values['id']

                email = jwt_token['user_id']
                answer = get_answer(email,req_id)

                if answer != None:
                    return answer,200
                return ''
            else:
                return '',401

        except Exception as e:
            print e
            print 'Invalid Access Token Found'
    return

if __name__ == "__main__":
    app.run()
