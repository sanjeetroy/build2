from flask import Flask, render_template, redirect, url_for, request,send_from_directory
# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/Users/sanjeet.roy/Desktop/build2',template_folder = '/Users/sanjeet.roy/Desktop/build2')

@app.route('/<path:path>')
def send_js(path):
    print path
    return send_from_directory('/Users/sanjeet.roy/Desktop/build2',path)

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            #return redirect(url_for('home'))
            return redirect('/index.html')
    return render_template('login.html', error=error)

if __name__ == "__main__":
    app.run()
