import json
from flask import Flask, jsonify, render_template, url_for, request, session, redirect, flash
from flask_pymongo import PyMongo
from pymongo.errors import PyMongoError
from pymongo.mongo_client import MongoClient
#from flask_session import Session
import configparser
import bcrypt
import requests

config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.config["SECRET_KEY"] = config['Database']['secret_key']

#app.config['MONGO_DBNAME'] = 'users'
#app.config['SESSION_TYPE'] = 'mongodb'
URI = config['Database']['Mongo_URI']
app.config["MONGO_URI"] = config['Database']['Mongo_URI']


client = MongoClient(URI)

try:
    #mongo = PyMongo(app)
    db = client.users["users"]
    #Session(app)
except PyMongoError as e:
    print(f"Error connecting to MongoDB: {e}")
    
    
@app.route("/")
@app.route("/main")
def main():
    return render_template('index.html')


@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        users = db.users
        signup_user = users.find_one({'username': request.form['username']})

        if signup_user:
            flash(request.form['username'] + ' username is already exist')
            return redirect(url_for('signup'))

        hashed = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt(14))
        users.insert_one({'username': request.form['username'], 'password': hashed, 'email': request.form['email']})
        return redirect(url_for('signin'))

    return render_template('signup.html')

@app.route('/index')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])

    return render_template('index.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        users = db.users
        signin_user = users.find_one({'username': request.form['username']})

        if signin_user:
            if bcrypt.hashpw(request.form['password'].encode('utf-8'), signin_user['password']) == \
                    signin_user['password']:
                session['username'] = request.form['username']
                return redirect(url_for('index'))

        flash('Username and password combination is wrong')
        return render_template('signin.html')

    return render_template('signin.html')

@app.route('/checkAccount', methods = ['POST', 'GET'])
def checkAccount():
    if request.method == 'GET':
        return render_template('checkAccount.html', username=session['username'])
    if request.method == 'POST':
        url = "https://email-data-leak-checker.p.rapidapi.com/emaild"

        querystring = {"email": request.form.get('account')}

        headers = {
	        "User-Agent": "application-name",
	        "Content-Type": "application/json",
	        "X-RapidAPI-Key": config['API']['email_data_leak_checker_key'],
	        "X-RapidAPI-Host": "email-data-leak-checker.p.rapidapi.com"
        }

        response = requests.get(url, headers=headers, params=querystring)
        print(response.json())
        return render_template('checkAccount.html', result = response.json() ,username=session['username'])
        #return render_template('checkAccount.html', results=response.json)

@app.route('/checkURL', methods = ['POST', 'GET'])
def checkURL():
    if request.method == 'GET':
        return render_template('checkURL.html', username=session['username'])
    if request.method == 'POST':


        url = "https://www.virustotal.com/api/v3/urls"

        if not request.form.get('URL'):
            return render_template('checkFile.html', result = "No input detected" ,username=session['username'])
        
        payload = { "url": request.form.get('URL') }
        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key'],
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post(url, data=payload, headers=headers)
        data = response.json()
        print(data)
        id = data['data']['id']

        print(response.text)

        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        result = requests.get(url, headers=headers)
        data = result.json()
        stats = data['data']['attributes']['stats']

        print(stats)

        #print(response.json())
        return render_template('checkURL.html', result = stats ,username=session['username'])
        #return render_template('checkAccount.html', results=response.json)


@app.route('/checkFile', methods = ['POST', 'GET'])
def checkRoute():
    if request.method == 'GET':
        return render_template('checkFile.html', username=session['username'])
    if request.method == 'POST':


        url = "https://www.virustotal.com/api/v3/files"

        file = request.files['file']
        if not file:
            return render_template('checkFile.html', result = "Unable to pass file to the server" ,username=session['username'])
        file.save(file.filename)

        #payload = { "url": request.form.get('file') }
        files = { "file": (file.filename, open(file.filename, "rb"), "text/plain") }
        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        response = requests.post(url, files=files, headers=headers)
        data = response.json()
        id = data['data']['id']

        ################################################

        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        result = requests.get(url, headers=headers)
        data = result.json()
        stats = data['data']['attributes']['stats'] 

        return render_template('checkFile.html', result = stats ,username=session['username'])
    
@app.route('/checkPastes', methods = ['POST', 'GET'])
def checkPastes():
    if request.method == 'GET':
        return render_template('checkPastes.html', username=session['username'])
    if request.method == 'POST':
        url = "https://psbdmp.ws/api/v3/search/"

        term = request.form.get('terms')
        print(term)

        url = url + term

        response = requests.get(url)
        print(response.json())
        return render_template('checkPastes.html', result = response.json() ,username=session['username'])
        #return render_template('checkAccount.html', results=response.json)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
    app.run()