import json
from flask import Flask, jsonify, render_template, url_for, request, session, redirect, flash
from flask_session import Session
from flask_pymongo import PyMongo
from pymongo.errors import PyMongoError
from pymongo.mongo_client import MongoClient
import configparser
import bcrypt
import requests
import shodan
from shodan import Shodan
from apify_client import ApifyClient
import joblib
from sklearn.feature_extraction.text import CountVectorizer


config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.config["SECRET_KEY"] = config['Database']['secret_key']
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

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
        terms = term.split(',') 
        terms = [term.lower() for term in terms]   
        print(terms)

        url = url + terms[0]

        response = requests.get(url)
        
        data = json.loads(response.text)
        
        results = []
        for paste in data:
            text = paste['text'].lower()
            if all(term in text for term in terms):
                results.append(paste)
        print(results)   
        
        #print(response.json())
        return render_template('checkPastes.html', result = results ,username=session['username'])
        #return render_template('checkAccount.html', results=response.json)
    
@app.route('/footprinting', methods = ['POST', 'GET'])
def footprinting():
    if request.method == 'GET':
        return render_template('footprinting.html', username=session['username'])
    if request.method == 'POST':
        shodan_key = config['API']['shodan_key']
        api = Shodan(shodan_key)

        ip = request.form.get('ip')
        host = api.host(ip)

        output = """
            IP: {}
            Organization: {}
            Operating System: {}
        """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

        # Concatenate all banners to the output string
        for item in host['data']:
            output += """
                Port: {}
                Banner: {}

            """.format(item['port'], item['data'])
        return render_template('footprinting.html', result = output ,username=session['username'])

    
@app.route('/checkNews', methods = ['POST', 'GET'])
def checkNews():
    if request.method == 'GET':
        model = joblib.load('random_forest.pkl')
        client = ApifyClient(config['API']['apify_key'])
        
        username = session['username']
        tweets_key = username + '_tweets'
        
        if tweets_key not in session:
            tweets = []
            run_input = {
                #"searchTerms": ["apify"],
                "searchMode": "live",
                "maxTweets": 10,
                "maxRequestRetries": 2,
                "addUserInfo": False,
                "scrapeTweetReplies": False,
                #"handle": ["@cnn"],
                "urls": ["https://twitter.com/search?q=%23cybersecuritynews&src=typeahead_click&f=live"],
            }

            # Run the Actor and wait for it to finish
            run = client.actor("heLL6fUofdPgRXZie").call(run_input=run_input)

            # Fetch and print Actor results from the run's dataset (if there are any)
            for item in client.dataset(run["defaultDatasetId"]).iterate_items():
                tweets.append(item)
            
            texts = [tweet['full_text'] for tweet in tweets]
            
            vectorizer = joblib.load('vectorizer_random_forest.pkl')
            vector_text = vectorizer.transform(texts)
            predictions = model.predict(vector_text)
            
            for tweet, prediction in zip(tweets, predictions):
                tweet['prediction'] = int(prediction)
            
            session[tweets_key] = tweets
        else:
            tweets = session[tweets_key]
        # Prepare the Actor input
        
        
        return render_template('checkNews.html', result = tweets, username=session['username'])
    

@app.route('/logout')
def logout():
    username = session['username']
    session.pop('username', None)
    session.pop(username + '_tweets', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
    app.run()