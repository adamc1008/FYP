import http
import json
import time
from bson import ObjectId
from flask import Flask, jsonify, render_template, url_for, request, session, redirect, flash
from flask_session import Session
from flask_pymongo import PyMongo
from pymongo.errors import PyMongoError
from pymongo.mongo_client import MongoClient
import configparser
import bcrypt
import requests
#import shodan
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
    notifications = client.users["notifications"]
    #Session(app)
except PyMongoError as e:
    print(f"Error connecting to MongoDB: {e}")
    
    
@app.route("/")
@app.route("/main")
def main():
    if 'username' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('signin'))


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
        ignore = {'username': False}
        data = list(notifications.find({'username': session['username']}, ignore))
        results = []
        for item in data:
            print(item)
            entry = eval(item["data"])
            entry["id"] = str(item["_id"])
            results.append(entry) 
            print(entry)
        print(results)
        return render_template('index.html', result = results, username=session['username'])
    else:
        return redirect(url_for('signin'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        users = db.users
        signin_user = users.find_one({'username': request.form['username']})

        if signin_user:
            if bcrypt.hashpw(request.form['password'].encode('utf-8'), signin_user['password']) == \
                    signin_user['password']:
                session['username'] = request.form['username']
                return redirect(url_for('info'))

        flash('Username and password combination is wrong')
        return render_template('signin.html')

    return render_template('signin.html')

@app.route('/info', methods=['GET'])
def info():
    return render_template('info.html',username=session['username'])

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
    past_results = get_past_results('URL')
    if request.method == 'GET':
        return render_template('checkURL.html', old_results = past_results, username=session['username'])
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
        
        time.sleep(20)

        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        result = requests.get(url, headers=headers)
        data = result.json()
        stats = data['data']['attributes']['stats']

        if(stats['malicious'] >= 4):
            risk = 1
        elif(stats['suspicious'] >= 10):
            risk = 2
        elif(stats['harmless'] >= 30 or stats['undetected'] >= 30):
            risk = 3
        else:
            risk = 0
        
        print(stats)
        print(payload["url"])
        output = {
            "title": payload["url"],
            "risk": risk,
            "type": "URL",
            "results" : {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "undetected": stats['undetected'],
                "timeout": stats['timeout']
            }
        }
        #print(response.json())
        return render_template('checkURL.html', result = output , old_results = past_results, username=session['username'])
        #return render_template('checkAccount.html', results=response.json)


@app.route('/checkFile', methods = ['POST', 'GET'])
def checkRoute():
    past_results = get_past_results('file')
    if request.method == 'GET':
        return render_template('checkFile.html', old_results= past_results, username=session['username'])
    if request.method == 'POST':


        url = "https://www.virustotal.com/api/v3/files"

        file = request.files['file']
        if not file:
            return render_template('checkFile.html', result = "Unable to pass file to the server" ,username=session['username'])
        file.save(file.filename)

        payload = { "url": request.form.get('file') }
        files = { "file": (file.filename, open(file.filename, "rb"), "text/plain") }
        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        response = requests.post(url, files=files, headers=headers)
        #conn.request("POST", "/api/v3/files", files, headers)
        
        data = response.json()
        #data = json.loads(conn.getresponse().read().decode("utf-8"))
        id = data['data']['id']

        ################################################

        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": config['API']['virus_total_key']
        }

        time.sleep(20)
        
        result = requests.get(url, headers=headers)
        data = result.json()
        stats = data['data']['attributes']['stats'] 
        
        if(stats['malicious'] >= 4):
            risk = 2
        elif(stats['suspicious'] >= 10):
            risk = 2
        elif(stats['harmless'] >= 30 or stats['undetected'] >= 30):
            risk = 3
        else:
            risk = 0
        
        output = {
            "title": file.filename,
            "risk": risk,
            "type": "file",
            "results" : {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "undetected": stats['undetected'],
                "timeout": stats['timeout'],
                "failure": stats['failure'],
                "type_unsupported": stats['type-unsupported'],
                "confirmed_timeout": stats['confirmed-timeout'],
            }
        }
        
        print(output)
        
        return render_template('checkFile.html', result = output, old_results= past_results, username=session['username'])
    
@app.route('/checkPastes', methods = ['POST', 'GET'])
def checkPastes():
    past_results = get_past_results('paste')
    if request.method == 'GET':
        return render_template('checkPastes.html', old_results=past_results, username=session['username'])
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
            print(paste)
            text = paste['text'].lower()
            if all(term in text for term in terms):
                paste['terms'] = terms
                results.append(paste)
        print(results)   
        
        #print(response.json())
        return render_template('checkPastes.html', result = results, old_results=past_results, username=session['username'])
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
        '''
        print(host)
        
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
            
        '''
        ports_info = []
        for item in host['data']:
            port_info = {
                'port': item['port'],
                'banner': item['data']
            }
            ports_info.append(port_info)
        
        output = {
            "IP": host['ip_str'],
            "Organization": host.get('org', 'n/a'),
            "Operating System": host.get('os', 'n/a'),
            "Ports": ports_info,
            "Domains": host.get('domains', 'n/a'),
            "hostname": host.get('hostnames', 'n/a')
        }
        
        print(output)
        
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
    
@app.route('/save', methods=['POST'])
def save_data():
    username = session['username']
    if username:
        data = request.form.get('card_to_save')
        #data = request.get_json()
        print("Raw form data:", request.form.to_dict())
        '''
        try:
            data_dict = json.loads(data)
        except json.JSONDecodeError:
            return "Invalid JSON data", 400
            '''
        print(data)
        document = {
            'username': username,
            'data': data
        }
        
        notifications.insert_one(document)
        return '', 204
    else:
        return "Unauthorized", 401
    
@app.route('/delete', methods=['POST'])
def delete_data():
    username = session['username']
    if username:
        data = request.form.get('card_to_delete')
        #data = request.get_json()
        print(data)
        print("Raw form data:", request.form.to_dict())
        '''
        try:
            data_dict = json.loads(data)
        except json.JSONDecodeError:
            return "Invalid JSON data", 400
            '''
        result = notifications.delete_one({'_id': ObjectId(data)})
        return redirect(url_for('index'))
    else:
        return "Unauthorized", 401
    

@app.route('/logout')
def logout():
    username = session['username']
    session.pop('username', None)
    session.pop(username + '_tweets', None)
    return redirect(url_for('index'))

def get_past_results(type):
    data = list(notifications.find( {'username': session['username'], 'data': {'$exists': True}}))
    past_results = []
    print(data)
    for item in data:
        print(item)
        entry = eval(item["data"])
        if entry.get('type') == type:
            entry['_id'] = str(item['_id'])
            past_results.append(entry) 
    return past_results

if __name__ == "__main__":
    app.run(debug=True)
    app.run()