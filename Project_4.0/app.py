from flask import Flask, render_template, url_for, request, session, redirect, flash
from flask_pymongo import PyMongo
from pymongo.errors import PyMongoError
from pymongo.mongo_client import MongoClient
import bcrypt

app = Flask(__name__)
app.config["SECRET_KEY"] = "71382d27b4b3b5303c3bd99f68f0b725a032efd4"

#app.config['MONGO_DBNAME'] = 'users'
app.config["MONGO_URI"] = "mongodb+srv://adamcdan:Ie3Bx4NVdXIEII5m@cluster0.l12dwnm.mongodb.net/?retryWrites=true&w=majority"

client = MongoClient("mongodb+srv://adamcdan:Ie3Bx4NVdXIEII5m@cluster0.l12dwnm.mongodb.net/?retryWrites=true&w=majority")

'''
uri = "mongodb+srv://adamcdan:Ie3Bx4NVdXIEII5m@cluster0.l12dwnm.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
client = MongoClient(uri)
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
'''
try:
    mongo = PyMongo(app)
    db = client.users["users"]
except PyMongoError as e:
    print(f"Error connecting to MongoDB: {e}")

try:
    mongo.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

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


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
    app.run()