from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'flak.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('main'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['hash'], password):
            session['user_id'] = user['user_id']
            return redirect(url_for('main'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hash = generate_password_hash(password)
        
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, hash) VALUES (?, ?)', (username, hash))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/main')
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('main.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/post')
def post():
    return render_template('post.html')


if __name__ == '__main__':
    app.run(debug=True)

#테스트 장상협