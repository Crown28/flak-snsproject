from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from werkzeug.utils import secure_filename
path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'static', 'image', 'uploads')
POST_IMGPATH = os.path.join('static', 'image', 'uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DB_FOLDER'] = POST_IMGPATH

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
    conn = get_db_connection()
    users = conn.execute('SELECT user_id, username FROM users').fetchall()
    posts = conn.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.user_id').fetchall()
    conn.close()
    
    return render_template('main.html', users=users, posts=posts)

@app.route('/user/<int:user_id>')
def user_page(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone() # 사용자 ID로, 실제 사용자 ID 값으로 대체해야 합니다.
    user_posts = conn.execute('''
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.user_id
    WHERE posts.user_id = ?
    ''', (user_id,)).fetchall()

    conn.close()
    
    return render_template('userpage.html', users=user, posts=user_posts)



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/post', methods=['GET', 'POST'])
def post():
    if request.method == 'POST':

        # 세션에서 사용자 ID 가져오기
        id = session.get("user_id")

        if id is None:
                flash('로그인 상태가 아닙니다.')
                return render_template('main.html')
        
        # 폼 데이터 처리
        content = request.form['content']  # 내용 처리
    
        # 파일 처리
        if 'user_file' not in request.files:
            return redirect(request.url)
        
        file = request.files['user_file']
        
        if file.filename == '':
            flash('파일이 선택되지 않았습니다.')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            relative_filepath = os.path.join(app.config['DB_FOLDER'],filename)
            print(relative_filepath)
            # 파일의 상대 경로 구하기
  

            file.save(filepath)
        else:
            flash('허용되지 않는 파일 형식입니다.')
            return redirect(request.url)
        
        # 데이터베이스 연결 및 데이터 삽입
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO posts (user_id, content, post_image) VALUES (?, ?, ?)', 
                    (id, content, relative_filepath))
        conn.commit()
        conn.close()

        flash('등록 성공!')
        return redirect(url_for('main'))
        
    else:
        # GET 요청 처리
        return render_template('post.html')


if __name__ == '__main__':
    app.run(debug=True)
