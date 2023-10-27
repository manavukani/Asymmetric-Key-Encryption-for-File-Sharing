from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_session import Session
import sqlite3
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import io
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret-key'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password TEXT NOT NULL, 
                public_key TEXT NOT NULL, 
                private_key TEXT NOT NULL)''')
# c.execute('''CREATE TABLE IF NOT EXISTS mes (id INTEGER PRIMARY KEY, sender_username TEXT NOT NULL, receiver_username TEXT NOT NULL, encrypted_message TEXT, filename TEXT,encrypted_file BLOB )''')
c.execute('''CREATE TABLE IF NOT EXISTS mes1 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_username TEXT NOT NULL,
    receiver_username TEXT NOT NULL,
    encrypted_message TEXT NOT NULL,
    filename TEXT,
    encrypted_file TEXT,
    date_time DATETIME NOT NULL,
    FOREIGN KEY (sender_username) REFERENCES users (username),
    FOREIGN KEY (receiver_username) REFERENCES users (username)
)''')

conn.commit()
conn.close()

def generate_key_pair():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')
    return public_key, private_key

@app.route('/')
def index():
    return render_template('/login.html')

@app.route('/signup', methods=['GET'])
def register():
    return render_template('/signup.html')

@app.route('/signup', methods=['POST'])

def signup():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # generate key pair for new user
        public_key, private_key = generate_key_pair()

        # save user data in database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username, ))
        result = c.fetchone()

        if result:
            error = 'Username already exists'
            return render_template('signup.html', error=error)
        c.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)", (username, password, public_key, private_key))
        conn.commit()
        conn.close()
        session['username'] = username
        flash('Account created successfully')
        return redirect(url_for('home'))
    else:
        return render_template('signup.html')
    
@app.route('/login', methods=['GET'])
def reg():
    return render_template('/login.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        result = c.fetchone()
        conn.close()
        
        if result:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Incorrect username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')
    
@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in to view your home page.')
        return redirect(url_for('login'))
    username = session['username']
    return render_template('home.html', username=username)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        flash('Please log in to send a message.')
        return redirect(url_for('signin'))

    sender_username = session['username']
    receiver_username = request.form['recipient']
    message = request.form['message']
    file = request.files.get('file')

    if sender_username == receiver_username:
        error = 'You cannot send a message to yourself.'
        return render_template('home.html', error=error)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''SELECT public_key FROM users WHERE username=?''', (receiver_username,))
    result = c.fetchone()

    if not result:
        error = 'No user exists with that username.'
        return render_template('home.html', error=error)

    receiver_public_key = result[0]
    receiver_key = RSA.import_key(receiver_public_key)
    cipher = PKCS1_OAEP.new(receiver_key)

    encrypted_message = b64encode(cipher.encrypt(message.encode('utf-8'))).decode('utf-8')
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if file:
        file_contents = file.read()
        print(file_contents)
        encrypted_file_contents = b64encode(cipher.encrypt(file_contents)).decode('utf-8')
        filename = file.filename
        file_type = filename.split('.')[-1]
        print(file_type)
        c.execute('''INSERT INTO mes1 (sender_username, receiver_username, encrypted_message, filename, encrypted_file, date_time)
                     VALUES (?, ?, ?, ?, ?, ?)''', (sender_username, receiver_username, encrypted_message, filename, encrypted_file_contents, time))
    else:
        c.execute('''INSERT INTO mes1 (sender_username, receiver_username, encrypted_message, date_time)
                     VALUES (?, ?, ?, ?)''', (sender_username, receiver_username, encrypted_message, time))

    conn.commit()
    conn.close()

    flash('Message sent successfully.')
    return redirect(url_for('home'))


@app.route('/view_messages')
def view_messages():
    if 'username' not in session:
        flash('Please log in to view messages.')
        return redirect(url_for('signin'))

    username = session['username']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''SELECT sender_username, encrypted_message, filename, encrypted_file, date_time FROM mes1 WHERE receiver_username=? order by date_time desc''', (username,))
    messages = c.fetchall()

    decrypted_messages = []
    private_key = c.execute('''SELECT private_key FROM users WHERE username=?''', (username,)).fetchone()[0]
    for message in messages:
        sender_username, encrypted_message, filename, encrypted_file, date_time = message
        # sender_public_key = se(sender_username)
        sender_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(sender_key)
        decrypted_message = cipher.decrypt(b64decode(encrypted_message)).decode('utf-8')
        decrypted_file = None
        if encrypted_file:
            decrypted_file = cipher.decrypt(b64decode(encrypted_file)).decode('utf-8')
        decrypted_messages.append((sender_username, decrypted_message, filename, decrypted_file, date_time))

    conn.close()
    return render_template('message.html', messages=decrypted_messages)

@app.route('/download/<file_name>')
def download_file(file_name):
    file_name = str(file_name)
    # Retrieve the file from the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    username = session['username']
    c.execute("SELECT encrypted_file FROM mes1 WHERE filename=? AND receiver_username=?", (file_name, username))
    encrypted_file = c.fetchone()[0]

    private_key = c.execute('''SELECT private_key FROM users WHERE username=?''', (username,)).fetchone()[0]
    sender_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(sender_key)
    # file_contents = file.read()
    # encrypted_file_contents = b64encode(cipher.encrypt(file_contents)).decode('utf-8')
    conn.close()
    decrypted_file = None
    if encrypted_file:
        decrypted_file = cipher.decrypt(b64decode(encrypted_file))
    
    # Create an in-memory file object
    file_stream = io.BytesIO(decrypted_file)
    # mtype = ""
    # if file_type == 'txt':
    #     mtype = "text/plain"
    # elif file_type == 'pdf':
    #     mtype = "application/pdf"
    # elif file_type == 'docx':
    #     mtype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    # Return the file as an attachment
    return send_file(file_stream, mimetype="text/plain", download_name=file_name)

@app.route('/logout')
def logout():
    session['username'] = None
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=8000, debug=True)