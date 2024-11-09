from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('job_tracker.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY,
        job_title TEXT NOT NULL,
        company TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT,
        link TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )''')
    conn.close()

init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], email=user[2])
    return None

# Route for the landing page
@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

# Route for the about page
@app.route('/about')
def about():
    return render_template('about.html')

# Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        conn = sqlite3.connect('job_tracker.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists. Please try again.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('job_tracker.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):
            login_user(User(id=user[0], username=user[1], email=user[2]))
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')
# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()

    # Total Applications
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ?", (current_user.id,))
    total_applications = cursor.fetchone()[0]

    # Pending Interviews
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ? AND status = 'Pending'", (current_user.id,))
    pending_interviews = cursor.fetchone()[0]

    # Successful Applications
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ? AND status = 'Accepted'", (current_user.id,))
    successful_applications = cursor.fetchone()[0]

    conn.close()

    # Pass these statistics to the template
    return render_template('dashboard.html', total_applications=total_applications, 
                           pending_interviews=pending_interviews, 
                           successful_applications=successful_applications)

# Route for the main index page (assuming it shows all job applications)
@app.route('/index')
@login_required
def index():
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE user_id = ?", (current_user.id,))
    applications = cursor.fetchall()
    conn.close()
    return render_template('index.html', applications=applications)

# Route for adding a job application
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_application():
    if request.method == 'POST':
        job_title = request.form['job_title']
        company = request.form['company']
        status = request.form['status']
        notes = request.form['notes']
        link = request.form['link']
        
        conn = sqlite3.connect('job_tracker.db')
        conn.execute("INSERT INTO applications (job_title, company, status, notes, link, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                     (job_title, company, status, notes, link, current_user.id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('add.html')

# Route for editing a job application
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_application(id):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id=? AND user_id=?", (id, current_user.id))
    application = cursor.fetchone()
    conn.close()
    
    if application is None:
        flash("Application not found or access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        job_title = request.form['job_title']
        company = request.form['company']
        status = request.form['status']
        notes = request.form['notes']
        link = request.form['link']
        
        conn = sqlite3.connect('job_tracker.db')
        conn.execute("UPDATE applications SET job_title=?, company=?, status=?, notes=?, link=? WHERE id=? AND user_id=?",
                     (job_title, company, status, notes, link, id, current_user.id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    return render_template('edit.html', application=application)

# Route for deleting a job application
@app.route('/delete/<int:id>')
@login_required
def delete_application(id):
    conn = sqlite3.connect('job_tracker.db')
    conn.execute("DELETE FROM applications WHERE id=? AND user_id=?", (id, current_user.id))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
