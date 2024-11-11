from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3
from io import BytesIO
import calendar
from datetime import datetime 
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Folder for storing profile pictures
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image formats

bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Initialize the SQLite database
def init_db():
    #code to clear the database
    # conn = sqlite3.connect('job_tracker.db')
    # cursor = conn.cursor()

    # # Get the list of all table names in the database
    # cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    # tables = cursor.fetchall()

    # # Drop each table
    # for table in tables:
    #     table_name = table[0]
    #     cursor.execute(f"DROP TABLE IF EXISTS {table_name}")

    # conn.commit()
    # conn.close()
    #code ends here
    conn = sqlite3.connect('job_tracker.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY,
        job_title TEXT NOT NULL,
        company TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT,
        link TEXT,
        user_id INTEGER NOT NULL,
        date_applied DATETIME DEFAULT CURRENT_TIMESTAMP,
        reminder DATETIME,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        bio TEXT,
        profile_pic BLOB
    )''')
    conn.close()

init_db()
#---------------------------------------------

# ---------User class for Flask-Login---------

class User(UserMixin):
    def __init__(self, id, username, email, bio=None, profile_pic=None):
        self.id = id
        self.username = username
        self.email = email
        self.bio = bio
        self.profile_pic = profile_pic

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], email=user[2], bio=user[4], profile_pic=user[5])
    return None
#---------------------------------------------

#---------User Authentication---------

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
            return render_template('register.html', error="Username or email already exists. Please try again.")
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
            login_user(User(id=user[0], username=user[1], email=user[2], bio=user[3], profile_pic=user[4]))
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # If login fails, pass an error message to the template
            return render_template('login.html', error="Invalid email or password")

    return render_template('login.html')

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))
#---------------------------------------------

#---------Forgot Password---------

# Function to get a user by their email

# Configure mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Or any other SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Get from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Get from .env
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Get from .env
mail = Mail(app)

# URL Safe Token Serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if the email exists in your database
        user = get_user_by_email(email)
        if user:
            # Generate a reset password token
            token = s.dumps(email, salt='reset-password')

            # Send email with the reset password link
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender='MAIL_USERNAME',
                          recipients=[email])
            msg.body = f'Click on the link to reset your password: {reset_url}'
            mail.send(msg)
            flash('A password reset link has been sent to your email address.', 'success')
        else:
            flash('Email not found. Please check your email and try again.', 'error')

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Try to load the email from the token
        email = s.loads(token, salt='reset-password', max_age=3600)  # Token expires after 1 hour
    except:
        flash('The link has expired or is invalid.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # Update the user's password in the database
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        update_user_password(email, new_password)
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email, token=token)

def get_user_by_email(email):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to update a user's password
def update_user_password(email, new_password):
    try:
        conn = sqlite3.connect('job_tracker.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        conn.commit()
    except sqlite3.Error as e:
        print("An error occurred:", e)  # Log the error for debugging
        return False  # Indicate failure
    finally:
        conn.close()
    return True  # Indicate success
#---------------------------------------------

#---------Route for webpages---------

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


@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()

    # Fetch the user's username
    cursor.execute("SELECT username FROM users WHERE id = ?", (current_user.id,))
    username = cursor.fetchone()[0]

    # Total Applications
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ?", (current_user.id,))
    total_applications = cursor.fetchone()[0]

    # Pending Interviews
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ? AND status = 'Pending'", (current_user.id,))
    pending_interviews = cursor.fetchone()[0]

    # Successful Applications
    cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id = ? AND status = 'Accepted'", (current_user.id,))
    successful_applications = cursor.fetchone()[0]

    # Monthly Applications (grouped by month)
    cursor.execute("""
        SELECT strftime('%Y-%m', date_applied) AS month, COUNT(*) AS applications
        FROM applications
        WHERE user_id = ?
        GROUP BY month
        ORDER BY month DESC
    """, (current_user.id,))
    monthly_data = cursor.fetchall()

    # Most recent 3 reminders with formatted date
    cursor.execute("""
        SELECT job_title, company, reminder
        FROM applications
        WHERE user_id = ?
        AND reminder IS NOT NULL
        AND reminder != ''
        ORDER BY reminder
        LIMIT 3
    """, (current_user.id,))
    recent_reminders = cursor.fetchall()

   # Format the reminder datetime into a more readable format
    formatted_reminders = []
    for reminder in recent_reminders:
        job_title, company, reminder_datetime = reminder
        if reminder_datetime:  # Check if the reminder is not empty or NULL
            # Convert the reminder string to a datetime object
            reminder_obj = datetime.strptime(reminder_datetime, '%Y-%m-%dT%H:%M')
            # Format the datetime to a human-readable format
            formatted_reminder = reminder_obj.strftime('%B %d, %Y at %I:%M %p')  # Format: November 15, 2024 at 10:20 AM
        else:
            formatted_reminder = "No reminder set"  # Default message if reminder is empty

        formatted_reminders.append((job_title, company, formatted_reminder))

    conn.close()

    # Process the monthly data to separate months and counts
    months = [data[0] for data in monthly_data]
    application_counts = [data[1] for data in monthly_data]

    # Get the current month and create a list of the last 6 months (from the current month)
    current_month = datetime.now().month
    all_months = [calendar.month_name[(current_month - i) % 12] for i in range(6)]
    all_months = list((all_months))  # Reverse so it starts from the current month

    # Ensure that even months with no applications are displayed (by checking and filling with 0)
    all_application_counts = []
    for month in all_months:
        if months and months[-1] == f"{datetime.now().year}-{str(current_month).zfill(2)}":
            all_application_counts.append(application_counts.pop())
        elif months and months[-1][:7] == f"{datetime.now().year}-{str(current_month).zfill(2)}":
            all_application_counts.append(application_counts.pop())
        else:
            all_application_counts.append(0)
        current_month -= 1

    # Monthly goal and progress calculation
    monthly_goal = 10
    current_month_applications = all_application_counts[0] if all_application_counts else 0
    progress_percentage = (current_month_applications / monthly_goal) * 100 if monthly_goal else 0

    # Pass the statistics and chart data to the template
    return render_template(
        'dashboard.html',
        total_applications=total_applications,
        pending_interviews=pending_interviews,
        successful_applications=successful_applications,
        username=username,
        months=all_months,
        application_counts=all_application_counts,
        monthly_goal=monthly_goal,
        current_month_applications=current_month_applications,
        progress_percentage=progress_percentage,
        recent_reminders=formatted_reminders  # Pass formatted reminders
    )


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
#---------------------------------------------

#---------Job Application---------

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
        reminder = request.form['reminder']
        
        conn = sqlite3.connect('job_tracker.db')
        # conn.execute("INSERT INTO applications (job_title, company, status, notes, link, user_id) VALUES (?, ?, ?, ?, ?, ?)",
        #              (job_title, company, status, notes, link, current_user.id))
        conn.execute("INSERT INTO applications (job_title, company, status, notes, link, user_id, date_applied, reminder) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)",
                    (job_title, company, status, notes, link, current_user.id, reminder))
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
#---------------------------------------------

#---------Profile---------

# Route for My Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        bio = request.form['bio']
        profile_pic = request.files['profile-pic'] if 'profile-pic' in request.files else None

        # Connect to the database
        conn = sqlite3.connect('job_tracker.db')
        cursor = conn.cursor()

        # Check if the new username is already in use by another user
        cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, current_user.id))
        existing_username_user = cursor.fetchone()
        
        # Check if the new email is already in use by another user
        cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, current_user.id))
        existing_email_user = cursor.fetchone()

        if existing_username_user:
            conn.close()
            return render_template('profile.html', error="Username is already in use. Please choose a different username.")

        if existing_email_user:
            conn.close()
            return render_template('profile.html', error="Email is already in use. Please use a different email.")
        
        # Update user information
        cursor.execute("UPDATE users SET username = ?, email = ?, bio = ? WHERE id = ?", (username, email, bio, current_user.id))
        conn.commit()

        # Handle Profile Picture Upload as BLOB
        if profile_pic and allowed_file(profile_pic.filename):
            profile_pic_binary = BytesIO(profile_pic.read()).getvalue()
            cursor.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (profile_pic_binary, current_user.id))
            conn.commit()

        conn.close()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Render the profile page with the current user's data
    return render_template('profile.html', 
                           username=current_user.username, 
                           email=current_user.email, 
                           bio=current_user.bio, 
                           profile_pic=current_user.profile_pic)

# Helper route to serve profile picture
@app.route('/profile_pic/<int:user_id>')
def profile_pic(user_id):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT profile_pic FROM users WHERE id = ?", (user_id,))
    profile_pic_binary = cursor.fetchone()[0]
    conn.close()

    if profile_pic_binary:
        return send_file(BytesIO(profile_pic_binary), mimetype='image/jpeg')
    else:
        return redirect(url_for('static', filename='user.jpg'))
#---------------------------------------------

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
