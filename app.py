from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('job_tracker.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY,
        job_title TEXT NOT NULL,
        company TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT
        link TEXT
    )''')
    conn.close()

init_db()

@app.route('/')
def index():
    # status = request.args.get('status')
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications")
    applications = cursor.fetchall()
    conn.close()
    return render_template('index.html', applications=applications)

@app.route('/add', methods=['GET', 'POST'])
def add_application():
    if request.method == 'POST':
        job_title = request.form['job_title']
        company = request.form['company']
        status = request.form['status']
        notes = request.form['notes']
        link = request.form['link']
        conn = sqlite3.connect('job_tracker.db')
        conn.execute("INSERT INTO applications (job_title, company, status, notes, link) VALUES (?, ?, ?, ?, ?)",
                     (job_title, company, status, notes, link))
        conn.commit()
        conn.close()
        return redirect(url_for('index', status='added'))
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_application(id):
    conn = sqlite3.connect('job_tracker.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id=?", (id,))
    application = cursor.fetchone()
    conn.close()
    if request.method == 'POST':
        job_title = request.form['job_title']
        company = request.form['company']
        status = request.form['status']
        notes = request.form['notes']
        link = request.form['link']
        conn = sqlite3.connect('job_tracker.db')
        conn.execute("UPDATE applications SET job_title=?, company=?, status=?, notes=? ,link=? WHERE id=?",
                     (job_title, company, status, notes,link, id))
        conn.commit()
        conn.close()
        return redirect(url_for('index', status='edited'))
    return render_template('edit.html', application=application)

@app.route('/delete/<int:id>')
def delete_application(id):
    conn = sqlite3.connect('job_tracker.db')
    conn.execute("DELETE FROM applications WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index', status='deleted'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)