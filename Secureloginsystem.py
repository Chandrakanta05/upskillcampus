from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"
DATABASE = "users.db"

STYLE = """
<style>
body{font-family:Arial;background:#f2f4f7;margin:0}
.box{width:380px;margin:70px auto;background:white;padding:30px;border-radius:12px;
box-shadow:0 5px 20px rgba(0,0,0,.12)}
h1,h2{text-align:center}input{width:100%;padding:11px;margin:8px 0 15px;
box-sizing:border-box;border:1px solid #ccc;border-radius:6px}
button{width:100%;padding:11px;background:#2563eb;color:white;border:0;border-radius:6px}
a{color:#2563eb;text-decoration:none}.msg{text-align:center;color:#c0392b}
.center{text-align:center}
</style>
"""

def db():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL
    )""")
    con.commit()
    con.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(STYLE + """
    <div class="box"><h1>Secure Login System</h1>
    <p class="center">Python Summer Internship Project</p>
    <p class="center"><a href="/login">Login</a> | <a href="/register">Register</a></p>
    </div>""")

@app.route("/register", methods=["GET","POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        password = request.form.get("password","")

        if not username or not email or not password:
            message = "All fields are required."
        elif len(password) < 6:
            message = "Password must contain at least 6 characters."
        else:
            try:
                con = db()
                con.execute(
                    "INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",
                    (username, email, hash_password(password))
                )
                con.commit()
                con.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                message = "Username or email already exists."

    return render_template_string(STYLE + """
    <div class="box"><h2>Create Account</h2>
    <p class="msg">{{message}}</p>
    <form method="POST">
    <label>Username</label><input name="username" required>
    <label>Email</label><input type="email" name="email" required>
    <label>Password</label><input type="password" name="password" required>
    <button>Register</button></form>
    <p class="center">Already registered? <a href="/login">Login</a></p>
    </div>""", message=message)

@app.route("/login", methods=["GET","POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        con = db()
        user = con.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        con.close()

        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        message = "Invalid username or password."

    return render_template_string(STYLE + """
    <div class="box"><h2>Login</h2>
    <p class="msg">{{message}}</p>
    <form method="POST">
    <label>Username</label><input name="username" required>
    <label>Password</label><input type="password" name="password" required>
    <button>Login</button></form>
    <p class="center">New user? <a href="/register">Register</a></p>
    </div>""", message=message)

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template_string(STYLE + """
    <div class="box"><h2>Welcome, {{username}}!</h2>
    <p class="center">You have successfully logged in.</p>
    <p class="center">This is a protected dashboard.</p>
    <p class="center"><a href="/logout">Logout</a></p></div>
    """, username=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
