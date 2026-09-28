import os
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, send_from_directory, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "TheAuroraH")  # 为空则不自动建管理员
UPLOAD_DIR = "uploads"
DB_PATH = "data.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024 * 1024  # 10GB


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 兼容旧库：如果没有 user_id 字段就补上
        for table in ("notes", "files"):
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER")
            except sqlite3.OperationalError:
                pass

        # 自动创建管理员
        if ADMIN_PASSWORD:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
            ).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users(username, password_hash, is_admin) VALUES(?, ?, 1)",
                    (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD))
                )


init_db()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


BASE = """
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>本地存储</title>
<style>
body{font-family:system-ui,sans-serif;max-width:780px;margin:24px auto;padding:0 16px;line-height:1.6}
input,textarea,button{font:inherit;padding:6px 8px}
button{cursor:pointer}
.nav a{margin-right:12px}
.flash{color:#b00}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}
small{color:#666}
</style>
</head>
<body>
<div class="nav">
  {% if session.get('user_id') %}
    <a href="/">首页</a>
    {% if session.get('is_admin') %}<a href="/admin">管理</a>{% endif %}
    <a href="/logout">退出</a>
    <small>已登录：{{ session.get('username') }}{% if session.get('is_admin') %}（管理员）{% endif %}</small>
  {% else %}
    <a href="/login">登录</a>
    <a href="/register">注册</a>
  {% endif %}
</div>
<hr>
{% with messages = get_flashed_messages() %}
  {% for m in messages %}<p class="flash">{{ m }}</p>{% endfor %}
{% endwith %}
{{ body|safe }}
</body>
</html>
"""


def page(body):
    return render_template_string(BASE, body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            next_url = request.args.get("next") or url_for("index")
            if not next_url.startswith("/"):
                next_url = url_for("index")
            return redirect(next_url)
        flash("用户名或密码错误")
    return page("""
    <h2>登录</h2>
    <form method="post">
      <p><input name="username" placeholder="用户名" required></p>
      <p><input name="password" type="password" placeholder="密码" required></p>
      <button>登录</button>
    </form>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("用户名和密码不能为空")
        elif len(password) < 6:
            flash("密码至少 6 位")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users(username, password_hash) VALUES(?, ?)",
                        (username, generate_password_hash(password))
                    )
                flash("注册成功，请登录")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("用户名已存在")
    return page("""
    <h2>注册</h2>
    <form method="post">
      <p><input name="username" placeholder="用户名" required></p>
      <p><input name="password" type="password" placeholder="密码（至少 6 位）" required></p>
      <button>注册</button>
    </form>
    """)


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    uid = session["user_id"]
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO notes(user_id, content) VALUES(?, ?)", (uid, content)
                )
        return redirect(url_for("index"))

    with get_db() as conn:
        notes = conn.execute(
            "SELECT id, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC",
            (uid,)
        ).fetchall()
        files = conn.execute(
            "SELECT id, filename, original_name, created_at FROM files WHERE user_id = ? ORDER BY id DESC",
            (uid,)
        ).fetchall()

    body = render_template_string("""
    <h2>存文本</h2>
    <form method="post">
      <textarea name="content" rows="4" cols="50" placeholder="输入要保存的内容"></textarea><br>
      <button>保存文本</button>
    </form>
    <h3>已存文本</h3>
    <ul>
    {% for n in notes %}<li>[{{ n['created_at'] }}] {{ n['content'] }}</li>
    {% else %}<li>暂无</li>{% endfor %}
    </ul>

    <h2>传文件</h2>
    <form method="post" action="/upload" enctype="multipart/form-data">
      <input type="file" name="file">
      <button>上传</button>
    </form>
    <h3>已传文件</h3>
    <ul>
    {% for f in files %}
      <li>[{{ f['created_at'] }}] <a href="/files/{{ f['filename'] }}">{{ f['original_name'] }}</a></li>
    {% else %}<li>暂无</li>{% endfor %}
    </ul>
    """, notes=notes, files=files)
    return page(body)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if f and f.filename:
        original_name = f.filename
        ext = os.path.splitext(original_name)[1]
        filename = secrets.token_hex(16) + ext
        f.save(os.path.join(UPLOAD_DIR, filename))
        with get_db() as conn:
            conn.execute(
                "INSERT INTO files(user_id, filename, original_name) VALUES(?, ?, ?)",
                (session["user_id"], filename, original_name)
            )
    return redirect(url_for("index"))


@app.route("/files/<filename>")
@login_required
def download(filename):
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_id, original_name FROM files WHERE filename = ?", (filename,)
        ).fetchone()
    if not row:
        abort(404)
    if row["user_id"] != session["user_id"] and not session.get("is_admin"):
        abort(403)
    return send_from_directory(
        UPLOAD_DIR, filename, as_attachment=True, download_name=row["original_name"]
    )


@app.route("/admin")
@admin_required
def admin():
    with get_db() as conn:
        users = conn.execute("""
            SELECT u.id, u.username, u.is_admin, u.created_at,
                   (SELECT COUNT(*) FROM notes WHERE user_id = u.id) AS note_count,
                   (SELECT COUNT(*) FROM files WHERE user_id = u.id) AS file_count
            FROM users u ORDER BY u.id
        """).fetchall()

    body = render_template_string("""
    <h2>用户管理</h2>
    <table>
      <tr>
        <th>ID</th><th>用户名</th><th>管理员</th>
        <th>文本数</th><th>文件数</th><th>注册时间</th><th>操作</th>
      </tr>
      {% for u in users %}
      <tr>
        <td>{{ u['id'] }}</td>
        <td>{{ u['username'] }}</td>
        <td>{{ '是' if u['is_admin'] else '否' }}</td>
        <td>{{ u['note_count'] }}</td>
        <td>{{ u['file_count'] }}</td>
        <td>{{ u['created_at'] }}</td>
        <td>
          {% if u['id'] != session.get('user_id') %}
          <form method="post" action="/admin/toggle/{{ u['id'] }}" style="display:inline">
            <button>{{ '取消管理员' if u['is_admin'] else '设为管理员' }}</button>
          </form>
          <form method="post" action="/admin/delete/{{ u['id'] }}" style="display:inline"
                onsubmit="return confirm('确定删除用户 {{ u['username'] }} 及其所有数据？')">
            <button>删除</button>
          </form>
          {% else %}
          <small>当前账号</small>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
    """, users=users)
    return page(body)


@app.route("/admin/toggle/<int:user_id>", methods=["POST"])
@admin_required
def admin_toggle(user_id):
    if user_id == session["user_id"]:
        abort(400)
    with get_db() as conn:
        conn.execute("UPDATE users SET is_admin = 1 - is_admin WHERE id = ?", (user_id,))
    return redirect(url_for("admin"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete(user_id):
    if user_id == session["user_id"]:
        abort(400)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT filename FROM files WHERE user_id = ?", (user_id,)
        ).fetchall()
        for r in rows:
            path = os.path.join(UPLOAD_DIR, r["filename"])
            if os.path.exists(path):
                os.remove(path)
        conn.execute("DELETE FROM files WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM notes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    return page("<h2>403 无权限</h2><p><a href='/'>返回首页</a></p>"), 403


@app.errorhandler(413)
def too_large(e):
    return page("<h2>文件太大</h2><p>请上传小于 95MB 的文件。</p>"), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8347, debug=False)
