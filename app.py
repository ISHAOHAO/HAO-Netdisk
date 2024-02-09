import json
import os
import secrets
import socket
import urllib.request
import urllib.request
import uuid
import webbrowser
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 16 字节的十六进制字符串

app.config['MAIL_SERVER'] = 'smtp.163.com'  # 设置为您的 SMTP 服务器地址
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hao_netdisk@163.com'  # 设置为您的邮箱
app.config['MAIL_PASSWORD'] = 'HBBAYKISCQCIAAEX'  # 设置为您的邮箱密码

mail = Mail(app)

# 指定上传文件的根目录
UPLOADS_DIR = 'uploads'
TEMPLATE_FOLDER = 'templates'
FILES_JSON = 'files.json'

app.config['UPLOAD_FOLDER'] = UPLOADS_DIR
app.config['TEMPLATE_FOLDER'] = TEMPLATE_FOLDER

# 检查uploads文件夹是否存在，如果不存在则创建
if not os.path.exists(UPLOADS_DIR):
    os.makedirs(UPLOADS_DIR)

# 获取当前脚本的绝对路径
current_script_path = os.path.abspath(os.path.dirname(__file__))

# 设置模板文件夹的路径为绝对路径
template_folder = os.path.join(current_script_path, 'templates')
app.config['TEMPLATE_FOLDER'] = template_folder
app.template_folder = template_folder

# 设置上传文件夹的路径为绝对路径
UPLOAD_FOLDER = os.path.join(current_script_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 存储用户信息的字典，实际项目应使用数据库
users = {}

# 存储已登录用户的信息
logged_in_users = {}

# 存储上传的文件信息的字典
files = {}

# JSON 文件用于保存文件信息
FILES_JSON = os.path.join(current_script_path, 'files.json')
if not os.path.exists(FILES_JSON):
    with open(FILES_JSON, 'w') as json_file:
        json.dump({}, json_file)


def format_size(size_in_bytes):
    size_in_kb = size_in_bytes / 1024
    if size_in_kb < 1024:
        return f"{size_in_kb:.2f} KB"
    size_in_mb = size_in_kb / 1024
    if size_in_mb < 1024:
        return f"{size_in_mb:.2f} MB"
    size_in_gb = size_in_mb / 1024
    return f"{size_in_gb:.2f} GB"


def load_files_from_json():
    if os.path.exists(FILES_JSON):
        with open(FILES_JSON, 'r') as file:
            return json.load(file)
    else:
        return {}


def save_files_to_json(files):
    with open(FILES_JSON, 'w') as file:
        json.dump(files, file)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}


def format_file_size(size_in_bytes):
    # 将字节数转换为 GB 或 MB 单位
    gb_size = size_in_bytes / (1024 ** 3)
    mb_size = size_in_bytes / (1024 ** 2)

    if gb_size >= 1:
        return f"{gb_size:.2f} GB"
    elif mb_size >= 1:
        return f"{mb_size:.2f} MB"
    else:
        return f"{size_in_bytes} Bytes"


try:
    with open('files.json', 'r') as file:
        file_content = file.read()  # 读取文件内容
        print("File Content:", file_content)  # 输出文件内容（调试用）

        # 尝试加载 JSON 数据，如果文件为空则赋予一个空字典
        files = json.loads(file_content) if file_content.strip() else {}
        for filename, file_info in files.items():
            file_info['formatted_size'] = format_size(file_info['size'])
except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
    print(f"Error Loading JSON: {e}")  # 输出解码错误信息
    # 如果文件不存在或 JSON 解码错误，赋予一个空字典
    files = {}


@app.route('/')
def index():
    # 加载文件信息
    global files
    files = load_files_from_json()
    return render_template('index.html', files=files, format_file_size=format_file_size)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')

        if username in users:
            # 生成唯一的重置令牌
            reset_token = str(uuid.uuid4())

            # 将令牌存储在数据库或其他持久性存储中，以便在重置密码时进行验证

            # 构建重置链接
            reset_link = f"http://{request.host}/reset_password/{reset_token}"

            # 发送包含重置链接的电子邮件
            send_reset_email(username, users[username]['email'], reset_link)

            return f"重置链接已发送到注册邮箱，请查收。"

        return "用户名不存在，请重试。"

    return render_template('forgot_password.html')


def send_reset_email(username, email, reset_link):
    subject = 'Reset Your Password - HAO-Netdisk'
    body = f"Hello {username},\n\nTo reset your password, please click the following link:\n\n{reset_link}\n\nIf you didn't request a password reset, please ignore this email."

    msg = Message(subject=subject, recipients=[email], body=body)

    try:
        mail.send(msg)
        print(f"Password reset email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # 将字段名称更改为 'email'

        if username in users:
            return "用户名已存在，请选择其他用户名。"

        # 保存用户信息（在真实应用中，可能需要对密码进行哈希处理）
        users[username] = {'password': password, 'email': email}

        return render_template('register_success.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:
            # 将用户信息存储在 session 中，标记为已登录
            session['user'] = {'username': username, 'email': users[username]['email']}
            logged_in_users[username] = session['user']
            return redirect(url_for('index'))

        return "无效的用户名或密码，请重试。"

    return render_template('login.html')


@app.route('/logout')
def logout():
    # 从 session 中移除用户信息，标记为已退出
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/upload_file', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            file_info = {
                'description': request.form['description'],
                'username': request.form['username'],
                'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'size': os.path.getsize(file_path),
                'formatted_size': format_size(os.path.getsize(file_path)),
                'path': file_path
            }
            files = load_files_from_json()
            files[filename] = file_info
            save_files_to_json(files)
            return redirect(url_for('index'))
    return render_template('upload.html')


@app.route('/manage/<filename>')
def manage(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_info = files.get(filename)
    return render_template('manage.html', file_info=file_info)


@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


def get_public_ipv6():
    # 使用请求获取公网 IPv6 地址
    try:
        response = urllib.request.urlopen('https://api64.ipify.org?format=json')
        data = json.loads(response.read().decode('utf-8'))
        return data['ip']
    except Exception as e:
        print(f"无法获取公网 IPv6 地址: {e}")
        return None


def open_browser(url):
    # 使用 webbrowser 模块在默认浏览器中打开链接
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"无法在浏览器中打开链接: {e}")


def get_local_ipv6():
    try:
        # 使用 socket 模块获取本地主机名
        host_name = socket.gethostname()

        # 使用 getaddrinfo 获取主机名对应的 IPv6 地址
        ipv6_address = socket.getaddrinfo(host_name, None, socket.AF_INET6)[0][4][0]

        return ipv6_address
    except Exception as e:
        print(f"获取本地IPv6地址失败: {e}")
        return None


if __name__ == '__main__':

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # 使用 IPv6 地址来启动应用
    host = '::'
    port = 5000
    local_ipv6 = get_local_ipv6()
    public_ipv6 = get_public_ipv6()

    url = f"http://[{local_ipv6}]:{port}/"

    print("\n当前版本号: v0.1.1")
    print("本程序由 'HAOHAO' 开发\n")
    print(f" 新版本更新:")
    print(f"https://gitee.com/is-haohao/HAO-Netdisk")
    print(f"https://github.com/ISHAOHAO/HAO-Netdisk(国内需要挂加速器) ")
    print("网盘启动成功，请访问以下链接（IPv6）:")
    print(f"本地IPv6地址: http://[{local_ipv6}]:{port}/")

    # 获取公网 IPv6 地址
    if public_ipv6:
        print(f"外网IPv6地址: http://[{public_ipv6}]:{port}/")
        print(f"请注意！您只能使用本地链接访问，其他用户只能使用外网链接访问")

    # 在程序启动后自动打开浏览器
    open_browser(url)

    app.run(debug=True, host=host, port=port)
