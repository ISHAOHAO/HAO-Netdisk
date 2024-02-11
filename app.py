import json
import os
import secrets
import socket
import urllib.request
import urllib.request
import uuid
import webbrowser
from datetime import datetime
from datetime import timedelta

from flask import Flask, request, redirect, url_for, send_from_directory, session
from flask import abort
from flask import jsonify
from flask import render_template
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 16 字节的十六进制字符串

app.config['MAIL_SERVER'] = 'smtp.163.com'  # 设置为您的 SMTP 服务器地址
app.config['MAIL_PORT'] = 25  # 设置为您的 SMTP 服务器的 SSL 端口
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'hao_netdisk@163.com'  # 设置为您的邮箱
app.config['MAIL_PASSWORD'] = 'HBBAYKISCQCIAAEX'  # 设置为您的邮箱密码
app.config['MAIL_DEFAULT_SENDER'] = 'hao_netdisk@163.com'  # 设置为您的邮箱

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

# 存储重置密码令牌的字典
reset_tokens = {}

# 有效的令牌过期时间（以秒为单位）
TOKEN_EXPIRATION_TIME = 1800  # 30分钟

# JSON 文件用于保存文件信息
FILES_JSON = os.path.join(current_script_path, 'files.json')
if not os.path.exists(FILES_JSON):
    with open(FILES_JSON, 'w') as json_file:
        json.dump({}, json_file)


def delete_file(filename):
    try:
        file_path = files[filename]['path']
        os.remove(file_path)
        del files[filename]
        save_files_to_json(files)
        return True
    except Exception as e:
        print(f"Error deleting file: {e}")
        return False


def update_file_description(filename, new_description):
    try:
        files[filename]['description'] = new_description
        save_files_to_json(files)
        return True
    except Exception as e:
        print(f"Error updating file description: {e}")
        return False


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


@app.route('/', methods=['GET'])
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 4  # 每页显示的文件数量
    search_query = request.args.get('search', '')

    # 加载文件信息
    global files
    files = load_files_from_json()

    # 进行搜索
    filtered_files = {filename: file_info for filename, file_info in files.items() if
                      search_query.lower() in file_info['description'].lower()}

    # 分页显示
    total_files = len(filtered_files)
    total_pages = (total_files + per_page - 1) // per_page  # 计算总页数
    paginated_files = dict(list(filtered_files.items())[per_page * (page - 1): per_page * page])

    return render_template('index.html', files=paginated_files, format_file_size=format_file_size,
                           search_query=search_query, page=page, total_pages=total_pages)


@app.route('/delete/<filename>')
def delete(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    if delete_file(filename):
        return redirect(url_for('index'))
    else:
        abort(500)


@app.route('/update/<filename>', methods=['POST'])
def update(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    new_description = request.form['new_description']
    if update_file_description(filename, new_description):
        return redirect(url_for('index'))
    else:
        abort(500)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')

        if username in users:
            # 生成唯一的重置令牌
            reset_token = str(uuid.uuid4())
            expiration_time = datetime.now() + timedelta(seconds=TOKEN_EXPIRATION_TIME)

            # 将令牌和相关信息存储在字典中
            reset_tokens[reset_token] = {'username': username, 'expiration_time': expiration_time}

            # 发送包含重置链接的电子邮件
            send_reset_email(username, users[username]['email'], reset_token)

            return render_template('password_reset_sent.html')

        return "用户名不存在，请重试。"

    return render_template('forgot_password.html')


@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):
    # 检查令牌是否存在且未过期
    if reset_token in reset_tokens and reset_tokens[reset_token]['expiration_time'] > datetime.now():
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            username = reset_tokens[reset_token]['username']

            # 更新用户密码
            users[username]['password'] = new_password

            # 重置密码后，删除令牌
            del reset_tokens[reset_token]

            return "密码重置成功，请使用新密码登录。"

        return render_template('reset_password.html', reset_token=reset_token)

    return "无效的重置链接或链接已过期。"


def send_email(username, email):
    subject = '来自HAO-Netdisk的邮件'

    with app.app_context():
        html_body = render_template('reset_password_email.html', username=username)

    msg = Message(subject=subject, recipients=[email], html=html_body)

    try:
        mail.send(msg)
        print(f"测试邮件发送至 {email}")
        return "测试邮件发送成功！"
    except Exception as e:
        print(f"发送邮件时出错: {e}")
        return "发送邮件时出错。请检查日志以获取更多信息。"


def send_reset_email(username, email, reset_token):
    subject = '重置密码 - HAO-Netdisk'

    with app.app_context():
        reset_link = url_for('reset_password', reset_token=reset_token, _external=True)
        html_body = render_template('reset_password_email.html', username=username, reset_link=reset_link)

    msg = Message(subject=subject, recipients=[email], html=html_body)

    try:
        mail.send(msg)
        print(f"密码重置邮件已发送至 {email}")
        return "密码重置邮件已发送，请查收。"
    except Exception as e:
        print(f"发送邮件时出错: {e}")
        return "发送邮件时出错。请检查日志以获取更多信息。"


@app.route('/send_test_email')
def send_test_email():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']['username']
    email = session['user']['email']

    result = send_email(username, email)
    return result


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error="Bad Request (400)", details=str(e)), 400


@app.errorhandler(401)
def unauthorized(e):
    return render_template('error.html', error="Unauthorized (401)", details=str(e)), 401


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error="Forbidden (403)", details=str(e)), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error="Not Found (404)", details=str(e)), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="Internal Server Error (500)", details=str(e)), 500


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

            # 解决文件名重复问题
            files = load_files_from_json()
            if filename in files:
                filename = f"{filename.split('.')[0]}_{secrets.token_hex(4)}.{filename.split('.')[-1]}"

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
            files[filename] = file_info
            save_files_to_json(files)
            return redirect(url_for('index'))
    return render_template('upload.html')


# 新增一个路由用于获取文件总数（用于分页）
@app.route('/file_count', methods=['GET'])
def file_count():
    return jsonify({'file_count': len(files)})


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

    print("\n当前版本号: v0.1.3")
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
