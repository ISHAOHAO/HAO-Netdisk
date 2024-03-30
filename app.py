import json
import logging
import os
import secrets
import socket
import urllib.request
import uuid
import webbrowser
from datetime import datetime
from datetime import timedelta
from shutil import copyfile

from flask import Flask, request, jsonify, send_from_directory
from flask import flash
from flask import redirect, url_for, render_template, abort
from flask import send_file
from flask import session
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_session import Session
from flask_sslify import SSLify
from tqdm import tqdm  # 引入 tqdm 库
from werkzeug.utils import secure_filename

# 在app.py开头添加全局变量声明
global files

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'
UPLOAD_AVATARS_DIR = 'templates/avatars'  # 用户头像上传目录
app.config['UPLOAD_AVATARS_FOLDER'] = UPLOAD_AVATARS_DIR
Session(app)

# 启用 HTTPS，确保传输安全
sslify = SSLify(app)

bcrypt = Bcrypt(app)
logging.basicConfig(filename='app.log', level=logging.INFO)

app.config['MAIL_SERVER'] = 'smtp.163.com'  # 设置为您的 SMTP 服务器地址
app.config['MAIL_PORT'] = 25  # 设置为您的 SMTP 服务器的 SSL 端口
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'hao_netdisk@163.com'  # 设置为您的邮箱
app.config['MAIL_PASSWORD'] = 'HBBAYKISCQCIAAEX'  # 设置为您的邮箱密码
app.config['MAIL_DEFAULT_SENDER'] = 'hao_netdisk@163.com'  # 设置为您的邮箱

mail = Mail(app)

# 指定上传文件的根目录
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOADS_DIR = os.path.join(ROOT_DIR, 'uploads')
TEMPLATE_FOLDER = os.path.join(ROOT_DIR, 'templates')
AVATARS_DIR = os.path.join(TEMPLATE_FOLDER, 'avatars')
FILES_JSON = os.path.join(ROOT_DIR, 'files.json')
USERS_JSON = os.path.join(ROOT_DIR, 'users.json')

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
UPLOAD_FOLDER = os.path.join(ROOT_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 存储用户信息的字典，实际项目应使用数据库
users = {}

# 存储已登录用户的信息
logged_in_users = {}

# 存储上传的文件信息的字典
files = {}

# 存储文件分享信息的字典
file_shares = {}

# 存储重置密码令牌的字典
reset_tokens = {}

# 有效的令牌过期时间（以秒为单位）
TOKEN_EXPIRATION_TIME = 1800  # 30分钟

# JSON 文件用于保存文件信息
FILES_JSON = os.path.join(current_script_path, 'files.json')
if not os.path.exists(FILES_JSON):
    with open(FILES_JSON, 'w') as json_file:
        json.dump({}, json_file)


def save_file_with_progress(file, file_path, progress_callback, update_interval=0.1):
    # 打开文件进行写入
    with open(file_path, 'wb') as f:
        # 初始化已上传的字节数
        uploaded_bytes = 0
        # 获取文件总字节数（尝试从请求头获取）
        total_bytes = int(request.headers.get('Content-Length', 0))
        # 使用 tqdm 迭代器包装文件内容
        with tqdm(total=total_bytes, unit='B', unit_scale=True, unit_divisor=1024, miniters=update_interval) as pbar:
            # 循环读取文件内容并写入
            while True:
                chunk = file.read(1024 * 1024)  # 读取 1MB 数据
                if not chunk:
                    break
                f.write(chunk)
                uploaded_bytes += len(chunk)  # 更新已上传字节数
                if pbar.n % update_interval == 0:
                    pbar.update(len(chunk))  # 更新 tqdm 进度条
                    progress_callback(int(uploaded_bytes / total_bytes * 100))  # 回调上传进度
            pbar.close()  # 关闭 tqdm 进度条


# 生成文件分享链接
def generate_share_link(filename, expiration_time=None, password=None):
    share_id = secrets.token_hex(16)
    file_shares[share_id] = {'filename': filename, 'expiration_time': expiration_time, 'password': password}
    return share_id


# 检查文件分享链接是否有效
def is_share_valid(share_id):
    if share_id in file_shares:
        share_info = file_shares[share_id]
        if not share_info['expiration_time'] or share_info['expiration_time'] > datetime.now():
            return True
        else:
            # 如果链接已过期，删除分享信息
            del file_shares[share_id]
    return False


def allowed_avatar_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


# 从 JSON 文件加载用户数据
def load_users_from_json():
    if os.path.exists(USERS_JSON):
        with open(USERS_JSON, 'r') as user_file:
            return json.load(user_file)
    else:
        return {}


# 将用户数据保存到 JSON 文件
def save_users_to_json(users):
    with open(USERS_JSON, 'w') as user_file:
        json.dump(users, user_file)


# 当应用程序启动时载入用户
users = load_users_from_json()


def hash_password(password):
    # 使用 bcrypt 对密码进行哈希处理
    return bcrypt.generate_password_hash(password).decode('utf-8')


def check_password(username, password):
    # 检查用户名和密码是否匹配
    if username in users and bcrypt.check_password_hash(users[username]['password'], password):
        return True
    return False


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


# 在需要修改文件信息时，直接在内存中进行修改
def update_file_description(filename, new_description):
    try:
        files[filename]['description'] = new_description
        save_files_to_json(files)
        return True
    except Exception as e:
        print(f"Error updating file description: {e}")
        return False


def get_file_info(filename):
    return files.get(filename)


def format_size(size_in_bytes):
    size_in_kb = size_in_bytes / 1024
    if size_in_kb < 1024:
        return f"{size_in_kb:.2f} KB"
    size_in_mb = size_in_kb / 1024
    if size_in_mb < 1024:
        return f"{size_in_mb:.2f} MB"
    size_in_gb = size_in_mb / 1024
    return f"{size_in_gb:.2f} GB"


# 从 JSON 文件加载文件信息
def load_files_from_json():
    if os.path.exists(FILES_JSON):
        with open(FILES_JSON, 'r') as file:
            return json.load(file)
    else:
        return {}


# 将文件信息保存到 JSON 文件中
def save_files_to_json(files):
    with open(FILES_JSON, 'w') as file:
        json.dump(files, file)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip',
                                                                      'rar', 'doc', 'docx', 'xls', 'xlsx', 'ppt',
                                                                      'pptx', 'mp3', 'mp4', 'avi', 'mkv', 'mov', 'wmv',
                                                                      'flv', 'webm', 'ogg', 'm4a', 'wav', 'aac'}


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
    global files  # 声明为全局变量
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 4, type=int)
    search_query = request.args.get('search', '')

    # 加载文件信息
    files = load_files_from_json()

    # 进行搜索
    filtered_files = {filename: file_info for filename, file_info in files.items() if
                      search_query.lower() in file_info['description'].lower()}

    # 按描述内容相关性排序结果
    sorted_files = dict(sorted(filtered_files.items(), key=lambda item: item[1]['description'].lower()))

    # 分页显示
    total_files = len(sorted_files)
    total_pages = (total_files + per_page - 1) // per_page
    paginated_files = dict(list(sorted_files.items())[per_page * (page - 1): per_page * page])

    return render_template('index.html', files=paginated_files, format_file_size=format_file_size,
                           search_query=search_query, page=page, total_pages=total_pages, per_page=per_page)


@app.route('/share/<filename>', methods=['POST'])
def share_file(filename):
    expiration_days = int(request.form['expiration_days'])
    expiration_time = datetime.now() + timedelta(days=expiration_days)
    password = request.form['password'] if 'password' in request.form else None
    share_id = generate_share_link(filename, expiration_time, password)
    return f"分享链接: {request.host_url}access/{share_id}"


# 用于访问分享的文件
@app.route('/access/<share_id>', methods=['GET', 'POST'])
def access_shared_file(share_id):
    if is_share_valid(share_id):
        # 如果设置了密码，则要求用户输入密码
        if file_shares[share_id]['password']:
            if request.method == 'POST':
                password = request.form['password']
                if password == file_shares[share_id]['password']:
                    return redirect(url_for('download', filename=file_shares[share_id]['filename']))
                else:
                    return "密码错误，请重试。"
            return render_template('enter_password.html', share_id=share_id)
        else:
            return redirect(url_for('download', filename=file_shares[share_id]['filename']))
    else:
        return "分享链接无效或已过期。"


# 用于输入访问密码后访问分享的文件
@app.route('/access/<share_id>/password', methods=['POST'])
def access_shared_file_with_password(share_id):
    password = request.form['password']
    if is_share_valid(share_id) and file_shares[share_id]['password'] == password:
        # 返回文件下载页面或直接下载文件
        return redirect(url_for('download', filename=file_shares[share_id]['filename']))
    else:
        return "访问密码错误。"


# 更新文件分享页面，以允许用户设置分享选项
@app.route('/share_file/<filename>', methods=['GET', 'POST'])
def share_file_page(filename):
    if request.method == 'POST':
        expiration_days = int(request.form['expiration_days'])
        expiration_time = datetime.now() + timedelta(days=expiration_days)
        password = request.form['password'] if 'password' in request.form else None
        share_id = generate_share_link(filename, expiration_time, password)
        return f"分享链接: {request.host_url}access/{share_id}"
    return render_template('share_file.html', filename=filename)


@app.route('/preview/<filename>')
def preview_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 检查文件类型，只预览特定类型的文件
    if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.pdf', '.txt')):
        return send_file(file_path, as_attachment=False)

    # 如果文件类型不支持预览，可以返回错误提示或重定向到其他页面
    return "不支持预览的文件类型"


@app.route('/delete/<filename>')
def delete(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    if delete_file(filename):
        logging.info(f"用户 {session['user']['username']} 删除了文件: {filename}")
        return redirect(url_for('index'))
    else:
        logging.error(f"删除文件时出错: {filename}")
        abort(500)


# 获取文件列表的API接口
@app.route('/api/files', methods=['GET'])
def get_file_list():
    files = load_files_from_json()
    return jsonify({'files': files})


# 下载文件的API接口
@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/update/<filename>', methods=['POST'])
def update(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    new_description = request.form['new_description']
    if update_file_description(filename, new_description):
        logging.info(f"用户 {session['user']['username']} 更新了文件描述: {filename}")
        return redirect(url_for('manage', filename=filename))
    else:
        logging.error(f"更新文件描述时出错: {filename}")
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
            logging.info(f"用户 {username} 请求重置密码，并收到了重置邮件")

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

            # 更新用户密码，使用哈希处理密码
            users[username]['password'] = hash_password(new_password)

            # 重置密码后，删除令牌
            del reset_tokens[reset_token]

            logging.info(f"用户 {username} 重置了密码")
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
        email = request.form['email']

        if username in users:
            return "用户名已存在，请选择其他用户名。"

        # 保存用户信息并散列密码
        users[username] = {'password': hash_password(password), 'email': email}

        # 将用户保存到 JSON 文件
        save_users_to_json(users)

        # 复制默认头像文件到新用户头像文件
        default_avatar_path = os.path.join(AVATARS_DIR, 'default_avatar.png')
        new_user_avatar_path = os.path.join(AVATARS_DIR, f'{username}.png')

        # 确保目标目录存在
        os.makedirs(AVATARS_DIR, exist_ok=True)

        copyfile(default_avatar_path, new_user_avatar_path)

        return render_template('register_success.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_password(username, password):
            # 在会话中存储用户信息
            session['user'] = {'username': username, 'email': users[username]['email']}
            logged_in_users[username] = session['user']
            return redirect(url_for('index'))

        return "用户名或密码无效。请重试。"

    return render_template('login.html')


@app.route('/logout')
def logout():
    # 从 session 中移除用户信息，标记为已退出
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_info = users.get(session['user']['username'], {})
    avatar_filename = user_info.get('avatars')
    avatar_path = url_for('avatars', filename=avatar_filename) if avatar_filename else url_for('static',
                                                                                               filename='avatars/default_avatar.png')

    return render_template('profile.html', avatar_path=avatar_path)


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'user' not in session:
        return redirect(url_for('login'))

    avatar = request.files.get('avatar')
    if avatar and allowed_avatar_file(avatar.filename):
        username = session['user']['username']
        avatar_filename = f"{username}.png"  # 使用用户名作为头像文件名，确保唯一性

        # 更新用户头像信息
        users[username]['avatar'] = avatar_filename
        save_users_to_json(users)

        # 确保目标目录存在，如果不存在则创建
        avatars_dir = os.path.join(app.config['TEMPLATE_FOLDER'], 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)

        avatar_path = os.path.join(avatars_dir, avatar_filename)

        # 删除之前的头像
        old_avatar = users[username].get('avatar')
        if old_avatar:
            old_avatar_path = os.path.join(avatars_dir, old_avatar)
            if os.path.exists(old_avatar_path):
                os.remove(old_avatar_path)

        # 保存新头像
        avatar.save(avatar_path)

        # 更新用户头像信息
        users[username]['avatar'] = avatar_filename
        save_users_to_json(users)

        # 添加提示信息
        flash('头像更新成功！', 'success')

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

            # 使用新的函数来保存文件，并传递进度回调函数
            save_file_with_progress(file, file_path, lambda progress: print(f'Upload progress: {progress}%'))

            file_info = {
                'description': request.form['description'],
                'username': session['user']['username'],
                'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'size': os.path.getsize(file_path),  # 现在可以安全获取文件大小
                'formatted_size': format_size(os.path.getsize(file_path)),
                'path': file_path
            }
            files[filename] = file_info
            save_files_to_json(files)
            logging.info(f"用户 {session['user']['username']} 上传了文件: {filename}")

            # 返回 JSON 格式的成功响应，包含重定向地址
            return jsonify({'redirect': url_for('index')})
    return render_template('upload.html')


# 新增一个路由用于获取文件总数（用于分页）
@app.route('/file_count', methods=['GET'])
def file_count():
    return jsonify({'file_count': len(files)})


@app.route('/avatars/<filename>')
def avatars(filename):
    return send_from_directory(AVATARS_DIR, filename)


@app.route('/manage/<filename>')
def manage(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_info = files.get(filename)
    return render_template('manage.html', files=files, file_info=file_info)


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

    print("\n当前版本号: v0.1.9")
    print("本程序由 'HAOHAO' 开发\n")
    print(f"新版本更新:")
    print(f"https://gitee.com/is-haohao/HAO-Netdisk/releases")
    print(f"https://github.com/ISHAOHAO/HAO-Netdisk/releases(国内需要挂加速器) ")
    print("网盘启动成功，请访问以下链接（IPv6）:")
    print(f"本地IPv6地址: http://[{local_ipv6}]:{port}/")

    # 获取公网 IPv6 地址
    if public_ipv6:
        print(f"外网IPv6地址: http://[{public_ipv6}]:{port}/")
        print(f"请注意！您只能使用本地链接访问，其他用户只能使用外网链接访问")

    # 在程序启动后自动打开浏览器
    open_browser(url)

    app.run(debug=True, host=host, port=port)

    # 使用IPV4
    # app.run(debug=True, host="0.0.0.0", port=port)
