import json
import os
import urllib.request
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

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

# 存储上传的文件信息的字典
files = {}

# JSON 文件用于保存文件信息
FILES_JSON = os.path.join(current_script_path, 'files.json')


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
        with open(FILES_JSON, 'r') as json_file:
            return json.load(json_file)
    else:
        return {}


def save_files_to_json():
    with open(FILES_JSON, 'w') as json_file:
        json.dump(files, json_file)


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


@app.route('/upload_file', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # 处理文件上传
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
            files[filename] = file_info
            save_files_to_json()
            return redirect(url_for('index'))
    return render_template('upload.html')


@app.route('/manage/<filename>')
def manage(filename):
    # 在此处实现管理文件的功能，例如修改名称、删除等
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


if __name__ == '__main__':

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # 使用 IPv6 地址来启动应用
    host = '::'
    port = 5000

    print("\n当前版本: v0.1.0")
    print("本程序由 'HAOHAO' 开发\n")
    print(f" 新版本更新:"
          f"https://gitee.com/is-haohao/HAO-Netdisk"
          f" 或 https://github.com/ISHAOHAO/HAO-Netdisk(国内需要挂加速器)")

    print("网盘已启动，请访问此链接(IPv6):")
    print(f"  http://[{host}]:{port}/  ")

    # 获取公网 IPv6 地址
    public_ipv6 = get_public_ipv6()
    if public_ipv6:
        print(f"  http://[{public_ipv6}]:{port}/  (你的网盘地址)")

    app.run(debug=True, host=host, port=port)
