import os
import socket
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename


def create_app():
    app = Flask(__name__)

    # 设置模板文件夹的路径为绝对路径
    template_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
    app.config['TEMPLATE_FOLDER'] = template_folder
    app.template_folder = template_folder

    UPLOAD_FOLDER = 'uploads'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # 存储用户信息的字典，实际项目应使用数据库
    users = {}

    # 存储上传的文件信息的字典
    files = {}

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
                                                                          'zip'}

    @app.route('/')
    def index():
        return render_template('index.html', files=files)

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
                    'path': file_path
                }
                files[filename] = file_info
                return redirect(url_for('index'))
        return render_template('upload.html')

    @app.route('/manage/<filename>')
    def manage(filename):
        # 在此处实现管理文件的功能，例如修改名称、删除等
        file_info = files.get(filename)
        return render_template('manage.html', file_info=file_info)

    @app.route('/download/<filename>')
    def download(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

    # ... 其他路由 ...

    return app


if __name__ == '__main__':
    app = create_app()

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # 获取 IPv4 或 IPv6 地址
    host = socket.getaddrinfo(socket.gethostname(), None)[0][4][0]
    if ':' in host:  # 如果包含冒号，则为IPv6地址
        print("网盘已启动，请访问以下链接:")
        print(f"  http://[{host}]:5000/  (IPv6)")
    else:
        print("网盘已启动，请访问以下链接:")
        print(f"  http://{host}:5000/  (IPv4)")

    print("\n当前版本号: 1.0")
    print("本程序由 'HAOHAO' 开发\n")
    print(f" 新版本更新:"
          f"https://gitee.com/is-haohao/HAO-Netdisk"
          f" 或 https://github.com/ISHAOHAO/HAO-Netdisk(国内需要挂加速器)")

    app.run(debug=True, host=host, port=5000)
