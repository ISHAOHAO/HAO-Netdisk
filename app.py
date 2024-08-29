import logging
import os
import secrets
import sys
import threading
import tkinter as tk
import uuid
import webbrowser
import tempfile
from datetime import datetime, timedelta, timezone
from tkinter import Tk, Toplevel, Listbox, END, ACTIVE, StringVar, Label, Entry, Button, OptionMenu
from tkinter import messagebox

import requests
from flask import Flask, send_file, abort, request, redirect, url_for, render_template, session, flash, \
    send_from_directory, jsonify
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
tempfile.tempdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['SECRET_KEY'] = 'secrets.token_hex(16)'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USERNAME'] = 'hao_netdisk@163.com'
app.config['MAIL_PASSWORD'] = 'HBBAYKISCQCIAAEX'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'hao_netdisk@163.com'
mail = Mail(app)
db = SQLAlchemy(app)


# 版本信息
current_version = "v1.4.5"  # 当前版本


# 获取所有地址，筛选出公网地址
def get_public_ip():
    ipv4_address = None
    ipv6_address = None
    try:
        ipv6_response = requests.get('https://api64.ipify.org?format=json')
        ipv6_address = ipv6_response.json()['ip']
    except Exception:
        pass

    try:
        ipv4_response = requests.get('https://api.ipify.org?format=json')
        ipv4_address = ipv4_response.json()['ip']
    except Exception:
        pass

    return ipv4_address, ipv6_address


# 设置日志记录
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


def log_event(event):
    logging.info(event)


# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100))  # 添加重置密码的 token
    token_expiration = db.Column(db.DateTime)  # 添加 token 过期时间
    files = db.relationship('File', backref='uploader', lazy=True)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    file_size = db.Column(db.Integer, nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    share_link = db.Column(db.String(100), unique=True)
    share_password = db.Column(db.String(100))
    share_expiration = db.Column(db.DateTime)
    is_public = db.Column(db.Boolean, default=True)  # 是否公开显示给所有人
    directory_id = db.Column(db.Integer, db.ForeignKey('directory.id'))  # 添加目录字段
    download_link = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))  # 随机生成下载链接


class Directory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    files = db.relationship('File', backref='directory', lazy=True)
    is_public = db.Column(db.Boolean, default=True)  # 目录公开状态字段
    uploader = db.relationship('User', backref='directories', lazy=True)  # 新增关联用户的关系


if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/')
def index():
    ip_address = request.remote_addr
    username = session.get('username', '游客')
    return render_template('index.html', ip_address=ip_address, username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('登录成功！', 'success')
            log_event(f'用户 {user.username} 登录成功。')
            return redirect(url_for('index'))
        else:
            flash('无效的用户名或电子邮箱或密码。', 'danger')
            log_event(f'无效的登录尝试，用户名或电子邮箱: {identifier}。')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        if User.query.filter_by(email=email).first():
            flash(f'电子邮箱{email}已被注册。', 'danger')
            log_event(f'电子邮箱 {email} 已被注册。')
        elif User.query.filter_by(username=username).first():
            flash(f'用户名 {username} 已被注册。', 'danger')
            log_event(f'用户名{username}已被注册。')
        else:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'注册成功！您的用户名为 {username} ,请登录。', 'success')
            log_event(f'新用户注册: {username}。')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            ip_address = request.remote_addr
            token = str(uuid.uuid4())
            user.reset_token = token
            user.token_expiration = datetime.utcnow() + timedelta(hours=1)  # Token 有效期 1 小时
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            html_body = render_template('reset_password_email.html', username=user.username, reset_link=reset_url)
            msg = Message('重置密码请求', recipients=[email], html=html_body)
            mail.send(msg)
            flash(f'重置密码的邮件已发送到您的邮箱 {email}。', 'info')
            log_event(f'{ip_address}发送重置密码邮件到 {email} ')
        else:
            flash(f'该电子邮件 {email} 未注册。', 'danger')
            log_event(f'电子邮件 {email} 未注册 ')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter(User.reset_token == token, User.token_expiration >= datetime.utcnow()).first()
    if not user:
        username = request.form.get('username')
        ip_address = request.remote_addr
        flash('重置密码链接无效或已过期。', 'danger')
        log_event(f'{ip_address} 使用 {username} 的重置密码链接无效或已过期')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('password')
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user.password = hashed_password
        user.reset_token = None  # 清除 token
        user.token_expiration = None
        db.session.commit()
        flash('密码重置成功，请重新登录。', 'success')
        log_event(f'{username} 密码重置成功')
        return redirect(url_for('login'))

    return render_template('reset_password.html', username=user.username)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        files = request.files.getlist('file')
        description = request.form.get('description')

        if files:
            try:
                if len(files) > 1:
                    directory = Directory(description=description, user_id=session['user_id'])
                    db.session.add(directory)
                    db.session.commit()
                    directory_id = directory.id

                    for file in files:
                        filename = file.filename
                        base_filename, file_extension = os.path.splitext(filename)
                        counter = 1

                        while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                            filename = f"{base_filename}({counter}){file_extension}"
                            counter += 1

                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                        # 使用流式上传
                        with open(filepath, 'wb') as f:
                            for chunk in file.stream:
                                f.write(chunk)

                        file_size = os.path.getsize(filepath)
                        new_file = File(
                            filename=filename,
                            description=base_filename,
                            file_size=file_size,
                            user_id=session['user_id'],
                            directory_id=directory_id
                        )
                        db.session.add(new_file)

                else:
                    directory_id = None
                    file = files[0]
                    filename = file.filename
                    base_filename, file_extension = os.path.splitext(filename)
                    counter = 1

                    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                        filename = f"{base_filename}({counter}){file_extension}"
                        counter += 1

                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                    # 使用流式上传
                    with open(filepath, 'wb') as f:
                        for chunk in file.stream:
                            f.write(chunk)

                    file_size = os.path.getsize(filepath)
                    new_file = File(
                        filename=filename,
                        description=description,
                        file_size=file_size,
                        user_id=session['user_id'],
                        directory_id=directory_id
                    )
                    db.session.add(new_file)

                db.session.commit()

                flash(f'用户 {session["username"]} 上传了文件。', 'success')
                log_event(f'用户 {session["username"]} 上传了文件。')
                return jsonify({'message': '文件上传成功！'}), 200

            except IOError as e:
                db.session.rollback()
                flash('文件上传失败，请重试。', 'danger')
                log_event(f'文件上传失败：{str(e)}')
                return jsonify({'message': '文件上传失败，请重试。'}), 500

        else:
            flash('未选择文件。', 'danger')
            return jsonify({'message': '未选择文件。'}), 400

    return render_template('upload.html')


@app.route('/directory/<int:directory_id>', methods=['GET'])
def directory_detail(directory_id):
    directory = Directory.query.get_or_404(directory_id)
    page = request.args.get('page', 1, type=int)
    files_query = File.query.filter_by(directory_id=directory_id).paginate(page=page, per_page=10)
    return render_template('directory_detail.html', directory=directory, files=files_query)


@app.route('/files', methods=['GET'])
def files():
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)

    # 查询所有目录，如果是其他用户则只显示公开目录
    directories_query = Directory.query.filter(
        Directory.description.like(f'%{search_query}%')
    ).filter(
        (Directory.user_id == session.get('user_id')) | (Directory.files.any(File.is_public == True))
    ).paginate(page=page, per_page=10)

    # 显示不属于任何目录的公开文件或当前用户的文件
    files_query = File.query.filter(File.directory_id.is_(None)).filter(File.filename.like(f'%{search_query}%')).filter(
        (File.is_public == True) | (File.user_id == session.get('user_id'))
    ).paginate(page=page, per_page=10)

    return render_template('files.html', directories=directories_query, files=files_query, search_query=search_query)


@app.route('/download/<download_link>')
def download(download_link):
    file = File.query.filter_by(download_link=download_link).first_or_404()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        abort(404)


@app.route('/files/<int:file_id>', methods=['GET', 'POST'])
def file_detail(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        if 'download' in request.form:
            return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)
        elif 'create_share_link' in request.form:
            share_link = secrets.token_urlsafe(16)
            file.share_link = share_link
            file.share_password = request.form.get('password')
            file.share_expiration = datetime.utcnow() + timedelta(days=1)  # 过期时间设置为1天
            db.session.commit()
            flash('分享链接已创建。', 'success')
            log_event(f'分享链接 {file.filename} 已创建。')
            return redirect(url_for('file_detail', file_id=file.id))
    return render_template('file_detail.html', file=file, share_link=file.share_link)


@app.route('/share/<share_link>', methods=['GET', 'POST'])
def share_file(share_link):
    file = File.query.filter_by(share_link=share_link).first_or_404()
    if request.method == 'POST':
        password = request.form.get('password')
        if file.share_password and password != file.share_password:
            flash('密码错误。', 'danger')
        else:
            return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)
    return render_template('share_file.html', file=file)


@app.route('/file_manager', methods=['GET', 'POST'])
def file_manager():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        item_id = request.form.get('item_id')
        action = request.form.get('action')
        item_type = request.form.get('item_type')

        if item_type == 'file':
            item = db.session.get(File, item_id)
        else:
            item = db.session.get(Directory, item_id)

        if action == 'delete' and item:
            if item_type == 'file':
                # 删除文件
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], item.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(item)
            elif item_type == 'directory':
                # 删除目录中的所有文件
                files_in_directory = File.query.filter_by(directory_id=item.id).all()
                for file in files_in_directory:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    db.session.delete(file)

                # 删除目录本身
                db.session.delete(item)

            db.session.commit()
            flash(f'{item_type.capitalize()} {item.description} 删除成功！', 'success')
            log_event(f'{item_type.capitalize()} {item.description} 删除成功！')

        elif 'update_description' in request.form and item:
            new_description = request.form.get('description')
            item.description = new_description
            db.session.commit()
            flash(f'{item_type.capitalize()} 描述更新成功。', 'success')
            log_event(f'{item_type.capitalize()} 描述更新为 {new_description} ')

        elif action == 'update_visibility' and item_type == 'file' and item:
            item.is_public = not item.is_public
            db.session.commit()
            flash(f'文件 {item.filename} 显示状态更改为 {"公开" if item.is_public else "不公开"}', 'success')
            log_event(f'文件 {item.filename} 显示状态更改为 {"公开" if item.is_public else "不公开"} ')

        elif action == 'update_directory_visibility' and item_type == 'directory' and item:
            item.is_public = not item.is_public
            db.session.commit()
            flash(f'目录 {item.description} 显示状态更改为 {"公开" if item.is_public else "不公开"}', 'success')
            log_event(f'目录 {item.description} 显示状态更改为 {"公开" if item.is_public else "不公开"} ')

        elif action == 'create_share_link' and item_type == 'file' and item:
            share_link = secrets.token_urlsafe(16)
            item.share_link = share_link
            item.share_password = request.form.get('password')
            item.share_expiration = datetime.now(timezone.utc) + timedelta(days=1)  # 过期时间设置为1天
            db.session.commit()
            ip_address = request.remote_addr
            flash(
                f'文件 {item.filename} 分享链接已创建 http://[{ip_address}]/share/{item.share_link} 密码：{item.share_password} ',
                'success')
            log_event(f'文件 {item.filename} 分享链接已创建 {item.share_link} 密码：{item.share_password} ')

        elif action == 'delete_share_link' and item_type == 'file' and item:
            item.share_link = None
            item.share_password = None
            item.share_expiration = None
            db.session.commit()
            flash(f'文件 {item.filename} 分享链接已删除。', 'success')
            log_event(f'文件 {item.filename} 分享链接已删除 ')

    user_files = File.query.filter_by(user_id=session['user_id'], directory_id=None).all()
    user_directories = Directory.query.filter_by(user_id=session['user_id']).all()
    return render_template('file_manager.html', files=user_files, directories=user_directories)


@app.route('/directory_manager/<int:directory_id>', methods=['GET', 'POST'])
def directory_manager(directory_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    directory = Directory.query.get_or_404(directory_id)

    if request.method == 'POST':
        action = request.form.get('action')
        file_id = request.form.get('file_id')

        if action == 'delete' and file_id:
            file = db.session.get(File, file_id)
            if file:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
                db.session.delete(file)
                db.session.commit()
                flash(f'文件 {file.filename} 删除成功！', 'success')
                log_event(f'文件 {file.filename} 删除成功！')
        elif action == 'update_visibility' and file_id:
            file = db.session.get(File, file_id)
            if file:
                file.is_public = not file.is_public
                db.session.commit()
                flash(f'文件 {file.filename} 显示状态更改为 {"公开" if file.is_public else "不公开"}', 'success')
                log_event(f'文件 {file.filename} 显示状态更改为 {"公开" if file.is_public else "不公开"} ')
        elif action == 'create_share_link' and file_id:
            file = db.session.get(File, file_id)
            if file:
                share_link = secrets.token_urlsafe(16)
                file.share_link = share_link
                file.share_password = request.form.get('password')
                file.share_expiration = datetime.now(timezone.utc) + timedelta(days=1)  # 过期时间设置为1天
                db.session.commit()
                ip_address = request.remote_addr
                flash(
                    f'文件 {file.filename} 分享链接已创建 http://[{ip_address}]/share/{file.share_link} 密码：{file.share_password} ',
                    'success')
                log_event(f'文件 {file.filename} 分享链接已创建 {file.share_link} 密码：{file.share_password} ')
        elif action == 'delete_share_link' and file_id:
            file = db.session.get(File, file_id)
            if file:
                file.share_link = None
                file.share_password = None
                file.share_expiration = None
                db.session.commit()
                flash(f'文件 {file.filename} 分享链接已删除。', 'success')
                log_event(f'文件 {file.filename} 分享链接已删除 ')
        elif action == 'update_description' and file_id:
            file = db.session.get(File, file_id)
            if file:
                new_description = request.form.get('description')
                file.description = new_description
                db.session.commit()
                flash(f'文件 {file.filename} 的描述已更新。', 'success')
                log_event(f'文件 {file.filename} 的描述已更新为 {new_description} ')
        elif action == 'update_directory_description':
            new_directory_description = request.form.get('directory_description')
            directory.description = new_directory_description
            db.session.commit()
            flash(f'目录描述已更新为 {new_directory_description}。', 'success')
            log_event(f'目录描述已更新为 {new_directory_description} ')

    files = File.query.filter_by(directory_id=directory_id).all()
    return render_template('directory_manager.html', directory=directory, files=files)


@app.route('/upload_to_directory/<int:directory_id>', methods=['GET', 'POST'])
def upload_file_to_directory(directory_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    directory = Directory.query.get_or_404(directory_id)

    if request.method == 'POST':
        files = request.files.getlist('file')

        if files:
            try:
                for file in files:
                    filename = file.filename
                    base_filename, file_extension = os.path.splitext(filename)
                    counter = 1

                    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                        filename = f"{base_filename}({counter}){file_extension}"
                        counter += 1

                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                    # 使用流式上传
                    with open(file_path, 'wb') as f:
                        for chunk in file.stream:
                            f.write(chunk)

                    new_file = File(
                        filename=filename,
                        description=base_filename,
                        file_size=os.path.getsize(file_path),
                        user_id=session['user_id'],
                        directory_id=directory_id
                    )
                    db.session.add(new_file)

                db.session.commit()
                flash('文件上传成功！', 'success')
                log_event('文件上传成功！')
                return jsonify({'message': '文件上传成功！'}), 200

            except IOError as e:
                db.session.rollback()
                flash('文件上传失败，请重试。', 'danger')
                log_event(f'文件上传失败：{str(e)}')
                return jsonify({'message': '文件上传失败，请重试。'}), 500

        else:
            flash('未选择文件。', 'danger')
            return jsonify({'message': '未选择文件。'}), 400

    return render_template('upload_to_directory.html', directory=directory)


@app.route('/logout')
def logout():
    ip_address = request.remote_addr
    log_event(f'访问IP {ip_address} 已注销登录 ')
    session.pop('user_id', None)
    session.pop('username', None)
    flash('已注销登录。', 'info')
    return redirect(url_for('index'))


@app.route('/file_list_api', methods=['GET'])
def file_list_api():
    files = File.query.all()
    files_data = [{'filename': file.filename, 'uploader': file.uploader.username} for file in files]
    return jsonify(files_data)


@app.route('/directory_list_api', methods=['GET'])
def directory_list_api():
    directories = Directory.query.all()
    directory_data = [{
        'id': directory.id,
        'description': directory.description,
        'files': [{'filename': file.filename} for file in directory.files]
    } for directory in directories]
    return jsonify(directory_data)


@app.route('/delete_directory', methods=['POST'])
def delete_directory():
    data = request.json
    directory_id = data.get('directory_id')
    if directory_id:
        directory = Directory.query.get(directory_id)
        if directory:
            # 删除目录中的所有文件
            for file in directory.files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        log_event(f'文件 {file.filename} 成功删除。')
                    except Exception as e:
                        log_event(f'删除文件 {file.filename} 失败: {e}')
                else:
                    log_event(f'文件 {file.filename} 不存在，无法删除。')
                db.session.delete(file)

            # 删除目录本身
            db.session.delete(directory)
            db.session.commit()
            return jsonify({'status': 'success', 'message': f'目录 {directory.description} 已成功删除!'}), 200
        else:
            return jsonify({'status': 'error', 'message': f'目录未找到!'}), 404
    return jsonify({'status': 'error', 'message': '无效请求!'}), 400


@app.route('/delete_file', methods=['POST'])
def delete_file():
    data = request.json
    filename = data.get('filename')
    if filename:
        file = File.query.filter_by(filename=filename).first()
        if file:
            db.session.delete(file)
            db.session.commit()
            return jsonify({'status': 'success', 'message': f'文件 {filename} 已成功删除!'}), 200
        else:
            return jsonify({'status': 'error', 'message': f'文件 {filename} 未找到!'}), 404
    return jsonify({'status': 'error', 'message': '无效请求!'}), 400


def start_flask_app(host, port, stop_event):
    def run():
        try:
            app.run(host=host, port=port, use_reloader=False)
        except Exception as e:
            print(f"Flask 服务运行出错: {e}")
            log_event(f"Flask 服务运行出错: {e}")

    flask_thread = threading.Thread(target=run, daemon=True)
    flask_thread.start()

    while not stop_event.is_set():
        stop_event.wait(1)

    # 停止 Flask 服务
    os._exit(0)


def open_browser(url):
    webbrowser.open(url)


class VersionChecker:
    def __init__(self, root):
        self.root = root

        # 配置信息
        self.ACCESS_TOKEN = "4af13024a4e20b212c998c308df5ca33"
        self.REPO_PATH = "is-haohao/HAO-Netdisk"
        self.API_URL = f"https://gitee.com/api/v5/repos/{self.REPO_PATH}/releases/latest"

        # 创建检测版本按钮
        self.check_button = tk.Button(self.root, text="检查最新版本", font=("Arial", 14), command=self.check_version,
                                      bg="#ffffff", fg="#000000", width=12)
        self.check_button.pack(pady=20)

        counter = 0

        Menubar = tk.Menu(root)

        # 创建文件菜单
        FileMenu = tk.Menu(Menubar, tearoff=0)
        Menubar.add_cascade(label='帮助', menu=FileMenu)
        FileMenu.add_command(label='关于协议选择', command=self.show_agreement_info)
        FileMenu.add_command(label='关于端口设置', command=self.show_port_info)
        FileMenu.add_command(label='关于', command=self.show_about_info)
        FileMenu.add_separator()
        FileMenu.add_command(label='查看日志', command=self.show_log_info)
        FileMenu.add_command(label='上传文件目录', command=self.show_folder_info)

        # 创建联系我们菜单
        Contact = tk.Menu(Menubar, tearoff=0)
        Menubar.add_cascade(label='联系我们', menu=Contact)
        Contact.add_command(label='发送邮件', command=self.send_email)
        Contact.add_command(label='我的网站', command=self.open_website)

        # 添加退出菜单项
        Menubar.add_cascade(label='退出', command=root.quit)

        # 配置菜单栏
        root.config(menu=Menubar)

    # 打开上传目录文件夹
    def show_folder_info(self):
        try:
            # 打开上传目录文件夹
            os.startfile(app.config['UPLOAD_FOLDER'])
        except FileNotFoundError:
            tk.messagebox.showerror('错误', '找不到上传目录文件夹')
            log_event(f'找不到上传目录文件夹')

    # 显示日志信息
    def show_log_info(self):
        try:
            with open('app.log', 'r') as file:
                log_content = file.read()

            # 创建一个新的窗口来显示日志
            log_window = tk.Toplevel(self.root)
            log_window.title('日志信息')
            log_window.geometry("700x500")

            # 创建一个文本框来显示日志内容
            text_box = tk.Text(log_window, wrap=tk.WORD)
            text_box.insert(tk.END, log_content)
            text_box.configure(state='disabled')  # 设置为只读

            # 创建一个垂直滚动条
            scroll_bar = tk.Scrollbar(log_window, orient=tk.VERTICAL)
            scroll_bar.pack(side=tk.RIGHT, fill=tk.Y)

            # 将滚动条与文本框关联
            text_box.config(yscrollcommand=scroll_bar.set)
            scroll_bar.config(command=text_box.yview)

            # 将文本框和滚动条添加到窗口
            text_box.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

            # 默认滚动到文本框的末尾
            text_box.see(tk.END)

        except FileNotFoundError:
            messagebox.showerror('错误', '找不到日志文件 "app.log"')
            log_event(f'找不到日志文件 "app.log"')
        except Exception as e:
            messagebox.showerror('错误', f'读取日志文件时发生错误: {e}')
            log_event(f'读取日志文件时发生错误: {e}')

    # 显示协议信息
    def show_agreement_info(self):
        import socket
        # 尝试创建一个IPv6的socket连接
        supports_ipv6 = False
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            # 连接到一个已知支持IPv6的地址
            sock.connect(('2001:4860:4860::8888', 53))
            supports_ipv6 = True
        except (socket.error, socket.gaierror):
            pass
        finally:
            sock.close()

        ipv6_status = "支持" if supports_ipv6 else "不支持"
        message = (
            f"当前网络{ipv6_status}IPv6。\n"
            "选择IPv6时，需要确保您的网络开启了IPv6，否则无法使用。\n"
            "选择IPv4时，需要确保您的网络运营商给您分配IPv4公网IP地址。"
        )
        messagebox.showinfo("关于协议选择", message)

    # 显示端口信息
    def show_port_info(self):
        messagebox.showinfo("关于端口设置", "端口可以进行随意设置,但需要确保端口未被占用。")

    # 显示关于信息
    def show_about_info(self):
        messagebox.showinfo("关于", f"HAO-Netdisk网盘系统。\n版本: {current_version}\nHAOHAO版权所有 © 2024")

    # 发送邮件
    def send_email(self):
        webbrowser.open("mailto:mdh233@126.com")

    # 打开网站
    def open_website(self):
        webbrowser.open("http://ishaohao.cn")

    def check_version(self):
        # 发送请求获取最新版本信息
        headers = {"Authorization": f"token {self.ACCESS_TOKEN}"}
        response = requests.get(self.API_URL, headers=headers)
        if response.status_code == 200:
            latest_release = response.json()
            latest_version = latest_release['tag_name']
            text_version = latest_version[1:]
            if latest_version > current_version:
                # 显示确认对话框，让用户选择是否更新
                answer = messagebox.askyesno("更新提示", f"发现新版本 {latest_version}，是否立即下载更新？")
                if answer:
                    webbrowser.open(
                        f"https://gitee.com/is-haohao/HAO-Netdisk/releases/download/{latest_version}/HAO-Netdisk_{text_version}.zip")
                    log_event(f"用户已选择更新，正在打开浏览器下载最新版本 {latest_version}。")
            else:
                messagebox.showinfo("版本信息", "当前已是最新版本。")
        else:
            messagebox.showerror("错误", "无法获取版本信息，请检查网络连接或访问令牌。")
            log_event("无法获取版本信息，请检查网络连接或访问令牌。")


class NetdiskLauncher:
    def __init__(self, master):
        self.master = master
        self.master.title("HAO-Netdisk 启动器")
        self.master.geometry("1060x680")
        self.master.configure(bg="#2e3a4f")
        self.master.resizable(False, False)
        self.stop_event = threading.Event()
        self.process = None
        self.host = "::"
        self.port = 5000

        self.create_widgets()
        self.update_status()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if messagebox.askokcancel("退出", "你确定要退出吗?"):
            if self.process:
                self.stop_service()
                self.process = None
            self.master.destroy()

    def create_widgets(self):
        Label(self.master, text="选择运行模式", font=("Arial", 14), bg="#2e3a4f", fg="#ffffff").pack(pady=10)

        self.mode_var = StringVar(value="IPv6")
        self.protocol_menu = OptionMenu(self.master, self.mode_var, "IPv6", "IPv4", command=self.update_protocol)
        self.protocol_menu.config(bg="#3b4d6b", fg="#ffffff", font=("Arial", 12))
        self.protocol_menu.pack(pady=5)

        self.protocol_menu["menu"].config(bg="#2e3a4f", fg="#ffffff", font=("Arial", 12))
        self.protocol_menu["highlightthickness"] = 0
        self.protocol_menu["bd"] = 0

        Label(self.master, text="端口号(默认5000)", font=("Arial", 12), bg="#2e3a4f", fg="#ffffff").pack(pady=5)
        self.port_entry = Entry(self.master, font=("Arial", 12))
        self.port_entry.pack(pady=5)
        self.port_entry.insert(0, str(self.port))

        self.start_button = Button(self.master, text="启动服务", font=("Arial", 14), command=self.start_service,
                                   bg="#4caf50", fg="#ffffff", width=15)
        self.start_button.pack(pady=10)

        self.stop_button = Button(self.master, text="停止服务", font=("Arial", 14), command=self.stop_service,
                                  bg="#f44336", fg="#ffffff", width=15)
        self.stop_button.pack(pady=10)

        self.restart_button = Button(self.master, text="重启服务", font=("Arial", 14), command=self.restart_service,
                                     bg="#ff9800", fg="#ffffff", width=15)
        self.restart_button.pack(pady=10)

        self.copy_public_link_button = Button(self.master, text="复制公网访问链接", font=("Arial", 14),
                                              command=self.copy_public_link,
                                              bg="#2196f3", fg="#ffffff", width=20)
        self.copy_public_link_button.pack(pady=10)

        self.copy_local_link_button = Button(self.master, text="复制本地访问链接", font=("Arial", 14),
                                             command=self.copy_local_link,
                                             bg="#2196f3", fg="#ffffff", width=20)
        self.copy_local_link_button.pack(pady=10)

        self.delete_file_button = Button(self.master, text="删除文件", font=("Arial", 14),
                                         command=self.delete_file_dialog, bg="#9c27b0", fg="#ffffff", width=15)
        self.delete_file_button.pack(pady=10)

        self.status_label = Label(self.master, text="", font=("Arial", 12), bg="#2e3a4f", fg="#ffffff")
        self.status_label.pack(pady=10)

        #  VersionChecker 组件
        self.version_checker = VersionChecker(self.master)

    def update_protocol(self, value):
        if value == "IPv6":
            self.host = "::"
        else:
            self.host = "0.0.0.0"
        self.update_status()

    def copy_public_link(self):
        if not self.process or not self.process.is_alive():
            messagebox.showwarning("警告", "服务未在运行中！")
            return
        selected_protocol = self.mode_var.get()
        public_ipv4, public_ipv6 = get_public_ip()
        if selected_protocol == "IPv4":
            if public_ipv4:
                link = f"http://{public_ipv4}:{self.port}"
            else:
                messagebox.showwarning("警告", "无法获取IPv4地址！")
                return
        elif selected_protocol == "IPv6":
            if public_ipv6:
                link = f"http://[{public_ipv6}]:{self.port}"
            else:
                messagebox.showwarning("警告", "无法获取IPv6地址！")
                return
        else:
            messagebox.showwarning("警告", "未知的协议类型！")
            return

            # 复制链接到剪贴板
        self.master.clipboard_clear()
        self.master.clipboard_append(link)
        self.master.update()

        # 显示信息消息
        messagebox.showinfo("信息", "公网访问链接已复制到剪贴板！")

    def copy_local_link(self):
        if not self.process or not self.process.is_alive():
            messagebox.showwarning("警告", "服务未在运行中！")
            return

        link = f"http://localhost:{self.port}"
        self.master.clipboard_clear()
        self.master.clipboard_append(link)
        self.master.update()
        messagebox.showinfo("信息", "本地访问链接已复制到剪贴板！")

    def update_status(self):
        if self.process and self.process.is_alive():
            self.status_label.config(text="服务正在运行", fg="#4caf50")
        else:
            self.status_label.config(text="服务未在运行", fg="#f44336")

    def start_service(self):
        if not self.process or not self.process.is_alive():
            self.host = self.host
            self.port = int(self.port_entry.get() or self.port)
            self.stop_event.clear()
            self.process = threading.Thread(target=self.run_flask_app, daemon=True)
            self.process.start()
            self.update_status()
            open_browser(f'http://localhost:{self.port}')

    def run_flask_app(self):
        start_flask_app(self.host, self.port, self.stop_event)

    def stop_service(self):
        if self.process and self.process.is_alive():
            self.stop_event.set()
            self.process.join()
            self.process = None
            self.update_status()
            messagebox.showinfo("信息", "网盘服务已停止！")
        else:
            messagebox.showwarning("警告", "服务未在运行中！")

    def restart_service(self):
        self.stop_service()
        self.start_service()

    def delete_file_dialog(self):
        if not self.process or not self.process.is_alive():
            messagebox.showwarning("警告", "服务未在运行中！")
            return

        try:
            response_files = requests.get(f"http://localhost:{self.port}/file_list_api")
            response_directories = requests.get(f"http://localhost:{self.port}/directory_list_api")
            response_files.raise_for_status()
            response_directories.raise_for_status()
        except requests.RequestException as e:
            messagebox.showerror("错误", f"无法获取文件或目录列表！\n{e}")
            log_event(f"无法获取文件或目录列表！\n{e}")
            return

        files = response_files.json()
        directories = response_directories.json()
        dialog = Toplevel(self.master)
        dialog.title("删除文件或目录")
        dialog.geometry("400x800")

        Label(dialog, text="选择要删除的文件或目录", font=("Arial", 16)).pack(pady=10)

        item_listbox = Listbox(dialog, font=("Arial", 16))
        item_listbox.insert(END, "文件:")
        for file in files:
            item_listbox.insert(END, file['filename'])
        item_listbox.insert(END, "目录:")
        for directory in directories:
            item_listbox.insert(END, directory['description'])
        item_listbox.pack(pady=5, fill='both', expand=True)

        def delete_item():
            selected_item = item_listbox.get(ACTIVE)
            if selected_item in [file['filename'] for file in files]:
                delete_type = 'file'
                payload = {'filename': selected_item}
                url = f"http://localhost:{self.port}/delete_file"
            elif selected_item in [directory['description'] for directory in directories]:
                delete_type = 'directory'
                directory_id = next(
                    directory['id'] for directory in directories if directory['description'] == selected_item)
                payload = {'directory_id': directory_id}
                url = f"http://localhost:{self.port}/delete_directory"
            else:
                messagebox.showerror("错误", "请选择要删除的文件或目录！")
                return

            try:
                response = requests.post(url, json=payload)
                response.raise_for_status()
                if response.status_code == 200:
                    messagebox.showinfo("信息", f"{delete_type.capitalize()} '{selected_item}' 已删除！")
                    log_event(f"管理员已删除 {delete_type} '{selected_item}'！")
                else:
                    messagebox.showerror("错误", f"{delete_type.capitalize()} '{selected_item}' 删除失败！")
                    log_event(f"管理员删除 {delete_type} '{selected_item}' 失败！")
            except requests.RequestException as e:
                messagebox.showerror("错误", f"{delete_type.capitalize()} '{selected_item}' 删除失败！\n{e}")
                log_event(f"管理员删除 {delete_type} '{selected_item}' 失败！\n{e}")
            dialog.destroy()

        Button(dialog, text="删除", command=delete_item, font=("Arial", 12)).pack(pady=10)


# 检查程序是否是第一次运行
first_run = True
try:
    with open('app.log', 'r') as file:
        if "程序已运行过" not in file.read():
            first_run = True
        else:
            first_run = False
except FileNotFoundError:
    first_run = True

if __name__ == "__main__":
    # 如果是第一次运行，创建桌面快捷方式
    if first_run:
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop_path, "HAO-Netdisk.lnk")  # 快捷方式文件名

        # 创建快捷方式的代码取决于操作系统
        if sys.platform.startswith('win'):
            # Windows系统下创建快捷方式
            import win32com.client

            shell = win32com.client.Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = sys.executable
            shortcut.WorkingDirectory = os.getcwd()
            shortcut.WindowStyle = 1
            shortcut.Save()

        # 记录日志，标记程序已运行过
        logging.info("程序为第一次运行，创建桌面快捷方式！")

    with app.app_context():
        db.create_all()

    try:
        import pyi_splash

        pyi_splash.close()
    except ImportError:
        pass

    root = Tk()
    app_gui = NetdiskLauncher(root)
    log_event("网盘启动器启动！")
    root.mainloop()
