# HAO-Netdisk（HAO网盘）

- 项目由"HAOHAO"参考ChatGPT内容编写完成。


- 本人第一次写项目各位大佬多多担待！有任何问题请[联系我](https://qm.qq.com/q/lf0MWf2Vna)QQ63507764，说明来意即可！

### 程序下载链接

- [Gitee:https://gitee.com/is-haohao/HAO-Netdisk/releases](https://gitee.com/is-haohao/HAO-Netdisk/releases)
- [https://github.com/ISHAOHAO/HAO-Netdisk/releases](https://github.com/ISHAOHAO/HAO-Netdisk/releases)

### 程序简介

- 这里是列表文本本项目是一个在线网盘程序，通过IPV6放行端口5000达到联网互通的效果。


- 上传的文件将在根目录中的【uploads】文件夹内呈现。

### 当前程序版本:v0.1.9

#### v0.1.9更新内容:

1. [x] 添加了`分享链接输入密码`的功能，在有密码保护分享链接中，需输入密码下载文件。
2. [x] 添加了`分享链接密码保护`的功能，可以选择是否需要密码保护。
3. [x] 添加了`分享链接过期处理`的功能，定期检查分享链接的有效期，过期后将其从文件分享数据结构中删除，使链接无效
4. [x] 修复了`上传头像只能上传一次`的错误，在过去版本中只能上传一次，现在可以多次上传。

#### 未来规划

1. [ ] `用户头像裁剪`，暂时还未开发完成。
2. [ ] `在线编辑`，暂时还未开发完成。
3. [ ] `手机端APP`，暂时还未开发完成。

### 使用说明

- 点击app.exe执行文件即可，本程序采用IPV6网络，没有IPV4公网IP也可以实现互联。
- 如何访问你所开启网盘：

1. 图片是你打开程序后的执行窗口，其中红框内的就是你所开启网盘的网址，直接复制输入浏览器即可

![网址位置](wangzhi.png)

- 想要关闭网盘将黑色执行窗口关闭即可,如果出现关闭窗口后程序依然执行的情况按照以下步骤操作：

1.同时按住 `Windows + R`

2.输入 `cmd`

3.输入 `taskkill /f /t /im app.exe` 即可！

