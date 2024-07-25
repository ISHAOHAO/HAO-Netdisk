// 文件上传预览
document.querySelector('input[type="file"]').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.querySelector('#file-preview');
            if (preview) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            }
        };
        reader.readAsDataURL(file);
    }
});

// 搜索功能自动提交
document.querySelector('input[name="search"]').addEventListener('input', function(event) {
    if (event.target.value.length >= 3) {
        document.querySelector('form').submit();
    }
});

// 处理表单提交事件，显示弹窗
document.addEventListener('DOMContentLoaded', () => {
    const flashMessage = document.querySelector('.flash-message');
    if (flashMessage) {
        setTimeout(() => {
            flashMessage.remove();
        }, 3000);
    }
});

// 处理表单提交后弹窗
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', (event) => {
        if (form.checkValidity()) {
            // 可以添加表单验证成功后的处理逻辑
        } else {
            event.preventDefault();
            alert('请检查表单中的错误。');
        }
    });
});

