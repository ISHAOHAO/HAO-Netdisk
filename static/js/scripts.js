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
