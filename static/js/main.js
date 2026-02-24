// Общие функции для всех страниц

// Автофокус на первом поле
document.addEventListener('DOMContentLoaded', function() {
    const firstInput = document.querySelector('input[autofocus]');
    if (firstInput) {
        firstInput.focus();
    }
});

// Обработка Enter в формах
document.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        const form = e.target.closest('form');
        if (form) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.click();
            }
        }
    }
});


