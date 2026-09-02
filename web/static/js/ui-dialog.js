/**
 * 统一风格对话框组件：替代浏览器原生 alert / confirm / prompt。
 *
 * API：
 *   appAlert(message[, options])                -> Promise<void>      （确定按钮）
 *   appConfirm(message[, options])              -> Promise<boolean>   （确定 / 取消）
 *   appPrompt(message[, defaultValue, options]) -> Promise<string|null>（确定返回输入值，取消返回 null）
 *
 * options:
 *   title      标题（默认按类型：提示 / 请确认 / 请输入）
 *   type       'info' | 'success' | 'warning' | 'error'（图标与标题色）
 *   confirmText / cancelText  自定义按钮文案
 *   multiline  appPrompt 多行输入（textarea）
 *   danger     确认按钮渲染为危险（红色）样式
 *
 * 样式完全复用项目 CSS 变量（style.css 的 :root / dark 主题），亮暗主题自动适配。
 */
(function () {
    const DIALOG_ROOT_ID = 'app-ui-dialog-root';
    const OPEN_CLASS = 'app-ui-dialog-open';
    const FOCUSABLE_SELECTOR =
        'input.app-ui-dialog-input, textarea.app-ui-dialog-input, button.app-ui-dialog-btn';

    let openCount = 0;
    let lastFocused = null;

    function t(key, fallback) {
        try {
            if (window.i18next && typeof window.i18next.t === 'function') {
                const v = window.i18next.t(key);
                if (v && v !== key) return v;
            }
        } catch (e) { /* i18n 未就绪时回退 */ }
        return fallback;
    }

    function ensureRoot() {
        let root = document.getElementById(DIALOG_ROOT_ID);
        if (!root) {
            root = document.createElement('div');
            root.id = DIALOG_ROOT_ID;
            document.body.appendChild(root);
        }
        return root;
    }

    function svgIcon(type) {
        const stroke = 'currentColor';
        const paths = {
            info: '<circle cx="12" cy="12" r="9"/><path d="M12 8v.01"/><path d="M12 11.5V16"/>',
            success: '<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>',
            warning: '<path d="M12 3.5 21 19.5H3z"/><path d="M12 10v4"/><path d="M12 17v.01"/>',
            error: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6"/><path d="M15 9l-6 6"/>'
        };
        return (
            '<svg class="app-ui-dialog-icon" viewBox="0 0 24 24" fill="none" stroke="' + stroke +
            '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            (paths[type] || paths.info) + '</svg>'
        );
    }

    /**
     * 打开一个对话框。kind: 'alert' | 'confirm' | 'prompt'
     * 返回 Promise；resolve 值：alert -> undefined, confirm -> bool, prompt -> string|null
     */
    function openDialog(kind, message, options) {
        options = options && typeof options === 'object' ? options : {};
        const type = ['info', 'success', 'warning', 'error'].indexOf(options.type) >= 0 ? options.type : 'info';

        let title = typeof options.title === 'string' ? options.title : '';
        if (!title) {
            if (kind === 'confirm') title = t('dialog.titleConfirm', '请确认');
            else if (kind === 'prompt') title = t('dialog.titlePrompt', '请输入');
            else if (type === 'error') title = t('dialog.titleError', '出错了');
            else title = t('dialog.titleNotice', '提示');
        }

        const confirmText = typeof options.confirmText === 'string' && options.confirmText.trim()
            ? options.confirmText.trim()
            : t('dialog.ok', '确定');
        const cancelText = typeof options.cancelText === 'string' && options.cancelText.trim()
            ? options.cancelText.trim()
            : t('dialog.cancel', '取消');

        const root = ensureRoot();

        return new Promise(function (resolve) {
            const overlay = document.createElement('div');
            overlay.className = 'app-ui-dialog-overlay';

            const dialog = document.createElement('div');
            dialog.className = 'app-ui-dialog';
            dialog.setAttribute('role', 'dialog');
            dialog.setAttribute('aria-modal', 'true');

            const header = document.createElement('div');
            header.className = 'app-ui-dialog-header';
            header.innerHTML =
                svgIcon(type) +
                '<h3 class="app-ui-dialog-title"></h3>';
            header.querySelector('.app-ui-dialog-title').textContent = title;

            const body = document.createElement('div');
            body.className = 'app-ui-dialog-body';
            const content = document.createElement('div');
            content.className = 'app-ui-dialog-message';
            // message 支持 \n 换行；错误详情等长文本保持等宽可换行
            content.style.whiteSpace = 'pre-wrap';
            content.style.wordBreak = 'break-word';
            content.textContent = message == null ? '' : String(message);
            body.appendChild(content);

            let input = null;
            if (kind === 'prompt') {
                input = document.createElement(options.multiline ? 'textarea' : 'input');
                input.className = 'app-ui-dialog-input';
                if (options.multiline) {
                    input.rows = options.rows || 5;
                    input.style.resize = 'vertical';
                } else {
                    input.type = options.inputType || 'text';
                }
                const initial = options.defaultValue != null ? String(options.defaultValue) : '';
                input.value = initial;
                body.appendChild(input);
            }

            const footer = document.createElement('div');
            footer.className = 'app-ui-dialog-footer';

            const confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = 'app-ui-dialog-btn app-ui-dialog-btn-primary' +
                (options.danger ? ' app-ui-dialog-btn-danger' : '');
            confirmBtn.textContent = confirmText;

            let cancelBtn = null;
            if (kind !== 'alert') {
                cancelBtn = document.createElement('button');
                cancelBtn.type = 'button';
                cancelBtn.className = 'app-ui-dialog-btn';
                cancelBtn.textContent = cancelText;
            }

            footer.appendChild(confirmBtn);
            if (cancelBtn) footer.appendChild(cancelBtn);

            dialog.appendChild(header);
            dialog.appendChild(body);
            dialog.appendChild(footer);
            overlay.appendChild(dialog);
            root.appendChild(overlay);

            let settled = false;
            function finish(value) {
                if (settled) return;
                settled = true;
                overlay.classList.remove('app-ui-dialog-visible');
                setTimeout(function () {
                    overlay.remove();
                }, 160);
                openCount -= 1;
                if (openCount <= 0) {
                    openCount = 0;
                    document.body.classList.remove(OPEN_CLASS);
                    if (lastFocused && document.contains(lastFocused)) {
                        try { lastFocused.focus(); } catch (e) { /* ignore */ }
                    }
                    lastFocused = null;
                }
                document.removeEventListener('keydown', onKeydown, true);
                resolve(value);
            }

            function onConfirm() {
                if (kind === 'confirm') finish(true);
                else if (kind === 'prompt') finish(input ? input.value : '');
                else finish(undefined);
            }
            function onCancel() {
                finish(kind === 'confirm' ? false : null);
            }

            function onKeydown(e) {
                if (!document.body.contains(overlay)) return;
                if (e.key === 'Escape' && kind !== 'alert') {
                    e.preventDefault();
                    e.stopPropagation();
                    onCancel();
                } else if (e.key === 'Enter' && kind !== 'alert') {
                    // prompt 单行输入回车确认；多行不拦截
                    if (kind === 'prompt' && options.multiline) return;
                    if (input && document.activeElement === input) {
                        e.preventDefault();
                        e.stopPropagation();
                        onConfirm();
                    }
                }
            }

            confirmBtn.addEventListener('click', onConfirm);
            if (cancelBtn) cancelBtn.addEventListener('click', onCancel);

            if (openCount === 0) {
                lastFocused = document.activeElement;
            }
            openCount += 1;
            document.body.classList.add(OPEN_CLASS);
            document.addEventListener('keydown', onKeydown, true);

            // 入场动画（下一帧触发 transition）
            requestAnimationFrame(function () {
                overlay.classList.add('app-ui-dialog-visible');
                const target = (kind === 'prompt' && input) ? input : confirmBtn;
                try { target.focus(); } catch (e) { /* ignore */ }
                if (kind === 'prompt' && input && !options.multiline) {
                    try { input.select(); } catch (e) { /* ignore */ }
                }
            });
        });
    }

    function appAlert(message, options) {
        return openDialog('alert', message, options);
    }
    function appConfirm(message, options) {
        return openDialog('confirm', message, options);
    }
    function appPrompt(message, defaultValue, options) {
        if (options == null && defaultValue != null && typeof defaultValue === 'object') {
            options = defaultValue;
            defaultValue = '';
        }
        const opts = Object.assign({}, options || {}, {
            defaultValue: defaultValue != null ? String(defaultValue) : ''
        });
        return openDialog('prompt', message, opts);
    }

    window.appAlert = appAlert;
    window.appConfirm = appConfirm;
    window.appPrompt = appPrompt;
})();
