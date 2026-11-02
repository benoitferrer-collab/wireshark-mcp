/* Route existing API calls directly to the analysis server, including large uploads. */
(() => {
    'use strict';
    if (window.PCAP_CONFIG?.webAuth) {
        const native = window.fetch.bind(window);
        const ready = native('/api/identity/me', {credentials:'same-origin'}).then(async response => {
            if (!response.ok) { window.location.assign('/auth/login'); throw new Error('Connexion requise'); }
            window.PCAP_IDENTITY = await response.json();
            return window.PCAP_IDENTITY;
        });
        window.PCAP_IDENTITY_READY = ready;
        window.fetch = async (input, init={}) => {
            const url = new URL(input instanceof Request ? input.url : String(input), location.href);
            if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return native(input,init);
            const user = await ready;
            const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
            headers.set('X-CSRF-Token',user.csrf);
            const options = {...init,headers,credentials:'same-origin'};
            if (window.PCAP_CONFIG.cloudMode && init.body instanceof FormData && ['/api/upload','/api/multi-pcap/analyze'].includes(url.pathname)) {
                const {uploadForm}=await import('/cloud-assets/upload.js');
                return uploadForm(init.body,url.pathname,'');
            }
            const response = await native(input,options);
            if (response.status===401) window.location.assign('/auth/login');
            return response;
        };
        return;
    }
    const configured = window.PCAP_CONFIG?.apiBaseUrl || '';
    const apiOrigin = configured ? new URL(configured).origin : window.location.origin;
    const nativeFetch = window.fetch.bind(window);
    const storageKey = `pcap-api-access:${apiOrigin}`;
    let token = sessionStorage.getItem(storageKey) || '';
    let pendingLogin = null;

    function connect() {
        if (pendingLogin) return pendingLogin;
        pendingLogin = new Promise((resolve, reject) => {
            const dialog = document.createElement('dialog');
            dialog.style.cssText = 'max-width:460px;width:90%;padding:24px;border-radius:16px;background:var(--bg-card,#182334);color:var(--text-primary,#fff);border:1px solid #64748b';
            dialog.innerHTML = `<form method="dialog">
                <h2>Connexion au serveur d’analyse</h2>
                <p>Renseigne ta clé d’accès. Elle sera conservée pour cette session du navigateur.</p>
                <label>Clé d’accès <input name="access" type="password" autocomplete="off" required minlength="32" style="width:100%;box-sizing:border-box;margin:12px 0;padding:10px"></label>
                <p role="alert" class="connection-error"></p>
                <button value="cancel" type="button">Annuler</button>
                <button type="submit">Se connecter</button>
            </form>`;
            document.body.appendChild(dialog);
            const form = dialog.querySelector('form');
            const input = form.elements.access;
            let settled = false;
            function cancel() {
                if (!settled) { settled = true; reject(new Error('Connexion annulée')); }
                dialog.close();
                dialog.remove();
            }
            dialog.addEventListener('cancel', event => { event.preventDefault(); cancel(); });
            dialog.querySelector('[value="cancel"]').addEventListener('click', cancel);
            form.addEventListener('submit', async event => {
                event.preventDefault();
                const candidate = input.value.trim();
                const submit = form.querySelector('[type="submit"]');
                submit.disabled = true;
                try {
                    const response = await nativeFetch(`${apiOrigin}/api/mcp-data/history?limit=1`, {
                        headers: { Authorization: `Bearer ${candidate}` }, credentials: 'omit',
                    });
                    if (!response.ok) throw new Error('Connexion refusée. Vérifie la clé et la configuration du serveur.');
                    if (settled) return;
                    token = candidate;
                    sessionStorage.setItem(storageKey, token);
                    settled = true;
                    resolve(token);
                    dialog.close();
                    dialog.remove();
                } catch (error) {
                    dialog.querySelector('.connection-error').textContent = error.message;
                } finally { submit.disabled = false; }
            });
            dialog.showModal();
        }).finally(() => { pendingLogin = null; });
        return pendingLogin;
    }

    window.fetch = async (input, init = {}) => {
        const isRequest = input instanceof Request;
        const url = new URL(isRequest ? input.url : String(input), window.location.href);
        if (!url.pathname.startsWith('/api/') || ![window.location.origin, apiOrigin].includes(url.origin)) {
            return nativeFetch(input, init);
        }
        const needsLogin = Boolean(configured || window.PCAP_CONFIG?.requiresAccessKey) && url.pathname !== '/api/health';
        if (needsLogin && !token) await connect();
        const target = new URL(url.pathname + url.search, apiOrigin);
        const headers = new Headers(init.headers || (isRequest ? input.headers : undefined));
        if (token) headers.set('Authorization', `Bearer ${token}`);
        const options = { ...init, headers, credentials: 'omit' };
        const request = isRequest ? new Request(target, new Request(input, options)) : target;
        let response;
        if (window.PCAP_CONFIG?.cloudMode && init.body instanceof FormData &&
            ['/api/upload', '/api/multi-pcap/analyze'].includes(url.pathname)) {
            const { uploadForm } = await import('/cloud-assets/upload.js');
            response = await uploadForm(init.body, url.pathname, `Bearer ${token}`);
        } else {
            response = await nativeFetch(request, isRequest ? undefined : options);
        }
        if (response.status === 401) {
            token = '';
            sessionStorage.removeItem(storageKey);
            // Do not automatically replay uploads or other mutations.
        }
        return response;
    };

    const button = document.createElement('button');
    button.textContent = 'Connexion API';
    button.className = 'btn btn-secondary';
    button.type = 'button';
    button.addEventListener('click', async () => {
        try { await connect(); } catch (_) { /* Cancellation is intentional. */ }
    });
    const actions = document.querySelector('.header-info');
    if (actions) actions.appendChild(button);
})();
