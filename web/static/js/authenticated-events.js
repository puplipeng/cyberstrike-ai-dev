(function (root) {
    'use strict';
    // Fetch-based SSE keeps the login token in Authorization, never in the URL.
    function createSSEParser(onmessage) {
        let pending = '', data = [], size = 0, event = '';
        return function push(text) {
            pending += text;
            let boundary;
            while ((boundary = pending.indexOf('\n')) >= 0) {
                let line = pending.slice(0, boundary).replace(/\r$/, '');
                pending = pending.slice(boundary + 1);
                if (line === '') {
                    if (data.length && (!event || event === 'message')) onmessage({data: data.join('\n')});
                    data = []; size = 0; event = '';
                } else if (line.startsWith('data:')) {
                    const value = line.slice(5).replace(/^ /, '');
                    size += value.length;
                    data.push(value);
                } else if (line.startsWith('event:')) event = line.slice(6).trim();
                if (size > 1024 * 1024) throw new Error('SSE event too large');
            }
            if (pending.length > 1024 * 1024) throw new Error('SSE line too large');
        };
    }

    function openAuthenticatedEventStream(url, options = {}) {
        let closed = false, controller = null, retryTimer = null;
        const fetcher = options.fetch || root.apiFetch;
        const stream = {close() {
            closed = true;
            if (retryTimer !== null) clearTimeout(retryTimer);
            if (controller) controller.abort();
        }};
        async function connect() {
            if (closed) return;
            controller = new AbortController();
            let reader;
            try {
                const response = await fetcher(url, {headers: {Accept: 'text/event-stream'}, signal: controller.signal, cache: 'no-store'});
                if (closed) { await response.body?.cancel(); return; }
                if (!response.ok) {
                    if ([401, 403, 503].includes(response.status)) closed = true;
                    await response.body?.cancel();
                    throw new Error('Event stream HTTP ' + response.status);
                }
                if (!response.headers.get('Content-Type')?.includes('text/event-stream')) { await response.body?.cancel(); throw new Error('Invalid event stream content type'); }
                reader = response.body.getReader();
                const decoder = new TextDecoder();
                const push = createSSEParser(e => { if (!closed) options.onmessage?.(e); });
                while (!closed) {
                    const result = await reader.read();
                    if (result.done) break;
                    if (!closed) push(decoder.decode(result.value, {stream: true}));
                }
            } catch (error) {
                if (!controller.signal.aborted) options.onerror?.(error);
            } finally {
                if (reader) { try { await reader.cancel(); } catch (_) {} reader.releaseLock(); }
                if (!closed) retryTimer = setTimeout(connect, 5000);
            }
        }
        connect();
        return stream;
    }
    root.openAuthenticatedEventStream = openAuthenticatedEventStream;
    if (typeof module !== 'undefined' && module.exports) module.exports = {createSSEParser, openAuthenticatedEventStream};
})(typeof window !== 'undefined' ? window : globalThis);
