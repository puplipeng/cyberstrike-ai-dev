/**
 * 主对话区智能粘底滚动：流式输出时自动跟随，用户上滑阅读时不抢焦点。
 * 主 POST 流（sendMessage）与刷新后 task-events 补流共用同一策略。
 */
(function () {
    'use strict';

    /** 距底部在此范围内才继续自动跟随（宜小，避免“差一点也被拽回去”） */
    const CHAT_SCROLL_FOLLOW_THRESHOLD_PX = 48;
    /** 只有真正到达底部才恢复跟随；2px 用于兼容高分屏的亚像素滚动。 */
    const CHAT_SCROLL_FOLLOW_RESUME_THRESHOLD_PX = 2;
    /** 到达此范围视为位于最后一轮 */
    const CHAT_SCROLL_NAV_BOTTOM_THRESHOLD_PX = 120;
    /** 用户上滑后的短暂锁，防止 SSE 与 scroll 事件竞态抢滚动 */
    const DETACH_LOCK_MS = 900;
    /** 刷新恢复会跨越历史消息、过程详情、字体与流订阅等多轮异步布局。 */
    const CONVERSATION_RESTORE_SETTLE_MIN_MS = 3000;
    const CONVERSATION_RESTORE_SETTLE_MAX_MS = 6000;
    const CONVERSATION_RESTORE_STABLE_FRAMES = 12;

    /**
     * following: 用户明确选择跟随最新输出
     * anchored: 新一轮开始后把问题固定在阅读区上方，回复增长不再持续推走视口
     * detached: 用户主动上滑阅读历史
     * @type {'following' | 'anchored' | 'detached'}
     */
    let scrollMode = 'following';
    let currentTurnAnchorId = '';
    /** 当前轮次的阅读锚点只应用一次，避免流式 DOM 增长反复改写主视口 scrollTop。 */
    let currentTurnAnchorApplied = false;
    let scrollFollowRaf = 0;
    let scrollSettleGeneration = 0;
    let conversationRestoreGeneration = 0;
    /** 用户脱离跟随后，下方是否有未读的新输出（不按 SSE 次数计） */
    let hasPendingNewBelow = false;
    let listenersBound = false;
    let lastScrollTop = 0;
    let lastScrollHeight = 0;
    let programmaticScroll = false;
    let detachLockUntil = 0;
    /** 最近一次由用户发起的滚动意图；布局变化或脚本滚动不得据此恢复粘底。 */
    let userScrollIntentUntil = 0;
    let turnRailRefreshRaf = 0;
    let turnRailSignature = '';
    let activeTurnIndex = -1;
    let turnRailObserver = null;
    let chatMessagesResizeObserver = null;
    let turnPreviewHideTimer = 0;
    /** 切出聊天页时保存稳定阅读位置，返回时只恢复一次，不重新启动持续滚底。 */
    let pageNavigationViewState = null;

    function getChatMessagesEl() {
        return document.getElementById('chat-messages');
    }

    function getTurnRailEl() {
        return document.getElementById('chat-turn-rail');
    }

    function getTurnRailMarkersEl() {
        return document.getElementById('chat-turn-rail-markers');
    }

    function getReturnLatestButton() {
        return document.getElementById('chat-return-latest');
    }

    function isChatPageActive() {
        const page = document.getElementById('page-chat');
        return !page || (page.classList && page.classList.contains('active'));
    }

    function cancelContinuousScrollWork() {
        scrollSettleGeneration++;
        conversationRestoreGeneration++;
        cancelAnimationFrame(scrollFollowRaf);
        scrollFollowRaf = 0;
        programmaticScroll = false;
    }

    function findChatMessageByIdentity(el, backendMessageId, elementId) {
        if (!el) return null;
        const backendId = String(backendMessageId || '').trim();
        const domId = String(elementId || '').trim();
        return Array.from(el.children || []).find(function (messageEl) {
            if (!messageEl) return false;
            const messageBackendId = messageEl.dataset
                ? String(messageEl.dataset.backendMessageId || '').trim()
                : '';
            return (backendId && messageBackendId === backendId) ||
                (domId && String(messageEl.id || '') === domId);
        }) || null;
    }

    function captureChatViewState() {
        if (!isChatPageActive() && pageNavigationViewState) {
            return Object.assign({}, pageNavigationViewState);
        }
        const el = getChatMessagesEl();
        if (!el) return null;
        const scrollTop = Number(el.scrollTop) || 0;
        const viewportAnchor = Array.from(el.children || []).find(function (messageEl) {
            if (!messageEl) return false;
            const top = Number(messageEl.offsetTop) || 0;
            const height = Math.max(1, Number(messageEl.offsetHeight) || 1);
            return top + height >= scrollTop;
        }) || null;
        const turnAnchor = currentTurnAnchorId
            ? findChatMessageByIdentity(el, '', currentTurnAnchorId)
            : null;
        return {
            mode: scrollMode,
            scrollTop: scrollTop,
            viewportAnchorBackendMessageId: viewportAnchor && viewportAnchor.dataset
                ? String(viewportAnchor.dataset.backendMessageId || '')
                : '',
            viewportAnchorElementId: viewportAnchor ? String(viewportAnchor.id || '') : '',
            viewportAnchorOffset: viewportAnchor
                ? (Number(viewportAnchor.offsetTop) || 0) - scrollTop
                : 0,
            turnAnchorBackendMessageId: turnAnchor && turnAnchor.dataset
                ? String(turnAnchor.dataset.backendMessageId || '')
                : '',
            turnAnchorElementId: turnAnchor ? String(turnAnchor.id || '') : '',
            hasPendingNewBelow: hasPendingNewBelow
        };
    }

    function restoreChatViewState(state) {
        if (!state || typeof state !== 'object') return;
        cancelContinuousScrollWork();
        if (!isChatPageActive()) {
            pageNavigationViewState = Object.assign({}, state);
            return;
        }
        const el = getChatMessagesEl();
        if (!el) return;

        const desiredMode = state.mode === 'following'
            ? 'following'
            : (state.mode === 'anchored' ? 'anchored' : 'detached');
        scrollMode = desiredMode;
        currentTurnAnchorId = '';
        currentTurnAnchorApplied = false;
        detachLockUntil = 0;
        userScrollIntentUntil = 0;
        hasPendingNewBelow = desiredMode === 'following' ? false : !!state.hasPendingNewBelow;

        if (desiredMode === 'anchored') {
            const turnAnchor = findChatMessageByIdentity(
                el,
                state.turnAnchorBackendMessageId,
                state.turnAnchorElementId
            );
            if (turnAnchor && turnAnchor.id) {
                currentTurnAnchorId = String(turnAnchor.id);
                currentTurnAnchorApplied = true;
            } else {
                // 重绘后找不到原轮次锚点时保持当前位置，不能退回持续跟随。
                scrollMode = 'detached';
            }
        }

        programmaticScroll = true;
        if (scrollMode === 'following') {
            el.scrollTop = el.scrollHeight;
        } else {
            const viewportAnchor = findChatMessageByIdentity(
                el,
                state.viewportAnchorBackendMessageId,
                state.viewportAnchorElementId
            );
            let targetScrollTop = Number(state.scrollTop) || 0;
            if (viewportAnchor) {
                targetScrollTop = (Number(viewportAnchor.offsetTop) || 0) -
                    (Number(state.viewportAnchorOffset) || 0);
            }
            const maxScrollTop = Math.max(0, el.scrollHeight - el.clientHeight);
            el.scrollTop = Math.max(0, Math.min(maxScrollTop, targetScrollTop));
        }
        lastScrollTop = el.scrollTop;
        lastScrollHeight = el.scrollHeight;
        requestAnimationFrame(function () {
            programmaticScroll = false;
            updateTurnRailState();
        });
    }

    function suspendChatAutoScrollForRender() {
        cancelContinuousScrollWork();
        scrollMode = 'detached';
        currentTurnAnchorId = '';
        currentTurnAnchorApplied = false;
        detachLockUntil = 0;
        userScrollIntentUntil = 0;
    }

    function onChatPageLeave() {
        pageNavigationViewState = captureChatViewState();
        cancelContinuousScrollWork();
    }

    function onChatPageEnter() {
        cancelContinuousScrollWork();
        if (pageNavigationViewState) {
            const state = pageNavigationViewState;
            pageNavigationViewState = null;
            restoreChatViewState(state);
            return;
        }
        const el = getChatMessagesEl();
        if (el) {
            lastScrollTop = el.scrollTop;
            lastScrollHeight = el.scrollHeight;
        }
        updateTurnRailState();
    }

    function normalizePreviewText(value) {
        return String(value || '').replace(/\s+/g, ' ').trim();
    }

    function trimPreviewText(value, maxLength) {
        const text = normalizePreviewText(value);
        if (text.length <= maxLength) return text;
        return text.slice(0, Math.max(1, maxLength - 1)).trimEnd() + '…';
    }

    function messagePreviewText(messageEl) {
        if (!messageEl) return '';
        const original = messageEl.dataset ? messageEl.dataset.originalContent : '';
        if (original) return normalizePreviewText(original);
        const bubble = messageEl.querySelector('.assistant-final-result, .message-bubble');
        if (!bubble) return '';
        const clone = bubble.cloneNode(true);
        clone.querySelectorAll('button, .message-copy-btn, .progress-actions, .progress-footer, .process-details-content').forEach(function (el) {
            el.remove();
        });
        return normalizePreviewText(clone.textContent);
    }

    /** 每条用户消息开始一轮，直到下一条用户消息前的助手消息都归入该轮。 */
    function collectConversationTurns() {
        const messagesEl = getChatMessagesEl();
        if (!messagesEl) return [];
        const turns = [];
        let currentTurn = null;
        Array.from(messagesEl.children).forEach(function (messageEl) {
            if (!messageEl.classList || !messageEl.classList.contains('message')) return;
            if (messageEl.classList.contains('user')) {
                currentTurn = { user: messageEl, assistants: [] };
                turns.push(currentTurn);
                return;
            }
            if (currentTurn && messageEl.classList.contains('assistant')) {
                currentTurn.assistants.push(messageEl);
            }
        });
        return turns;
    }

    function localizedTurnLabel(index, question) {
        const number = index + 1;
        const prefix = typeof window.t === 'function'
            ? window.t('chat.turnNumber', { number: number })
            : '第 ' + number + ' 轮';
        const safePrefix = prefix && prefix !== 'chat.turnNumber' ? prefix : ('第 ' + number + ' 轮');
        return question ? safePrefix + '：' + question : safePrefix;
    }

    function turnPreviewData(turn, index) {
        const question = trimPreviewText(messagePreviewText(turn && turn.user), 100)
            || localizedTurnLabel(index, '');
        const assistants = turn && turn.assistants ? turn.assistants : [];
        let assistant = null;
        for (let i = assistants.length - 1; i >= 0; i--) {
            if (!assistants[i].classList.contains('progress-message')) {
                assistant = assistants[i];
                break;
            }
        }
        if (!assistant && assistants.length) assistant = assistants[assistants.length - 1];
        let summary = trimPreviewText(messagePreviewText(assistant), 220);
        if (!summary) {
            summary = typeof window.t === 'function' ? window.t('chat.turnPending') : '正在处理…';
            if (!summary || summary === 'chat.turnPending') summary = '正在处理…';
        }
        return { question: question, summary: summary };
    }

    function hideTurnPreview() {
        if (turnPreviewHideTimer) {
            window.clearTimeout(turnPreviewHideTimer);
            turnPreviewHideTimer = 0;
        }
        const preview = document.getElementById('chat-turn-rail-preview');
        if (preview) preview.hidden = true;
    }

    function scheduleHideTurnPreview() {
        if (turnPreviewHideTimer) window.clearTimeout(turnPreviewHideTimer);
        turnPreviewHideTimer = window.setTimeout(hideTurnPreview, 160);
    }

    function showTurnPreview(marker, index) {
        if (turnPreviewHideTimer) {
            window.clearTimeout(turnPreviewHideTimer);
            turnPreviewHideTimer = 0;
        }
        const preview = document.getElementById('chat-turn-rail-preview');
        const title = document.getElementById('chat-turn-rail-preview-title');
        const summary = document.getElementById('chat-turn-rail-preview-summary');
        const turn = collectConversationTurns()[index];
        if (!preview || !title || !summary || !marker || !turn) return;

        const data = turnPreviewData(turn, index);
        title.textContent = data.question;
        summary.textContent = data.summary;
        preview.hidden = false;

        const markerRect = marker.getBoundingClientRect();
        const previewRect = preview.getBoundingClientRect();
        const left = Math.min(markerRect.right + 18, window.innerWidth - previewRect.width - 12);
        const desiredTop = markerRect.top + markerRect.height / 2 - previewRect.height / 2;
        const top = Math.max(12, Math.min(desiredTop, window.innerHeight - previewRect.height - 12));
        preview.style.left = Math.max(12, left) + 'px';
        preview.style.top = top + 'px';
    }

    function setActiveTurnMarker(index) {
        const markersEl = getTurnRailMarkersEl();
        if (!markersEl) return;
        const markers = Array.from(markersEl.querySelectorAll('.chat-turn-rail-marker'));
        if (!markers.length) return;
        const nextIndex = Math.max(0, Math.min(index, markers.length - 1));
        markers.forEach(function (marker, markerIndex) {
            const active = markerIndex === nextIndex;
            marker.classList.toggle('is-active', active);
            if (active) marker.setAttribute('aria-current', 'step');
            else marker.removeAttribute('aria-current');
        });
        markers[markers.length - 1].classList.toggle('has-pending-new', hasPendingNewBelow);

        if (activeTurnIndex !== nextIndex) {
            activeTurnIndex = nextIndex;
            const activeMarker = markers[nextIndex];
            const markerTop = activeMarker.offsetTop;
            const markerBottom = markerTop + activeMarker.offsetHeight;
            if (markerTop < markersEl.scrollTop) {
                markersEl.scrollTop = Math.max(0, markerTop - 8);
            } else if (markerBottom > markersEl.scrollTop + markersEl.clientHeight) {
                markersEl.scrollTop = markerBottom - markersEl.clientHeight + 8;
            }
        }
    }

    function updateTurnRailActive() {
        const messagesEl = getChatMessagesEl();
        const turns = collectConversationTurns();
        if (!messagesEl || !turns.length) return;
        if (isNearBottom(CHAT_SCROLL_NAV_BOTTOM_THRESHOLD_PX)) {
            setActiveTurnMarker(turns.length - 1);
            return;
        }
        const readingLine = messagesEl.scrollTop + messagesEl.clientHeight * 0.34;
        let index = 0;
        for (let i = 0; i < turns.length; i++) {
            if (turns[i].user.offsetTop <= readingLine) index = i;
            else break;
        }
        setActiveTurnMarker(index);
    }

    function jumpToConversationTurn(index) {
        const messagesEl = getChatMessagesEl();
        const turn = collectConversationTurns()[index];
        if (!messagesEl || !turn || !turn.user) return;
        setScrollDetached();
        programmaticScroll = true;
        messagesEl.scrollTo({
            top: Math.max(0, turn.user.offsetTop - 20),
            behavior: 'smooth'
        });
        setActiveTurnMarker(index);
        hideTurnPreview();
        window.setTimeout(function () {
            programmaticScroll = false;
            lastScrollTop = messagesEl.scrollTop;
            updateTurnRailActive();
        }, 420);
    }

    function focusTurnMarker(index) {
        const markersEl = getTurnRailMarkersEl();
        const marker = markersEl && markersEl.querySelector('.chat-turn-rail-marker[data-turn-index="' + index + '"]');
        if (marker) marker.focus();
    }

    function rebuildTurnRail(force) {
        const rail = getTurnRailEl();
        const markersEl = getTurnRailMarkersEl();
        if (!rail || !markersEl) return;
        const turns = collectConversationTurns();
        rail.hidden = turns.length === 0;
        if (!turns.length) {
            markersEl.replaceChildren();
            turnRailSignature = '';
            activeTurnIndex = -1;
            hideTurnPreview();
            return;
        }

        const signature = turns.map(function (turn, index) {
            return (turn.user.id || ('turn-' + index)) + ':' + messagePreviewText(turn.user);
        }).join('|');
        if (!force && signature === turnRailSignature) {
            updateTurnRailActive();
            return;
        }

        const fragment = document.createDocumentFragment();
        turns.forEach(function (turn, index) {
            const marker = document.createElement('button');
            const question = trimPreviewText(messagePreviewText(turn.user), 88);
            marker.type = 'button';
            marker.className = 'chat-turn-rail-marker';
            marker.dataset.turnIndex = String(index);
            marker.setAttribute('aria-label', localizedTurnLabel(index, question));
            marker.addEventListener('click', function () {
                jumpToConversationTurn(index);
            });
            marker.addEventListener('mouseenter', function () {
                showTurnPreview(marker, index);
            });
            marker.addEventListener('mouseleave', scheduleHideTurnPreview);
            marker.addEventListener('keydown', function (event) {
                if (event.key === 'ArrowDown' || event.key === 'ArrowRight') {
                    event.preventDefault();
                    focusTurnMarker(Math.min(turns.length - 1, index + 1));
                } else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') {
                    event.preventDefault();
                    focusTurnMarker(Math.max(0, index - 1));
                } else if (event.key === 'Home') {
                    event.preventDefault();
                    focusTurnMarker(0);
                } else if (event.key === 'End') {
                    event.preventDefault();
                    focusTurnMarker(turns.length - 1);
                }
            });
            fragment.appendChild(marker);
        });
        markersEl.replaceChildren(fragment);
        turnRailSignature = signature;
        activeTurnIndex = -1;
        updateTurnRailActive();
    }

    function scheduleTurnRailRefresh(force) {
        cancelAnimationFrame(turnRailRefreshRaf);
        turnRailRefreshRaf = requestAnimationFrame(function () {
            rebuildTurnRail(force === true);
        });
    }

    function streamBelongsToVisibleConversation(stream) {
        if (!stream || !stream.active) return false;
        const visibleConversationId = typeof window.currentConversationId === 'string'
            ? window.currentConversationId.trim()
            : '';
        const streamConversationId = typeof stream.conversationId === 'string'
            ? stream.conversationId.trim()
            : '';

        // 新建对话在后端返回 conversationId 前，两边都为空，仍属于当前界面。
        if (!streamConversationId) return !visibleConversationId;
        return streamConversationId === visibleConversationId;
    }

    /** 只有当前可见对话的主 POST 流 / task-events 补流才视为「正在输出」 */
    function isStreamActive() {
        try {
            const live = window.__csAgentLiveStream;
            if (streamBelongsToVisibleConversation(live)) return true;
            const replay = window.__csTaskEventStream;
            return streamBelongsToVisibleConversation(replay);
        } catch (e) {
            return false;
        }
    }

    function isVisibleConversationTaskActive() {
        if (isStreamActive()) return true;
        try {
            const visibleConversationId = typeof window.currentConversationId === 'string'
                ? window.currentConversationId.trim()
                : '';
            if (!visibleConversationId) return false;
            const taskChecker = typeof window.isConversationTaskRunning === 'function'
                ? window.isConversationTaskRunning
                : (typeof isConversationTaskRunning === 'function' ? isConversationTaskRunning : null);
            return !!(taskChecker && taskChecker(visibleConversationId));
        } catch (e) {
            return false;
        }
    }

    function distanceFromBottom(el) {
        if (!el) return 0;
        const { scrollTop, scrollHeight, clientHeight } = el;
        return scrollHeight - clientHeight - scrollTop;
    }

    function isNearBottom(thresholdPx) {
        const el = getChatMessagesEl();
        if (!el) return true;
        return distanceFromBottom(el) <= thresholdPx;
    }

    function isChatMessagesPinnedToBottom() {
        return isNearBottom(CHAT_SCROLL_NAV_BOTTOM_THRESHOLD_PX);
    }

    /** 已在底部时恢复 following（解决：手动滚到底但 scrollMode 仍为 detached） */
    function resumeFollowingIfAtBottom(thresholdPx, userInitiated) {
        if (!userInitiated && Date.now() < detachLockUntil) return false;
        const threshold = Number.isFinite(Number(thresholdPx))
            ? Math.max(0, Number(thresholdPx))
            : CHAT_SCROLL_FOLLOW_RESUME_THRESHOLD_PX;
        if (!isNearBottom(threshold)) return false;
        // anchored / detached 都是稳定阅读状态。布局变化、流式增高和模式切换
        // 即使让视口暂时接近底部，也不能自行恢复；只有用户明确向下滚到底才恢复。
        if (scrollMode !== 'following') {
            if (!userInitiated) return false;
            setScrollFollowing();
        }
        return true;
    }

    function captureScrollPinState() {
        if (Date.now() < detachLockUntil) return false;
        return scrollMode === 'following';
    }

    function setScrollFollowing() {
        scrollMode = 'following';
        currentTurnAnchorId = '';
        currentTurnAnchorApplied = false;
        detachLockUntil = 0;
        userScrollIntentUntil = 0;
        hasPendingNewBelow = false;
        updateTurnRailState();
    }

    function markPendingNewBelow() {
        if (scrollMode === 'following') return;
        hasPendingNewBelow = true;
        updateTurnRailState();
    }

    function setScrollDetached() {
        scrollMode = 'detached';
        currentTurnAnchorId = '';
        currentTurnAnchorApplied = false;
        detachLockUntil = Date.now() + DETACH_LOCK_MS;
        cancelAnimationFrame(scrollFollowRaf);
        if (isStreamActive()) {
            hasPendingNewBelow = true;
        }
        updateTurnRailState();
    }

    function scrollChatToTurnAnchor() {
        if (scrollMode !== 'anchored' || !currentTurnAnchorId || currentTurnAnchorApplied) return false;
        const el = getChatMessagesEl();
        const anchor = document.getElementById(currentTurnAnchorId);
        if (!el || !anchor) return false;

        const maxScrollTop = Math.max(0, el.scrollHeight - el.clientHeight);
        const targetScrollTop = Math.max(0, Math.min(maxScrollTop, anchor.offsetTop - 18));
        currentTurnAnchorApplied = true;
        programmaticScroll = true;
        if (Math.abs(el.scrollTop - targetScrollTop) > 1) {
            el.scrollTop = targetScrollTop;
        }
        lastScrollTop = el.scrollTop;
        lastScrollHeight = el.scrollHeight;
        requestAnimationFrame(function () {
            programmaticScroll = false;
            updateTurnRailState();
        });
        return true;
    }

    function scheduleChatTurnAnchor() {
        if (scrollMode !== 'anchored' || currentTurnAnchorApplied) return;
        cancelAnimationFrame(scrollFollowRaf);
        scrollFollowRaf = requestAnimationFrame(scrollChatToTurnAnchor);
    }

    function setScrollAnchored(anchorMessageId) {
        const id = String(anchorMessageId || '').trim();
        if (!id) {
            setScrollFollowing();
            return;
        }
        scrollMode = 'anchored';
        currentTurnAnchorId = id;
        currentTurnAnchorApplied = false;
        detachLockUntil = 0;
        userScrollIntentUntil = 0;
        hasPendingNewBelow = false;
        // 用户消息已经插入 DOM，此处同步固定阅读位置，先于进度消息和 SSE 更新。
        // 极少数节点尚未可用的场景再退回下一帧重试。
        if (!scrollChatToTurnAnchor()) scheduleChatTurnAnchor();
        updateTurnRailState();
    }

    function scrollChatToBottomInstant() {
        if (!isChatPageActive() || scrollMode !== 'following') return;
        const el = getChatMessagesEl();
        if (!el) return;
        programmaticScroll = true;
        el.scrollTop = el.scrollHeight;
        lastScrollTop = el.scrollTop;
        lastScrollHeight = el.scrollHeight;
        requestAnimationFrame(function () {
            programmaticScroll = false;
        });
    }

    function scrollChatToBottomSmooth() {
        const el = getChatMessagesEl();
        if (!el) return;
        programmaticScroll = true;
        el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
        requestAnimationFrame(function () {
            programmaticScroll = false;
            const node = getChatMessagesEl();
            if (node) {
                lastScrollTop = node.scrollTop;
                lastScrollHeight = node.scrollHeight;
            }
        });
    }

    function updateTurnRailState() {
        updateTurnRailActive();
        updateReturnLatestButton();
    }

    function updateReturnLatestButton() {
        const button = getReturnLatestButton();
        const messagesEl = getChatMessagesEl();
        if (!button || !messagesEl) return;
        const scrollable = messagesEl.scrollHeight > messagesEl.clientHeight + 2;
        const atLatest = isNearBottom(CHAT_SCROLL_FOLLOW_RESUME_THRESHOLD_PX);
        const readingDetachedHistory = scrollMode !== 'following' && !atLatest;
        const farFromLatestFallback = !isNearBottom(CHAT_SCROLL_NAV_BOTTOM_THRESHOLD_PX);
        const shouldShow = scrollable && (readingDetachedHistory || farFromLatestFallback);
        const streaming = shouldShow && isVisibleConversationTaskActive();
        button.hidden = !shouldShow;
        button.classList.toggle('is-streaming', streaming);
        button.classList.toggle('has-pending-new', shouldShow && hasPendingNewBelow);
    }

    function isolateReturnLatestPointerEvent(event) {
        if (!event) return;
        // 该按钮会在点击后立即隐藏。阻止指针事件继续冒泡，避免长历史对话中
        // 按钮隐藏与底部审批卡片重排发生在同一帧时产生点击穿透。
        event.stopPropagation();
    }

    function onReturnLatestClick(event) {
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        forceScrollChatToBottom(true);
        const button = getReturnLatestButton();
        if (button) {
            button.hidden = true;
            button.blur();
        }
    }

    function canAutoScrollNow(wasPinnedBeforeDomUpdate) {
        if (!isChatPageActive()) return false;
        if (Date.now() < detachLockUntil) return false;
        if (scrollMode !== 'following') return false;
        if (wasPinnedBeforeDomUpdate === true) return true;
        return isNearBottom(CHAT_SCROLL_FOLLOW_THRESHOLD_PX);
    }

    function scheduleChatScrollToBottomIfFollowing(wasPinnedBeforeDomUpdate) {
        if (!canAutoScrollNow(wasPinnedBeforeDomUpdate)) {
            markPendingNewBelow();
            return;
        }
        cancelAnimationFrame(scrollFollowRaf);
        scrollFollowRaf = requestAnimationFrame(scrollChatToBottomInstant);
    }

    /**
     * 长详情恢复/终态对账会跨多个 requestAnimationFrame 分批增高 DOM。
     * 单次滚底可能早于最后一批节点；在仍处于 following 时连续若干帧校准，
     * 用户一旦主动上滑进入 detached，后续帧立即停止，避免抢回阅读位置。
     */
    function settleChatToBottomIfFollowing(frameCount) {
        const frames = Number.isFinite(Number(frameCount))
            ? Math.max(1, Math.min(30, Math.floor(Number(frameCount))))
            : 12;
        const generation = ++scrollSettleGeneration;

        function settleFrame(remaining) {
            if (generation !== scrollSettleGeneration) return;
            if (scrollMode !== 'following' || Date.now() < detachLockUntil) return;
            scrollChatToBottomInstant();
            if (remaining > 1) {
                requestAnimationFrame(function () {
                    settleFrame(remaining - 1);
                });
            }
        }

        requestAnimationFrame(function () {
            settleFrame(frames);
        });
    }

    /**
     * 刷新恢复长会话时，消息、详情和审批卡会跨多帧继续增高。
     * 进入恢复流程时明确回到 following；用户随后若主动上滑，既有输入监听会立即
     * 切换为 detached，并使后续校准帧停止，不会抢回阅读位置。
     */
    function settleConversationRestoreToBottom(frameCount) {
        if (!isChatPageActive()) return;
        setScrollFollowing();
        const requestedFrames = Number.isFinite(Number(frameCount))
            ? Math.max(1, Math.floor(Number(frameCount)))
            : 30;
        const minimumDuration = Math.max(
            CONVERSATION_RESTORE_SETTLE_MIN_MS,
            Math.ceil(requestedFrames * (1000 / 60))
        );
        const generation = ++conversationRestoreGeneration;
        const startedAt = Date.now();
        let lastHeight = -1;
        let stableFrames = 0;

        function settleRestoreFrame() {
            if (generation !== conversationRestoreGeneration) return;
            if (!isChatPageActive()) return;
            // wheel / touch / keyboard / scrollbar drag 会进入 detached；立即尊重用户阅读位置。
            if (scrollMode !== 'following' || Date.now() < detachLockUntil) return;
            const el = getChatMessagesEl();
            if (!el) return;

            scrollChatToBottomInstant();
            const currentHeight = el.scrollHeight;
            if (currentHeight === lastHeight && isNearBottom(1)) {
                stableFrames += 1;
            } else {
                stableFrames = 0;
            }
            lastHeight = currentHeight;

            const elapsed = Date.now() - startedAt;
            const reachedStableMinimum = elapsed >= minimumDuration
                && stableFrames >= CONVERSATION_RESTORE_STABLE_FRAMES;
            if (!reachedStableMinimum && elapsed < CONVERSATION_RESTORE_SETTLE_MAX_MS) {
                requestAnimationFrame(settleRestoreFrame);
            }
        }

        requestAnimationFrame(settleRestoreFrame);
    }

    /** @param {boolean} wasPinned DOM 更新前是否应跟随（由 captureScrollPinState 传入） */
    function scrollChatMessagesToBottomIfPinned(wasPinned) {
        scheduleChatScrollToBottomIfFollowing(wasPinned);
    }

    function forceScrollChatToBottom(smooth) {
        setScrollFollowing();
        cancelAnimationFrame(scrollFollowRaf);
        if (smooth) {
            scrollChatToBottomSmooth();
        } else {
            scrollChatToBottomInstant();
        }
    }

    function onUserSendMessage(anchorMessageId) {
        setScrollAnchored(anchorMessageId);
    }

    function clearAllStreamingMarkers() {
        document.querySelectorAll('.progress-container.is-streaming, .process-details-container.is-streaming').forEach(function (el) {
            el.classList.remove('is-streaming');
        });
    }

    function markProgressStreaming(active, progressId) {
        if (!active) {
            clearAllStreamingMarkers();
            return;
        }
        if (!progressId) return;
        const progressEl = document.getElementById(progressId);
        const container = progressEl && progressEl.querySelector('.progress-container');
        if (container) container.classList.add('is-streaming');
    }

    function markProcessDetailsStreaming(active, assistantDomId) {
        if (!active) {
            document.querySelectorAll('.process-details-container.is-streaming').forEach(function (el) {
                el.classList.remove('is-streaming');
            });
            return;
        }
        if (!assistantDomId) return;
        const container = document.getElementById('process-details-' + assistantDomId);
        if (!container) return;
        container.classList.add('is-streaming');
        const timeline = container.querySelector('.progress-timeline');
        if (timeline) timeline.classList.add('expanded');
    }

    function onStreamEnd() {
        clearAllStreamingMarkers();
        try {
            window.__csTaskEventStream = { active: false, conversationId: null, assistantDomId: null, progressId: null };
        } catch (e) { /* ignore */ }
        scheduleTurnRailRefresh(true);
        updateTurnRailState();
    }

    /** 刷新后会话 task-events 补流开始时，与 sendMessage 主流程对齐 */
    function onTaskEventStreamBegin(conversationId, assistantDomId, progressId) {
        try {
            window.__csTaskEventStream = {
                active: true,
                conversationId: conversationId || null,
                assistantDomId: assistantDomId || null,
                progressId: progressId || null
            };
        } catch (e) { /* ignore */ }
        markProcessDetailsStreaming(true, assistantDomId);
        resumeFollowingIfAtBottom();
        scheduleTurnRailRefresh();
        updateTurnRailState();
    }

    function onTaskEventStreamEnd() {
        onStreamEnd();
    }

    function applyMessageScrollOption(options) {
        scheduleTurnRailRefresh();
        const opt = (options && options.scroll) || 'follow';
        if (opt === 'none') return;
        if (opt === 'force') {
            forceScrollChatToBottom(false);
            return;
        }
        scheduleChatScrollToBottomIfFollowing(captureScrollPinState());
    }

    /** 流式/用户未跟随时禁止 scrollIntoView 抢滚动 */
    function scrollElementIntoViewIfFollowing(el, options) {
        if (!el || !captureScrollPinState()) return;
        el.scrollIntoView(options || { behavior: 'smooth', block: 'nearest' });
    }

    function onChatMessagesScroll() {
        const el = getChatMessagesEl();
        if (!el) return;

        const st = el.scrollTop;
        const sh = el.scrollHeight;
        const hasUserScrollIntent = Date.now() <= userScrollIntentUntil;

        if (programmaticScroll) {
            // 正在执行恢复/流式粘底时，用户仍可能反向滚轮或拖动滚动条。
            // 脚本滚底只会让 scrollTop 增大；此处出现减小必定是用户在中断跟随。
            if (st < lastScrollTop - 1 && (scrollMode === 'detached' || hasUserScrollIntent)) {
                setScrollDetached();
            }
            lastScrollTop = st;
            lastScrollHeight = sh;
            updateTurnRailState();
            return;
        }

        const scrolledUp = st < lastScrollTop - 1;
        const scrolledDown = st > lastScrollTop + 1;
        const contentShrank = sh < lastScrollHeight - 1;

        // 刷新/终态重绘会先清空或折叠旧 DOM，浏览器会被动把 scrollTop 压小。
        // 这不是用户上滑，不应错误退出 following。
        if (contentShrank) {
            lastScrollTop = st;
            lastScrollHeight = sh;
            updateTurnRailState();
            return;
        }

        // 刷新恢复会重建消息和详情，滚动锚定可能在没有用户输入时让 scrollTop
        // 暂时减小。只有明确的滚轮、触控、键盘或滚动条意图才解除粘底。
        if (scrolledUp && (scrollMode === 'detached' || hasUserScrollIntent)) {
            setScrollDetached();
        } else if (
            scrolledDown &&
            hasUserScrollIntent &&
            resumeFollowingIfAtBottom(CHAT_SCROLL_FOLLOW_RESUME_THRESHOLD_PX, true)
        ) {
            // 仅在用户明确向下滚动并到达真实底部时恢复跟随，不主动改写 scrollTop。
            // 后续新增内容再按 following 状态自然粘底，避免接近底部时突然跳动。
        }

        lastScrollTop = st;
        lastScrollHeight = sh;
        updateTurnRailState();
    }

    function bindChatScrollListeners() {
        if (listenersBound) return;
        const el = getChatMessagesEl();
        if (!el) return;
        listenersBound = true;
        lastScrollTop = el.scrollTop;
        lastScrollHeight = el.scrollHeight;

        el.addEventListener('wheel', function (e) {
            if (Math.abs(e.deltaY) > 1) {
                userScrollIntentUntil = Date.now() + 1200;
            }
            if (e.deltaY < -1) {
                setScrollDetached();
            }
        }, { passive: true });

        // 拖动原生纵向滚动条不会产生 wheel；先记录指针意图，再由 scroll 事件确认方向。
        el.addEventListener('pointerdown', function (e) {
            const rect = el.getBoundingClientRect();
            if (e.clientX >= rect.right - 18) {
                userScrollIntentUntil = Date.now() + 1800;
            }
        }, { passive: true });

        el.addEventListener('keydown', function (e) {
            const scrollKeys = ['ArrowUp', 'PageUp', 'Home', 'ArrowDown', 'PageDown', 'End', ' '];
            if (scrollKeys.includes(e.key)) {
                userScrollIntentUntil = Date.now() + 1200;
            }
            if (e.key === 'ArrowUp' || e.key === 'PageUp' || e.key === 'Home' || (e.key === ' ' && e.shiftKey)) {
                setScrollDetached();
            }
        });

        el.addEventListener('touchmove', function (e) {
            if (e.touches && e.touches.length === 1) {
                userScrollIntentUntil = Date.now() + 1200;
                el._csTouchLastY = el._csTouchLastY != null ? el._csTouchLastY : e.touches[0].clientY;
                if (e.touches[0].clientY > el._csTouchLastY + 4) {
                    setScrollDetached();
                }
                el._csTouchLastY = e.touches[0].clientY;
            }
        }, { passive: true });
        el.addEventListener('touchstart', function (e) {
            if (e.touches && e.touches.length) {
                el._csTouchLastY = e.touches[0].clientY;
            }
        }, { passive: true });
        el.addEventListener('touchend', function () {
            el._csTouchLastY = null;
        }, { passive: true });

        el.addEventListener('scroll', onChatMessagesScroll, { passive: true });

        const returnLatestButton = getReturnLatestButton();
        if (returnLatestButton) {
            returnLatestButton.addEventListener('pointerdown', isolateReturnLatestPointerEvent);
            returnLatestButton.addEventListener('pointerup', isolateReturnLatestPointerEvent);
            returnLatestButton.addEventListener('click', onReturnLatestClick);
        }

        const turnPreview = document.getElementById('chat-turn-rail-preview');
        if (turnPreview) {
            turnPreview.addEventListener('mouseenter', function () {
                if (turnPreviewHideTimer) {
                    window.clearTimeout(turnPreviewHideTimer);
                    turnPreviewHideTimer = 0;
                }
            });
            turnPreview.addEventListener('mouseleave', scheduleHideTurnPreview);
        }

        if (typeof MutationObserver === 'function') {
            turnRailObserver = new MutationObserver(function () {
                if (!isChatPageActive()) return;
                scheduleTurnRailRefresh();
                // 最终回复会替换消息气泡内部 HTML，任务详情也会在子树内持续增高。
                // 只在仍处于 following 时按帧合并粘底；用户上滑后的 detached 状态不受影响。
            if (scrollMode === 'following' && Date.now() >= detachLockUntil) {
                scheduleChatScrollToBottomIfFollowing(true);
            } else if (scrollMode === 'anchored') {
                markPendingNewBelow();
                scheduleChatTurnAnchor();
            } else {
                markPendingNewBelow();
            }
            });
            turnRailObserver.observe(el, { childList: true, subtree: true, characterData: true });
        }

        if (typeof ResizeObserver === 'function') {
            chatMessagesResizeObserver = new ResizeObserver(function () {
                if (!isChatPageActive()) return;
                // 顶部运行任务条、输入框或视口变化会改变消息区 clientHeight，
                // 但不会触发消息子树 MutationObserver。跟随模式下需重新精确粘底。
                if (scrollMode === 'following' && Date.now() >= detachLockUntil) {
                    scheduleChatScrollToBottomIfFollowing(true);
                } else if (scrollMode === 'anchored') {
                    markPendingNewBelow();
                    scheduleChatTurnAnchor();
                } else {
                    markPendingNewBelow();
                    updateTurnRailState();
                }
            });
            chatMessagesResizeObserver.observe(el);
        }

        window.addEventListener('resize', function () {
            if (!isChatPageActive()) return;
            hideTurnPreview();
            if (scrollMode === 'following' && Date.now() >= detachLockUntil) {
                scheduleChatScrollToBottomIfFollowing(true);
            } else {
                updateTurnRailState();
            }
        }, { passive: true });
    }

    function initChatScroll() {
        bindChatScrollListeners();
        const el = getChatMessagesEl();
        if (el) {
            lastScrollTop = el.scrollTop;
            lastScrollHeight = el.scrollHeight;
        }
        scheduleTurnRailRefresh(true);
        updateTurnRailState();
    }

    window.CyberStrikeChatScroll = {
        init: initChatScroll,
        onUserSendMessage: onUserSendMessage,
        onStreamEnd: onStreamEnd,
        onTaskEventStreamBegin: onTaskEventStreamBegin,
        onTaskEventStreamEnd: onTaskEventStreamEnd,
        captureScrollPinState: captureScrollPinState,
        scheduleScroll: scheduleChatScrollToBottomIfFollowing,
        scrollIfPinned: scrollChatMessagesToBottomIfPinned,
        settleToBottomIfFollowing: settleChatToBottomIfFollowing,
        settleConversationRestoreToBottom: settleConversationRestoreToBottom,
        forceScrollToBottom: forceScrollChatToBottom,
        applyMessageScroll: applyMessageScrollOption,
        scrollIntoViewIfFollowing: scrollElementIntoViewIfFollowing,
        isPinnedToBottom: isChatMessagesPinnedToBottom,
        markProgressStreaming: markProgressStreaming,
        markProcessDetailsStreaming: markProcessDetailsStreaming,
        setScrollFollowing: setScrollFollowing,
        setScrollAnchored: setScrollAnchored,
        setScrollDetached: setScrollDetached,
        captureViewState: captureChatViewState,
        restoreViewState: restoreChatViewState,
        suspendForRender: suspendChatAutoScrollForRender,
        onPageLeave: onChatPageLeave,
        onPageEnter: onChatPageEnter,
        refreshReturnLatest: updateReturnLatestButton,
        refreshTurnRail: function () { scheduleTurnRailRefresh(true); },
    };

    window.isChatMessagesPinnedToBottom = isChatMessagesPinnedToBottom;
    window.captureScrollPinState = captureScrollPinState;
    window.scrollChatMessagesToBottomIfPinned = scrollChatMessagesToBottomIfPinned;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initChatScroll);
    } else {
        initChatScroll();
    }
})();
