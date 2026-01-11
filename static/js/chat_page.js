// chat_page.js
document.addEventListener('DOMContentLoaded', () => {
  const messages = document.getElementById('chat-messages');
  const input = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send');

  // read CSRF token from meta tag placed in the page head
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute('content') : null;

  // In-memory conversation history (resets on refresh)
  let conversationHistory = [];

  function escapeHtml(s) {
    if (!s && s !== 0) return '';
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );
  }

  function addMessage(text, role = 'bot') {
    const div = document.createElement('div');
    div.className = 'msg ' + (role === 'user' ? 'user' : 'bot');
    div.innerHTML = `<div class="bubble">${escapeHtml(text)}</div>`;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
  }

  function addLoadingMessage() {
    const div = document.createElement('div');
    div.className = 'msg bot loading-msg';
    div.innerHTML = `<div class="bubble">Thinking…</div>`;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
    return div;
  }

  function removeLoadingMessage(element) {
    if (element && element.parentNode) element.parentNode.removeChild(element);
  }

  async function sendQuery(q) {
    if (!q) return;

    addMessage(q, 'user');
    input.value = '';

    conversationHistory.push({ role: 'user', content: q });
    if (conversationHistory.length > 20) {
      conversationHistory = conversationHistory.slice(-20);
    }

    sendBtn.disabled = true;
    input.disabled = true;

    const loadingEl = addLoadingMessage();

    try {
      // build headers, include CSRF header if available
      const headers = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      };
      if (CSRF_TOKEN) headers['X-CSRFToken'] = CSRF_TOKEN;

      const res = await fetch('/api/chat', {
        method: 'POST',
        credentials: 'same-origin',
        headers,
        body: JSON.stringify({ query: q, history: conversationHistory })
      });

      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await res.text().catch(() => '');
        console.error('Non-JSON response from server:', text);
        removeLoadingMessage(loadingEl);

        if (/login|sign.?in/i.test(text)) {
          addMessage('⚠️ You are not logged in. Please sign in and try again.', 'bot');
        } else if (/csrf token is missing/i.test(text.toLowerCase())) {
          addMessage('⚠️ CSRF token missing. Reload the page and try again.', 'bot');
        } else {
          addMessage('⚠️ Server returned unexpected response. Please try again.', 'bot');
        }
        return;
      }

      const data = await res.json().catch(e => {
        console.error('Failed to parse JSON:', e);
        return null;
      });

      removeLoadingMessage(loadingEl);

      if (!res.ok) {
        const msg = (data && (data.answer || data.error || data.message)) || `Server error ${res.status}`;
        if (res.status === 401) {
          addMessage('⚠️ Authentication required. Please login and try again.', 'bot');
        } else {
          addMessage(msg, 'bot');
        }
        return;
      }

      const answer = (data && (data.answer || data.response || data.reply)) || 'Sorry, I could not answer that.';
      addMessage(answer, 'bot');

      conversationHistory.push({ role: 'assistant', content: answer });
      if (conversationHistory.length > 20) {
        conversationHistory = conversationHistory.slice(-20);
      }

    } catch (err) {
      console.error('Network / fetch error:', err);
      removeLoadingMessage(loadingEl);
      addMessage('Error talking to server. Please check your connection or try again.', 'bot');
    } finally {
      sendBtn.disabled = false;
      input.disabled = false;
      input.focus();
    }
  }

  sendBtn.addEventListener('click', () => {
    const q = input.value.trim();
    if (q) sendQuery(q);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const q = input.value.trim();
      if (q) sendQuery(q);
    }
  });

  // initial greeting
  addMessage("Hi! I'm your AI assistant. Ask me about notes, timetable, exams, or subjects.", 'bot');
  input.focus();
});
