import { api, jwtToken } from './api.js?v=2';
import { showToast } from './ui.js';
import { currentCaseId } from './state.js';

export function setupChat() {
    const chatInput = document.getElementById('chat-input');
    const chatSendBtn = document.getElementById('chat-send');
    const chatMessages = document.getElementById('chat-messages');

    async function sendMessage() {
        const text = chatInput.value.trim();
        if (!text) return;

        if (!currentCaseId) {
            showToast("Please open a case before using the AI Chat.", 'error');
            return;
        }

        const userMsg = document.createElement('div');
        userMsg.className = 'chat-msg user-msg animate-fade-in';
        userMsg.innerHTML = `
          <div class="msg-avatar">U</div>
          <div class="msg-bubble">${text}</div>
        `;
        chatMessages.appendChild(userMsg);
        chatInput.value = '';
        chatMessages.scrollTop = chatMessages.scrollHeight;

        const loadingMsg = document.createElement('div');
        loadingMsg.className = 'chat-msg ai-msg animate-fade-in';
        loadingMsg.innerHTML = `
          <div class="msg-avatar"><i data-lucide="cpu" style="width:20px;height:20px;"></i></div>
          <div class="msg-bubble" style="opacity: 0.7; font-style: italic;">Analyzing case data...</div>
        `;
        chatMessages.appendChild(loadingMsg);
        if (typeof lucide !== 'undefined') lucide.createIcons();
        chatMessages.scrollTop = chatMessages.scrollHeight;

        try {
            // Ensure we have a token (if not, we could await a dummy api call, but cases load first so it should exist)
            const response = await fetch('/api/chat/stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': jwtToken ? `Bearer ${jwtToken}` : ''
                },
                body: JSON.stringify({ case_id: parseInt(currentCaseId, 10), question: text })
            });
            
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}: ${response.statusText}`);
            }

            loadingMsg.remove();

            const aiMsg = document.createElement('div');
            aiMsg.className = 'chat-msg ai-msg animate-fade-in';
            
            const avatarDiv = document.createElement('div');
            avatarDiv.className = 'msg-avatar';
            avatarDiv.innerHTML = '<i data-lucide="message-square" style="width:20px;height:20px;"></i>';
            aiMsg.appendChild(avatarDiv);
            
            const bubbleDiv = document.createElement('div');
            bubbleDiv.className = 'msg-bubble';
            
            const textDiv = document.createElement('div');
            bubbleDiv.appendChild(textDiv);
            
            const metaDiv = document.createElement('div');
            metaDiv.style = "margin-top: 0.75rem; font-size: 0.75rem; color: var(--text-muted); border-top: 1px solid rgba(255,255,255,0.1); padding-top: 0.5rem; display: none;";
            bubbleDiv.appendChild(metaDiv);
            
            aiMsg.appendChild(bubbleDiv);
            chatMessages.appendChild(aiMsg);
            if (typeof lucide !== 'undefined') lucide.createIcons();
            
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            
            let fullText = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n');
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const data = JSON.parse(line.substring(6));
                            
                            if (data.type === 'meta') {
                                metaDiv.innerHTML = `Model: ${data.provider || 'unknown'} | Grounding: ${data.grounding_score !== undefined ? data.grounding_score : 'N/A'}`;
                                metaDiv.style.display = 'block';
                            } else if (data.type === 'token') {
                                fullText += data.text;
                                textDiv.innerHTML = fullText.replace(/\\n|\n/g, '<br>');
                                chatMessages.scrollTop = chatMessages.scrollHeight;
                            } else if (data.type === 'done') {
                                // Stream complete
                            } else if (data.type === 'error') {
                                textDiv.innerHTML += `<br><br><span style="color: var(--danger);">[Server Error: ${data.message}]</span>`;
                                chatMessages.scrollTop = chatMessages.scrollHeight;
                            }
                        } catch (e) {
                            console.error("Error parsing SSE JSON", e, line);
                        }
                    }
                }
            }

        } catch (err) {
            console.error(err);
            loadingMsg.remove();
            const errMsg = document.createElement('div');
            errMsg.className = 'chat-msg ai-msg animate-fade-in';
            errMsg.innerHTML = `
              <div class="msg-avatar"><i data-lucide="alert-triangle" style="width:20px;height:20px; color: var(--danger);"></i></div>
              <div class="msg-bubble" style="color: var(--danger); background: rgba(239, 68, 68, 0.1);">Error connecting to AI: ${err.message}</div>
            `;
            chatMessages.appendChild(errMsg);
            if (typeof lucide !== 'undefined') lucide.createIcons();
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }

    if (chatSendBtn) {
        chatSendBtn.addEventListener('click', sendMessage);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
    }

    const suggestionChips = document.querySelectorAll('#chat-suggestions .chip');
    suggestionChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const query = chip.getAttribute('data-query');
            if (query) {
                chatInput.value = query;
                sendMessage();
            }
        });
    });
}
