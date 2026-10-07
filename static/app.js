/* ========================================================
   ELEMENTS
======================================================== */

const chatEl = document.getElementById("chat");
const msgEl = document.getElementById("message");
const send = document.getElementById("sendBtn");
const attach = document.getElementById("attachBtn");
const input = document.getElementById("fileInput");
const mic = document.getElementById("micBtn");
const chips = document.getElementById("attachments");
const health = document.getElementById("health");
const newChat = document.getElementById("newChat");

const loginScreen = document.getElementById("loginScreen");
const chatApp = document.getElementById("chatApp");
const loginForm = document.getElementById("loginForm");
const loginUsername = document.getElementById("loginUsername");
const loginPassword = document.getElementById("loginPassword");
const loginButton = document.getElementById("loginButton");
const loginError = document.getElementById("loginError");
const currentUser = document.getElementById("currentUser");
const logoutButton = document.getElementById("logoutButton");

let history = [];
let attachments = [];
let recorder = null;
let chunks = [];

const WELCOME_HTML = `
    <div class="welcome" id="welcome">
        <h1>How can I help you?</h1>
        <p>Upload a document, image or audio file, or ask a question.</p>
    </div>
`;

/* ========================================================
   AUTHENTICATION HELPERS
======================================================== */

function getToken() {
    return localStorage.getItem("access_token");
}

function showLogin() {
    if (loginScreen) loginScreen.style.display = "flex";
    if (chatApp) chatApp.style.display = "none";
}

function showChat() {
    if (loginScreen) loginScreen.style.display = "none";
    if (chatApp) chatApp.style.display = "flex";
}

function clearAuth() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");

    showLogin();

    if (loginUsername) loginUsername.value = "";
    if (loginPassword) loginPassword.value = "";
    if (loginError) loginError.textContent = "";

    history = [];
    attachments = [];
    render();

    if (chatEl) chatEl.innerHTML = WELCOME_HTML;
}

function authHeaders(extra = {}) {
    return {
        ...extra,
        "Authorization": `Bearer ${getToken()}`
    };
}

/* Wrapper for every protected API request. */
async function authenticatedFetch(url, options = {}) {
    if (!getToken()) {
        clearAuth();
        throw new Error("Authentication required. Please login again.");
    }

    const response = await fetch(url, {
        ...options,
        headers: authHeaders(options.headers || {})
    });

    if (response.status === 401) {
        clearAuth();
        throw new Error("Session expired. Please login again.");
    }

    return response;
}

/* ========================================================
   LOGIN
======================================================== */

async function login(username, password) {
    const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, password: password })
    });

    let data = {};

    try {
        data = await response.json();
    } catch (error) {
        data = {};
    }

    if (!response.ok) {
        throw new Error(data.detail || "Invalid User ID or password.");
    }

    if (!data.access_token) {
        throw new Error("Login succeeded but no access token was returned.");
    }

    localStorage.setItem("access_token", data.access_token);

    return data;
}

async function loadCurrentUser() {
    if (!getToken()) {
        return false;
    }

    try {
        const response = await fetch("/api/auth/me", {
            method: "GET",
            headers: authHeaders()
        });

        if (!response.ok) {
            clearAuth();
            return false;
        }

        const user = await response.json();

        localStorage.setItem("user", JSON.stringify(user));

        if (currentUser) {
            currentUser.textContent = `${user.username} (${user.role})`;
        }

        showChat();

        return true;

    } catch (error) {
        console.error("Authentication check failed:", error);
        clearAuth();
        return false;
    }
}

if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        if (loginError) loginError.textContent = "";

        const username = loginUsername ? loginUsername.value.trim() : "";
        const password = loginPassword ? loginPassword.value : "";

        if (!username || !password) {
            if (loginError) {
                loginError.textContent = "User ID and password are required.";
            }
            return;
        }

        const originalLabel = loginButton ? loginButton.textContent : "";

        if (loginButton) {
            loginButton.disabled = true;
            loginButton.textContent = "Signing in...";
        }

        try {
            await login(username, password);

            const authenticated = await loadCurrentUser();

            if (!authenticated) {
                throw new Error("Authentication failed.");
            }

            if (loginPassword) loginPassword.value = "";

            check();

        } catch (error) {
            console.error("Login error:", error);

            localStorage.removeItem("access_token");
            localStorage.removeItem("user");

            if (loginError) {
                loginError.textContent = error.message || "Login failed.";
            }

        } finally {
            if (loginButton) {
                loginButton.disabled = false;
                loginButton.textContent = originalLabel;
            }
        }
    });
}

if (logoutButton) {
    logoutButton.addEventListener("click", () => {
        clearAuth();
        if (loginUsername) loginUsername.focus();
    });
}

/* Runs once when the page opens: login first, chat only if token is valid. */
(async function initializeAuthentication() {
    if (!loginScreen || !chatApp) {
        console.error(
            "index.html is missing #loginScreen or #chatApp - " +
            "the login page cannot be shown."
        );
    }

    const authenticated = await loadCurrentUser();

    if (!authenticated) {
        showLogin();
        if (loginUsername) loginUsername.focus();
    } else {
        check();
    }
})();

/* ========================================================
   MARKDOWN / HTML ESCAPING
======================================================== */

const HTML_ESCAPES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
};

function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

function md(s) {
    s = esc(s);

    /* Pull code blocks out first so their line breaks are kept as-is. */
    const blocks = [];

    s = s.replace(/```([\s\S]*?)```/g, (_, code) => {
        blocks.push("<pre><code>" + code.replace(/^\n/, "") + "</code></pre>");
        return "\u0000" + (blocks.length - 1) + "\u0000";
    });

    s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/\n/g, "<br>");

    s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => blocks[Number(i)]);

    return s;
}

/* ========================================================
   MESSAGES
======================================================== */

function add(role, text, sources = []) {
    document.getElementById("welcome")?.remove();

    const d = document.createElement("div");
    d.className = "msg " + role;

    let ttsButton = "";

    if (role === "assistant") {
        ttsButton = `
            <button
                class="tts-button"
                type="button"
                onclick="playTTS(this)"
                data-text="${encodeURIComponent(text)}">
                🔊
            </button>
        `;
    }

    d.innerHTML = `
        <div class="avatar">${role === "user" ? "You" : "AI"}</div>

        <div class="bubble">
            ${md(text)}
            <div class="message-actions">${ttsButton}</div>
        </div>
    `;

    if (chatEl) {
        chatEl.appendChild(d);
        chatEl.scrollTop = chatEl.scrollHeight;
    }
}

function typing() {
    document.getElementById("welcome")?.remove();

    const d = document.createElement("div");
    d.className = "msg assistant";
    d.id = "typing";

    d.innerHTML = `
        <div class="avatar">AI</div>
        <div class="bubble typing">Thinking...</div>
    `;

    if (chatEl) {
        chatEl.appendChild(d);
        chatEl.scrollTop = chatEl.scrollHeight;
    }
}

/* ========================================================
   ATTACHMENTS
======================================================== */

function render() {
    if (!chips) return;

    chips.innerHTML = attachments
        .map(
            (x, i) => `
                <div class="chip">
                    ${esc(x.filename)}
                    <button type="button" onclick="removeA(${i})">×</button>
                </div>
            `
        )
        .join("");
}

window.removeA = function (i) {
    attachments.splice(i, 1);
    render();
};

if (attach && input) {
    attach.onclick = () => input.click();
}

if (input) {
    input.onchange = async () => {
        for (const file of input.files) {
            try {
                const form = new FormData();
                form.append("file", file);

                const response = await authenticatedFetch("/api/upload", {
                    method: "POST",
                    body: form
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.detail || "Upload failed.");
                }

                attachments.push(data);
                render();

            } catch (error) {
                add("assistant", "Upload error: " + error.message);
            }
        }

        input.value = "";
    };
}

/* ========================================================
   CHAT
======================================================== */

async function sendMessage() {
    const text = msgEl ? msgEl.value.trim() : "";

    if (!text) return;

    add("user", text);

    /* History sent to the server excludes the current message. */
    const old = history.slice();

    history.push({ role: "user", content: text });

    if (msgEl) {
        msgEl.value = "";
        msgEl.style.height = "auto";
    }

    typing();

    if (send) send.disabled = true;

    try {
        const response = await authenticatedFetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: text,
                history: old,
                file_ids: attachments.map((x) => x.file_id),
                use_web: true
            })
        });

        const data = await response.json();

        document.getElementById("typing")?.remove();

        if (!response.ok) {
            throw new Error(data.detail || "Chat failed.");
        }

        add("assistant", data.answer);

        history.push({ role: "assistant", content: data.answer });

    } catch (error) {
        document.getElementById("typing")?.remove();

        add("assistant", "Error: " + error.message);

        /* Remove the failed user message from history. */
        if (history.length > 0 && history[history.length - 1].role === "user") {
            history.pop();
        }

    } finally {
        if (send) send.disabled = false;
        if (msgEl) msgEl.focus();
    }
}

if (send) {
    send.onclick = sendMessage;
}

if (msgEl) {
    msgEl.onkeydown = (event) => {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            sendMessage();
        }
    };

    msgEl.oninput = () => {
        msgEl.style.height = "auto";
        msgEl.style.height = Math.min(msgEl.scrollHeight, 180) + "px";
    };
}

if (newChat) {
    newChat.onclick = () => {
        history = [];
        attachments = [];
        render();

        if (chatEl) chatEl.innerHTML = WELCOME_HTML;
    };
}

/* ========================================================
   MICROPHONE
======================================================== */

async function startMic() {
    if (!navigator.mediaDevices) {
        throw new Error("Microphone access is not supported by this browser.");
    }

    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

    recorder = new MediaRecorder(stream, { mimeType: "audio/webm" });

    chunks = [];

    recorder.ondataavailable = (event) => {
        if (event.data.size) chunks.push(event.data);
    };

    recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());

        if (mic) {
            mic.classList.remove("recording");
            mic.textContent = "🎤";
        }

        const form = new FormData();

        form.append(
            "file",
            new Blob(chunks, { type: "audio/webm" }),
            "microphone.webm"
        );

        try {
            if (mic) mic.disabled = true;

            const response = await authenticatedFetch("/api/transcribe", {
                method: "POST",
                body: form
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Transcription failed.");
            }

            if (msgEl) {
                msgEl.value = data.text || "";
                msgEl.dispatchEvent(new Event("input"));
            }

            if (data.text && data.text.trim()) {
                await sendMessage();
            }

        } catch (error) {
            add("assistant", "Microphone error: " + error.message);

        } finally {
            if (mic) mic.disabled = false;
        }
    };

    recorder.start();

    if (mic) {
        mic.classList.add("recording");
        mic.textContent = "■";
    }
}

if (mic) {
    mic.onclick = () => {
        if (recorder && recorder.state === "recording") {
            recorder.stop();
        } else {
            startMic().catch((error) =>
                add("assistant", "Microphone error: " + error.message)
            );
        }
    };
}

/* ========================================================
   TEXT TO SPEECH
======================================================== */

async function playTTS(button) {
    const text = decodeURIComponent(button.dataset.text);

    try {
        button.disabled = true;
        button.textContent = "⏳";

        const response = await authenticatedFetch("/api/tts", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: text })
        });

        if (!response.ok) {
            let errorData = {};

            try {
                errorData = await response.json();
            } catch (error) {
                errorData = {};
            }

            throw new Error(errorData.detail || "TTS failed.");
        }

        const audioBlob = await response.blob();
        const audioURL = URL.createObjectURL(audioBlob);
        const audio = new Audio(audioURL);

        button.textContent = "🔊";

        audio.onended = () => {
            URL.revokeObjectURL(audioURL);
            button.disabled = false;
        };

        audio.onerror = () => {
            URL.revokeObjectURL(audioURL);
            button.disabled = false;
            button.textContent = "🔊";
        };

        await audio.play();

    } catch (error) {
        console.error("TTS error:", error);

        button.textContent = "🔊";
        button.disabled = false;

        alert("TTS error: " + error.message);
    }
}

/* ========================================================
   HEALTH CHECK
======================================================== */

async function check() {
    if (!health) return;

    try {
        const response = await fetch("/api/health");
        const data = await response.json();

        health.textContent =
            data.ollama && data.model_found
                ? "● Ollama ready"
                : "● " + (data.detail || "Model not ready");

    } catch (error) {
        health.textContent = "● Backend unavailable";
    }
}

check();