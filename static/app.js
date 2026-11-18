
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
const modelSelect = document.getElementById("modelSelect");

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

let refreshPromise = null;
let isLoggingOut = false;

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

    if (chatEl) {
        chatEl.innerHTML = WELCOME_HTML;
    }
}

function authHeaders(extra = {}) {
    const headers = { ...extra };
    const token = getToken();

    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    return headers;
}

/* ========================================================
   AUTOMATIC TOKEN REFRESH

   Requires backend:
   POST /api/auth/refresh

   Backend must:
   1. Read HttpOnly refresh-token cookie.
   2. Validate the refresh token.
   3. Return a new access_token.
   4. Rotate the refresh token when appropriate.
======================================================== */

async function refreshAccessToken() {

    // Prevent multiple simultaneous refresh requests.
    if (refreshPromise) {
        return refreshPromise;
    }

    refreshPromise = (async () => {

        try {

            const response = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (!response.ok) {
                return false;
            }

            const data = await response.json();

            if (!data.access_token) {
                return false;
            }

            localStorage.setItem(
                "access_token",
                data.access_token
            );

            console.log("Access token refreshed successfully.");

            return true;

        } catch (error) {

            console.error("Token refresh failed:", error);

            return false;

        } finally {

            refreshPromise = null;

        }

    })();

    return refreshPromise;
}

/* ========================================================
   AUTHENTICATED API REQUEST

   Automatically refreshes expired access tokens
   and retries the original request once.
======================================================== */

async function authenticatedFetch(url, options = {}) {

    if (isLoggingOut) {
        throw new Error("You have been logged out.");
    }

    if (!getToken()) {

        const refreshed = await refreshAccessToken();

        if (!refreshed) {
            clearAuth();
            throw new Error("Session expired. Please login again.");
        }
    }

    const makeRequest = () => {

        const headers = authHeaders(options.headers || {});

        return fetch(url, {
            ...options,
            headers,
            credentials: "same-origin"
        });

    };

    let response = await makeRequest();

    // First 401: attempt automatic refresh.
    if (response.status === 401) {

        const refreshed = await refreshAccessToken();

        if (!refreshed) {

            clearAuth();

            throw new Error(
                "Your session has expired. Please login again."
            );
        }

        // Retry original request only once.
        response = await makeRequest();

        if (response.status === 401) {

            clearAuth();

            throw new Error(
                "Authentication failed after token renewal. Please login again."
            );
        }
    }

    return response;
}

/* ========================================================
   LOGIN
======================================================== */

async function login(username, password) {

    const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username,
            password
        })
    });

    let data = {};

    try {
        data = await response.json();
    } catch (error) {
        data = {};
    }

    if (!response.ok) {
        throw new Error(
            data.detail || "Invalid User ID or password."
        );
    }

    if (!data.access_token) {
        throw new Error(
            "Login succeeded but no access token was returned."
        );
    }

    localStorage.setItem(
        "access_token",
        data.access_token
    );

    return data;
}

/* ========================================================
   LOAD CURRENT USER
======================================================== */

async function loadCurrentUser() {

    try {

        // If access token is missing, try refreshing first.
        if (!getToken()) {

            const refreshed = await refreshAccessToken();

            if (!refreshed) {
                return false;
            }
        }

        const response = await authenticatedFetch(
            "/api/auth/me",
            {
                method: "GET"
            }
        );

        if (!response.ok) {
            return false;
        }

        const user = await response.json();

        localStorage.setItem(
            "user",
            JSON.stringify(user)
        );

        if (currentUser) {
            currentUser.textContent =
                `${user.username} (${user.role})`;
        }

        showChat();

        await loadAvailableModels();

        return true;

    } catch (error) {

        console.error(
            "Authentication check failed:",
            error
        );

        return false;
    }
}

/* ========================================================
   LOGIN FORM EVENT
======================================================== */

if (loginForm) {

    loginForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        if (loginError) {
            loginError.textContent = "";
        }

        const username = loginUsername
            ? loginUsername.value.trim()
            : "";

        const password = loginPassword
            ? loginPassword.value
            : "";

        if (!username || !password) {

            if (loginError) {
                loginError.textContent =
                    "User ID and password are required.";
            }

            return;
        }

        const originalLabel = loginButton
            ? loginButton.textContent
            : "";

        if (loginButton) {
            loginButton.disabled = true;
            loginButton.textContent = "Signing in...";
        }

        isLoggingOut = false;

        try {

            await login(username, password);

            const authenticated = await loadCurrentUser();

            if (!authenticated) {
                throw new Error("Authentication failed.");
            }

            if (loginPassword) {
                loginPassword.value = "";
            }

            check();

        } catch (error) {

            console.error("Login error:", error);

            localStorage.removeItem("access_token");
            localStorage.removeItem("user");

            if (loginError) {
                loginError.textContent =
                    error.message || "Login failed.";
            }

        } finally {

            if (loginButton) {
                loginButton.disabled = false;
                loginButton.textContent = originalLabel;
            }
        }
    });
}

/* ========================================================
   LOGOUT
======================================================== */

if (logoutButton) {

    logoutButton.addEventListener("click", async () => {

        isLoggingOut = true;

        try {

            // Optional backend logout endpoint.
            // It should revoke the refresh token and clear its cookie.

            await fetch("/api/auth/logout", {
                method: "POST",
                credentials: "same-origin"
            });

        } catch (error) {

            console.error("Logout request failed:", error);

        } finally {

            clearAuth();

            if (loginUsername) {
                loginUsername.focus();
            }

            isLoggingOut = false;
        }
    });
}

/* ========================================================
   INITIALIZE AUTHENTICATION
======================================================== */

(async function initializeAuthentication() {

    if (!loginScreen || !chatApp) {

        console.error(
            "index.html is missing #loginScreen or #chatApp."
        );
    }

    showLogin();

    const authenticated = await loadCurrentUser();

    if (!authenticated) {

        clearAuth();

        showLogin();

        if (loginUsername) {
            loginUsername.focus();
        }

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

    return String(s).replace(
        /[&<>"']/g,
        (c) => HTML_ESCAPES[c]
    );
}

function md(s) {

    s = esc(s);

    const blocks = [];

    s = s.replace(/```([\s\S]*?)```/g, (_, code) => {

        blocks.push(
            "<pre><code>" +
            code.replace(/^\n/, "") +
            "</code></pre>"
        );

        return "\u0000" + (blocks.length - 1) + "\u0000";
    });

    s = s.replace(
        /`([^`\n]+)`/g,
        "<code>$1</code>"
    );

    s = s.replace(
        /\*\*([^*]+)\*\*/g,
        "<strong>$1</strong>"
    );

    s = s.replace(/\n/g, "<br>");

    s = s.replace(
        /\u0000(\d+)\u0000/g,
        (_, i) => blocks[Number(i)]
    );

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
        <div class="avatar">
            ${role === "user" ? "You" : "AI"}
        </div>

        <div class="bubble">
            ${md(text)}
            <div class="message-actions">
                ${ttsButton}
            </div>
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
                    <button
                        type="button"
                        onclick="removeA(${i})">
                        ×
                    </button>
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

                const response = await authenticatedFetch(
                    "/api/upload",
                    {
                        method: "POST",
                        body: form
                    }
                );

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(
                        data.detail || "Upload failed."
                    );
                }

                attachments.push(data);

                render();

            } catch (error) {

                add(
                    "assistant",
                    "Upload error: " + error.message
                );
            }
        }

        input.value = "";
    };
}

/* ========================================================
   MODEL SELECTOR
======================================================== */

async function loadAvailableModels() {

    if (!modelSelect || !getToken()) return;

    try {

        const response = await authenticatedFetch(
            "/api/models"
        );

        if (!response.ok) {
            throw new Error("Could not load model list.");
        }

        const data = await response.json();

        if (
            !Array.isArray(data.models) ||
            data.models.length === 0
        ) {
            return;
        }

        const previousSelection = modelSelect.value;

        modelSelect.replaceChildren();

        for (const model of data.models) {

            const option = document.createElement("option");

            option.value = model.id;
            option.textContent = model.label;
            option.title = model.description || "";

            modelSelect.appendChild(option);
        }

        const validPrevious = data.models.some(
            (model) => model.id === previousSelection
        );

        modelSelect.value = validPrevious
            ? previousSelection
            : (data.default_model || data.models[0].id);

    } catch (error) {

        console.error(
            "Model list could not be loaded:",
            error
        );
    }
}

/* ========================================================
   CHAT
======================================================== */

async function sendMessage() {

    const text = msgEl
        ? msgEl.value.trim()
        : "";

    if (!text) return;

    add("user", text);

    // Preserve the previous conversation history.
    const old = history.slice();

    history.push({
        role: "user",
        content: text
    });

    if (msgEl) {

        msgEl.value = "";
        msgEl.style.height = "auto";
    }

    typing();

    if (send) {
        send.disabled = true;
    }

    try {

        const response = await authenticatedFetch(
            "/api/chat",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({

                    message: text,

                    history: old,

                    file_ids: attachments.map(
                        (x) => x.file_id
                    ),

                    use_web: true,

                    model: modelSelect
                        ? modelSelect.value
                        : "qwen-ollama"

                })
            }
        );

        const data = await response.json();

        document.getElementById("typing")?.remove();

        if (!response.ok) {

            throw new Error(
                data.detail || "Chat failed."
            );
        }

        add("assistant", data.answer);

        history.push({
            role: "assistant",
            content: data.answer
        });

        // Clear uploaded file selections after successful submission.
        attachments = [];

        render();

    } catch (error) {

        document.getElementById("typing")?.remove();

        add(
            "assistant",
            "Error: " + error.message
        );

        // Remove failed user message from history.
        if (
            history.length > 0 &&
            history[history.length - 1].role === "user"
        ) {
            history.pop();
        }

    } finally {

        if (send) {
            send.disabled = false;
        }

        if (msgEl) {
            msgEl.focus();
        }
    }
}

if (send) {

    send.onclick = sendMessage;
}

if (msgEl) {

    msgEl.onkeydown = (event) => {

        if (
            event.key === "Enter" &&
            !event.shiftKey
        ) {

            event.preventDefault();

            sendMessage();
        }
    };

    msgEl.oninput = () => {

        msgEl.style.height = "auto";

        msgEl.style.height =
            Math.min(msgEl.scrollHeight, 180) + "px";
    };
}

/* ========================================================
   NEW CHAT
======================================================== */

if (newChat) {

    newChat.onclick = () => {

        history = [];

        attachments = [];

        render();

        if (chatEl) {
            chatEl.innerHTML = WELCOME_HTML;
        }
    };
}

/* ========================================================
   MICROPHONE
======================================================== */

async function startMic() {

    if (!navigator.mediaDevices) {

        throw new Error(
            "Microphone access is not supported by this browser."
        );
    }

    const stream =
        await navigator.mediaDevices.getUserMedia({
            audio: true
        });

    const mimeType = MediaRecorder.isTypeSupported(
        "audio/webm"
    )
        ? "audio/webm"
        : "";

    recorder = mimeType
        ? new MediaRecorder(stream, { mimeType })
        : new MediaRecorder(stream);

    chunks = [];

    recorder.ondataavailable = (event) => {

        if (event.data.size) {
            chunks.push(event.data);
        }
    };

    recorder.onstop = async () => {

        stream.getTracks().forEach(
            (track) => track.stop()
        );

        if (mic) {

            mic.classList.remove("recording");

            mic.textContent = "🎤";
        }

        const form = new FormData();

        const actualMimeType =
            recorder.mimeType || "audio/webm";

        form.append(
            "file",
            new Blob(chunks, {
                type: actualMimeType
            }),
            "microphone.webm"
        );

        try {

            if (mic) {
                mic.disabled = true;
            }

            const response = await authenticatedFetch(
                "/api/transcribe",
                {
                    method: "POST",
                    body: form
                }
            );

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.detail || "Transcription failed."
                );
            }

            if (msgEl) {

                msgEl.value = data.text || "";

                msgEl.dispatchEvent(
                    new Event("input")
                );
            }

            if (data.text && data.text.trim()) {

                await sendMessage();
            }

        } catch (error) {

            add(
                "assistant",
                "Microphone error: " + error.message
            );

        } finally {

            if (mic) {
                mic.disabled = false;
            }
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

        if (
            recorder &&
            recorder.state === "recording"
        ) {

            recorder.stop();

        } else {

            startMic().catch((error) => {

                add(
                    "assistant",
                    "Microphone error: " + error.message
                );
            });
        }
    };
}

/* ========================================================
   TEXT TO SPEECH
======================================================== */

async function playTTS(button) {

    const text = decodeURIComponent(
        button.dataset.text
    );

    let audioURL = null;

    try {

        button.disabled = true;

        button.textContent = "⏳";

        const response = await authenticatedFetch(
            "/api/tts",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    text
                })
            }
        );

        if (!response.ok) {

            let errorData = {};

            try {
                errorData = await response.json();
            } catch (error) {
                errorData = {};
            }

            throw new Error(
                errorData.detail || "TTS failed."
            );
        }

        const audioBlob = await response.blob();

        audioURL = URL.createObjectURL(audioBlob);

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

        if (audioURL) {
            URL.revokeObjectURL(audioURL);
        }

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

        if (!response.ok) {

            health.textContent = "";

            return;
        }

        const data = await response.json();

        health.textContent =
            data.ollama && data.model_found
                ? "● User Preferred Model"
                : "User Preferred Model";

    } catch (error) {

        health.textContent = "";
    }
}
