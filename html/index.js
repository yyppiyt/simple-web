const tokenKey = "simple-web-auth-token";
let authToken = localStorage.getItem(tokenKey) || "";
let currentUser = null;

const elements = {
    authForm: document.getElementById("auth-form"),
    authPanel: document.getElementById("auth-panel"),
    authStatus: document.getElementById("auth-status"),
    echoButton: document.getElementById("echo-button"),
    helloButton: document.getElementById("hello-button"),
    logoutButton: document.getElementById("logout-button"),
    message: document.getElementById("message"),
    messageForm: document.getElementById("message-form"),
    messageList: document.getElementById("message-list"),
    messagePanel: document.getElementById("message-panel"),
    messageStatus: document.getElementById("message-status"),
    password: document.getElementById("password"),
    refreshButton: document.getElementById("refresh-button"),
    registerButton: document.getElementById("register-button"),
    result: document.getElementById("result"),
    result2: document.getElementById("result2"),
    userStatus: document.getElementById("user-status"),
    username: document.getElementById("username"),
};

function setStatus(element, message, type = "") {
    element.textContent = message;
    element.className = type ? `status ${type}` : "status";
}

function authHeaders(headers = {}) {
    return authToken
        ? { ...headers, Authorization: `Bearer ${authToken}` }
        : headers;
}

async function parseResponse(response) {
    const text = await response.text();
    let data = null;

    try {
        data = text ? JSON.parse(text) : null;
    } catch (err) {
        data = { error: text || response.statusText };
    }

    if (!response.ok) {
        throw new Error(data?.error || `Request failed (${response.status})`);
    }

    return data;
}

async function apiJson(url, options = {}) {
    const response = await fetch(url, options);
    return parseResponse(response);
}

function renderSession() {
    const loggedIn = Boolean(authToken && currentUser);

    elements.authPanel.hidden = loggedIn;
    elements.messagePanel.hidden = !loggedIn;
    elements.logoutButton.hidden = !loggedIn;
    elements.userStatus.textContent = loggedIn
        ? `Signed in as ${currentUser.username}`
        : "Not signed in";
}

function setAuth(data) {
    authToken = data.token;
    currentUser = data.user;
    localStorage.setItem(tokenKey, authToken);
    elements.password.value = "";
    renderSession();
}

function clearAuth() {
    authToken = "";
    currentUser = null;
    localStorage.removeItem(tokenKey);
    renderSession();
}

function getAuthPayload() {
    return {
        username: elements.username.value.trim(),
        password: elements.password.value,
    };
}

async function login() {
    setStatus(elements.authStatus, "Logging in...");

    const data = await apiJson("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(getAuthPayload()),
    });

    setAuth(data);
    setStatus(elements.messageStatus, "Logged in.", "success");
    await loadMessages();
}

async function register() {
    setStatus(elements.authStatus, "Creating account...");

    const data = await apiJson("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(getAuthPayload()),
    });

    setAuth(data);
    setStatus(elements.messageStatus, "Account created.", "success");
    await loadMessages();
}

async function logout() {
    try {
        if (authToken) {
            await fetch("/api/auth/logout", {
                method: "POST",
                headers: authHeaders(),
            });
        }
    } catch (err) {
        console.warn("Logout request failed", err);
    } finally {
        clearAuth();
        setStatus(elements.authStatus, "Logged out.", "success");
        setStatus(elements.messageStatus, "");
    }
}

function renderMessages(messages) {
    elements.messageList.replaceChildren();

    if (messages.length === 0) {
        const empty = document.createElement("li");
        empty.className = "empty";
        empty.textContent = "No messages yet.";
        elements.messageList.append(empty);
        return;
    }

    for (const item of messages) {
        const li = document.createElement("li");
        li.className = "message-item";

        const meta = document.createElement("div");
        meta.className = "message-meta";

        const name = document.createElement("strong");
        name.textContent = item.name;

        const time = document.createElement("span");
        time.textContent = new Date(item.created_at).toLocaleString();

        const text = document.createElement("p");
        text.className = "message-text";
        text.textContent = item.message;

        meta.append(name, time);
        li.append(meta, text);
        elements.messageList.append(li);
    }
}

async function loadMessages() {
    const messages = await apiJson("/api/messages");
    renderMessages(messages);
}

async function addMessage() {
    const message = elements.message.value.trim();

    if (!authToken) {
        setStatus(elements.authStatus, "Please login first.", "error");
        return;
    }

    if (!message) {
        setStatus(elements.messageStatus, "Message is required.", "error");
        return;
    }

    setStatus(elements.messageStatus, "Saving...");

    await apiJson("/api/messages", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ message }),
    });

    elements.message.value = "";
    setStatus(elements.messageStatus, "Message added.", "success");
    await loadMessages();
}

async function restoreSession() {
    if (!authToken) {
        renderSession();
        await loadMessages();
        return;
    }

    try {
        const data = await apiJson("/api/auth/me", {
            headers: authHeaders(),
        });
        currentUser = data.user;
        renderSession();
    } catch (err) {
        clearAuth();
        setStatus(elements.authStatus, "Session expired. Please login again.", "error");
    }

    await loadMessages();
}

async function callApi() {
    const data = await apiJson("/api/hello");
    elements.result.textContent = JSON.stringify(data, null, 2);
}

async function callEcho() {
    const data = await apiJson("/api/echo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            name: currentUser?.username || "Tom",
            message: "Hello",
        }),
    });
    elements.result2.textContent = JSON.stringify(data, null, 2);
}

elements.authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
        await login();
    } catch (err) {
        setStatus(elements.authStatus, err.message, "error");
    }
});

elements.registerButton.addEventListener("click", async () => {
    if (!elements.authForm.reportValidity()) {
        return;
    }

    try {
        await register();
    } catch (err) {
        setStatus(elements.authStatus, err.message, "error");
    }
});

elements.logoutButton.addEventListener("click", logout);

elements.messageForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
        await addMessage();
    } catch (err) {
        setStatus(elements.messageStatus, err.message, "error");
    }
});

elements.refreshButton.addEventListener("click", async () => {
    try {
        await loadMessages();
        setStatus(elements.messageStatus, "Messages refreshed.", "success");
    } catch (err) {
        setStatus(elements.messageStatus, err.message, "error");
    }
});

elements.helloButton.addEventListener("click", async () => {
    try {
        await callApi();
    } catch (err) {
        elements.result.textContent = err.message;
    }
});

elements.echoButton.addEventListener("click", async () => {
    try {
        await callEcho();
    } catch (err) {
        elements.result2.textContent = err.message;
    }
});

restoreSession().catch((err) => {
    elements.messageList.textContent = err.message;
});