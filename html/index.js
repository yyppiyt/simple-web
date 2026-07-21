let currentUser = null;

const elements = {
    echoButton: document.getElementById("echo-button"),
    helloButton: document.getElementById("hello-button"),
    logoutButton: document.getElementById("logout-button"),
    message: document.getElementById("message"),
    messageForm: document.getElementById("message-form"),
    messageList: document.getElementById("message-list"),
    messagePanel: document.getElementById("message-panel"),
    messageStatus: document.getElementById("message-status"),
    refreshButton: document.getElementById("refresh-button"),
    result: document.getElementById("result"),
    result2: document.getElementById("result2"),
    userStatus: document.getElementById("user-status"),
};

function setStatus(element, message, type = "") {
    element.textContent = message;
    element.className = type ? `status ${type}` : "status";
}

function authHeaders(headers = {}) {
    return SimpleWebSession.authHeaders(headers);
}

async function apiJson(url, options = {}) {
    try {
        return await SimpleWebSession.apiJson(url, options);
    } catch (err) {
        if (err.status === 401) {
            SimpleWebSession.clear();
            SimpleWebSession.goToLogin();
        }

        throw err;
    }
}

async function logout() {
    try {
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: authHeaders(),
        });
    } catch (err) {
        console.warn("Logout request failed", err);
    } finally {
        SimpleWebSession.clear();
        SimpleWebSession.goToLogin();
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
    const messages = await apiJson("/api/messages", {
        headers: authHeaders(),
    });
    renderMessages(messages);
}

async function addMessage() {
    const message = elements.message.value.trim();

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

async function initializePage() {
    const { error, redirecting, session } = await SimpleWebSession.routePage();

    if (redirecting || !session) {
        return;
    }

    if (error) {
        SimpleWebSession.goToLogin();
        return;
    }

    currentUser = session.user;
    SimpleWebSession.renderUserBadge(elements.userStatus, currentUser);
    await loadMessages();
}

async function callApi() {
    const data = await apiJson("/api/hello", {
        headers: authHeaders(),
    });
    elements.result.textContent = JSON.stringify(data, null, 2);
}

async function callEcho() {
    const data = await apiJson("/api/echo", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
            name: currentUser?.username || "Tom",
            message: "Hello",
        }),
    });
    elements.result2.textContent = JSON.stringify(data, null, 2);
}

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

initializePage().catch((err) => {
    console.warn("Page initialization failed", err);
    elements.messageList.textContent = err.message;
});
