const tokenKey = "simple-web-auth-token";
let authToken = localStorage.getItem(tokenKey) || "";
let currentUser = null;

const elements = {
    result: document.getElementById("result"),
};

function authHeaders(headers = {}) {
    return authToken
        ? { ...headers, Authorization: `Bearer ${authToken}` }
        : headers;
}

function renderSession() {
    const loggedIn = Boolean(authToken && currentUser);

    elements.result.textContent = loggedIn
        ? `Signed in as ${currentUser.username}`
        : "Not signed in";
}

function clearAuth() {
    authToken = "";
    currentUser = null;
    localStorage.removeItem(tokenKey);
    renderSession();
}

async function apiJson(url, options = {}) {
    const response = await fetch(url, options);
    return parseResponse(response);
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

async function restoreSession() {
    if (!authToken) {
        renderSession();
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
    }
}

restoreSession().catch((err) => {
    console.warn(err.message);
});