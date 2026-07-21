(function () {
    "use strict";

    const tokenKey = "simple-web-auth-token";
    const authPaths = new Set([
        "/login",
        "/login.html",
        "/register",
        "/register.html",
        "/verify-2fa",
        "/verify-2fa.html",
    ]);

    function normalizedPath() {
        return globalThis.location.pathname.replace(/\/+$/, "") || "/";
    }

    function isAuthPage() {
        return authPaths.has(normalizedPath());
    }

    function getToken() {
        return localStorage.getItem(tokenKey) || "";
    }

    function setSession(data) {
        if (!data?.token || !data?.user) {
            throw new Error("Invalid login response");
        }

        localStorage.setItem(tokenKey, data.token);
    }

    function clearSession() {
        localStorage.removeItem(tokenKey);
    }

    function authHeaders(headers = {}) {
        const token = getToken();

        return token
            ? { ...headers, Authorization: `Bearer ${token}` }
            : headers;
    }

    async function parseResponse(response) {
        const text = await response.text();
        let data = null;

        try {
            data = text ? JSON.parse(text) : null;
        } catch (_err) {
            const contentType = response.headers?.get?.("content-type") || "";
            const isHtml = contentType.includes("text/html")
                || /^\s*(?:<!doctype\s+html|<html\b)/i.test(text);

            data = {
                error: isHtml
                    ? `Server endpoint unavailable (${response.status}). Please update the API and try again.`
                    : text || response.statusText,
            };
        }

        if (!response.ok) {
            const error = new Error(data?.error || `Request failed (${response.status})`);
            error.status = response.status;
            throw error;
        }

        return data;
    }

    async function apiJson(url, options = {}) {
        const response = await fetch(url, options);
        return parseResponse(response);
    }

    async function verifySession() {
        const token = getToken();

        if (!token) {
            return null;
        }

        try {
            const data = await apiJson("/api/auth/me", {
                cache: "no-store",
                headers: authHeaders(),
            });

            return {
                token,
                user: data.user,
            };
        } catch (err) {
            if (err.status === 401) {
                clearSession();
                return null;
            }

            throw err;
        }
    }

    function revealPage() {
        document.documentElement.classList.remove("auth-pending");
    }

    function goToIndex() {
        globalThis.location.replace("/");
    }

    function goToLogin() {
        globalThis.location.replace("/login");
    }

    function renderUserBadge(element, user) {
        element.replaceChildren();
        element.className = "user-badge";

        const avatar = user?.avatar_data
            ? document.createElement("img")
            : document.createElement("span");
        avatar.className = "user-avatar";

        if (user?.avatar_data) {
            avatar.src = user.avatar_data;
            avatar.alt = "";
        } else {
            avatar.textContent = (user?.username || "?").slice(0, 1).toUpperCase();
            avatar.setAttribute("aria-hidden", "true");
        }

        const username = document.createElement("span");
        username.textContent = user?.username || "User";
        element.append(avatar, username);
    }

    async function routePage() {
        const authPage = isAuthPage();
        let session = null;

        try {
            session = await verifySession();
        } catch (error) {
            if (authPage) {
                revealPage();
                return { error, redirecting: false, session: null };
            }

            goToLogin();
            return { error, redirecting: true, session: null };
        }

        if (session && authPage) {
            goToIndex();
            return { error: null, redirecting: true, session };
        }

        if (!session && !authPage) {
            goToLogin();
            return { error: null, redirecting: true, session: null };
        }

        revealPage();
        return { error: null, redirecting: false, session };
    }

    globalThis.SimpleWebSession = {
        apiJson,
        authHeaders,
        clear: clearSession,
        goToIndex,
        goToLogin,
        renderUserBadge,
        routePage,
        set: setSession,
    };
})();
