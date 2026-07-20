(function () {
    "use strict";

    const tokenKey = "simple-web-auth-token";
    const indexPaths = new Set(["/", "/index", "/index.html"]);
    const loginPaths = new Set(["/login", "/login.html"]);

    function normalizedPath() {
        return globalThis.location.pathname.replace(/\/+$/, "") || "/";
    }

    function pageType() {
        const path = normalizedPath();

        if (indexPaths.has(path)) {
            return "index";
        }

        if (loginPaths.has(path)) {
            return "login";
        }

        return "other";
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
            data = { error: text || response.statusText };
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

    async function routePage() {
        const type = pageType();
        let session = null;

        try {
            session = await verifySession();
        } catch (error) {
            if (type === "login") {
                revealPage();
                return { error, redirecting: false, session: null };
            }

            goToLogin();
            return { error, redirecting: true, session: null };
        }

        if (session && type !== "index") {
            goToIndex();
            return { error: null, redirecting: true, session };
        }

        if (!session && type !== "login") {
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
        routePage,
        set: setSession,
    };
})();
