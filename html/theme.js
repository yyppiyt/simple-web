(function () {
    "use strict";

    const storageKey = "simple-web-theme";
    const root = document.documentElement;

    function normalizeTheme(theme) {
        return theme === "light" ? "light" : "dark";
    }

    function readStoredTheme() {
        try {
            return localStorage.getItem(storageKey);
        } catch (_err) {
            return null;
        }
    }

    function storeTheme(theme) {
        try {
            localStorage.setItem(storageKey, theme);
        } catch (_err) {
            // The selected theme still applies for the current page.
        }
    }

    function syncToggles(theme) {
        const darkMode = theme === "dark";

        document.querySelectorAll("[data-theme-toggle]").forEach((toggle) => {
            toggle.setAttribute("aria-checked", String(darkMode));
            toggle.title = darkMode
                ? "Switch to light mode"
                : "Switch to dark mode";
        });
    }

    function applyTheme(theme, persist = false) {
        const nextTheme = normalizeTheme(theme);
        root.dataset.theme = nextTheme;
        document.querySelector('meta[name="theme-color"]')?.setAttribute(
            "content",
            nextTheme === "dark" ? "#071426" : "#F4F7FB"
        );
        syncToggles(nextTheme);

        if (persist) {
            storeTheme(nextTheme);
        }
    }

    function bindToggles() {
        syncToggles(root.dataset.theme);

        document.querySelectorAll("[data-theme-toggle]").forEach((toggle) => {
            toggle.addEventListener("click", () => {
                const nextTheme = root.dataset.theme === "dark"
                    ? "light"
                    : "dark";

                applyTheme(nextTheme, true);
            });
        });
    }

    applyTheme(readStoredTheme());

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bindToggles, { once: true });
    } else {
        bindToggles();
    }

    globalThis.addEventListener("storage", (event) => {
        if (event.key === storageKey) {
            applyTheme(event.newValue);
        }
    });
})();
