const elements = {
    authForm: document.getElementById("auth-form"),
    authStatus: document.getElementById("auth-status"),
    loginButton: document.getElementById("login-button"),
    password: document.getElementById("password"),
    registerButton: document.getElementById("register-button"),
    username: document.getElementById("username"),
};

function setStatus(message, type = "") {
    elements.authStatus.textContent = message;
    elements.authStatus.className = type ? `status ${type}` : "status";
}

function setBusy(busy) {
    elements.loginButton.disabled = busy;
    elements.registerButton.disabled = busy;
    elements.username.disabled = busy;
    elements.password.disabled = busy;
}

function getAuthPayload() {
    return {
        username: elements.username.value.trim(),
        password: elements.password.value,
    };
}

async function authenticate(path, pendingMessage) {
    setBusy(true);
    setStatus(pendingMessage);

    try {
        const data = await SimpleWebSession.apiJson(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(getAuthPayload()),
        });

        SimpleWebSession.set(data);
        elements.password.value = "";
        SimpleWebSession.goToIndex();
    } catch (err) {
        setStatus(err.message, "error");
        setBusy(false);
    }
}

elements.authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await authenticate("/api/auth/login", "Logging in...");
});

elements.registerButton.addEventListener("click", async () => {
    if (!elements.authForm.reportValidity()) {
        return;
    }

    await authenticate("/api/auth/register", "Creating account...");
});

SimpleWebSession.routePage()
    .then(({ error, redirecting }) => {
        if (redirecting) {
            return;
        }

        if (error) {
            setStatus("Unable to verify the current session. You can try signing in.", "error");
        }

        if (!document.activeElement || document.activeElement === document.body) {
            elements.username.focus();
        }
    })
    .catch((err) => {
        document.documentElement.classList.remove("auth-pending");
        setStatus(err.message, "error");
    });
