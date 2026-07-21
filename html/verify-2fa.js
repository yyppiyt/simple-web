const challengeKey = "simple-web-2fa-challenge";
const challenge = sessionStorage.getItem(challengeKey) || "";
const form = document.getElementById("verify-form");
const code = document.getElementById("code");
const button = document.getElementById("verify-button");
const status = document.getElementById("verify-status");

function setStatus(message, type = "") {
    status.textContent = message;
    status.className = type ? `status ${type}` : "status";
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    button.disabled = true;
    code.disabled = true;
    setStatus("Verifying...");
    try {
        const data = await SimpleWebSession.apiJson("/api/auth/2fa/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ challengeToken: challenge, code: code.value }),
        });
        sessionStorage.removeItem(challengeKey);
        SimpleWebSession.set(data);
        SimpleWebSession.goToIndex();
    } catch (err) {
        setStatus(err.message, "error");
        button.disabled = false;
        code.disabled = false;
        code.select();
    }
});

SimpleWebSession.routePage().then(({ redirecting }) => {
    if (redirecting) return;
    if (!challenge) {
        setStatus("Your verification request is missing. Please log in again.", "error");
        button.disabled = true;
        return;
    }
    code.focus();
});
