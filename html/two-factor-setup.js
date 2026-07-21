const el = {
    user: document.getElementById("user-status"), setup: document.getElementById("setup-content"),
    actions: document.getElementById("disabled-actions"), start: document.getElementById("start-setup"),
    qr: document.getElementById("qr-code"), seed: document.getElementById("seed"), copy: document.getElementById("copy-seed"),
    enableForm: document.getElementById("enable-form"), enableCode: document.getElementById("enable-code"),
    disableForm: document.getElementById("disable-form"), disableCode: document.getElementById("disable-code"),
    status: document.getElementById("two-factor-status"), title: document.getElementById("setup-title")
};
function status(message, type = "") { el.status.textContent = message; el.status.className = type ? `status ${type}` : "status"; }
async function api(path, code) { return SimpleWebSession.apiJson(path, { method: "POST", headers: SimpleWebSession.authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(code ? { code } : {}) }); }
el.start.addEventListener("click", async () => {
    el.start.disabled = true; status("Creating setup code...");
    try { const data = await api("/api/auth/2fa/setup"); el.qr.src = data.qr_code; el.seed.value = data.secret; el.setup.hidden = false; el.actions.hidden = true; status(""); el.enableCode.focus(); }
    catch (err) { status(err.message, "error"); el.start.disabled = false; }
});
el.copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(el.seed.value); status("Seed copied.", "success"); } catch (_) { status("Could not copy automatically. Select and copy the seed manually.", "error"); } });
el.enableForm.addEventListener("submit", async (event) => { event.preventDefault(); if (!el.enableForm.reportValidity()) return; try { const data = await api("/api/auth/2fa/enable", el.enableCode.value); status(data.message, "success"); el.setup.hidden = true; el.disableForm.hidden = false; el.title.textContent = "2FA is enabled"; } catch (err) { status(err.message, "error"); el.enableCode.select(); } });
el.disableForm.addEventListener("submit", async (event) => { event.preventDefault(); if (!el.disableForm.reportValidity()) return; try { const data = await api("/api/auth/2fa/disable", el.disableCode.value); status(data.message, "success"); el.disableForm.hidden = true; el.actions.hidden = false; el.start.disabled = false; el.title.textContent = "Set up 2FA"; } catch (err) { status(err.message, "error"); el.disableCode.select(); } });
SimpleWebSession.routePage().then(({ redirecting, session }) => { if (redirecting || !session) return; SimpleWebSession.renderUserBadge(el.user, session.user); if (session.user.two_factor_enabled) { el.title.textContent = "2FA is enabled"; el.actions.hidden = true; el.disableForm.hidden = false; el.disableCode.focus(); } else { el.start.focus(); } });
