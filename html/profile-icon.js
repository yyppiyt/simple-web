let currentUser = null;
let pendingAvatar = "";

const elements = {
    file: document.getElementById("avatar-file"),
    form: document.getElementById("avatar-form"),
    logout: document.getElementById("logout-button"),
    preview: document.getElementById("avatar-preview"),
    remove: document.getElementById("remove-button"),
    save: document.getElementById("save-button"),
    status: document.getElementById("avatar-status"),
    userStatus: document.getElementById("user-status"),
};

function setStatus(message, type = "") {
    elements.status.textContent = message;
    elements.status.className = type ? `status ${type}` : "status";
}

function showPreview(data) {
    elements.preview.replaceChildren();
    elements.preview.style.backgroundImage = data ? `url(${data})` : "";
    elements.preview.style.backgroundSize = "cover";
    elements.preview.style.backgroundPosition = "center";
    if (!data) elements.preview.textContent = (currentUser?.username || "?")[0].toUpperCase();
}

function resizeImage(file) {
    return new Promise((resolve, reject) => {
        const image = new Image();
        const objectUrl = URL.createObjectURL(file);
        image.onload = () => {
            const canvas = document.createElement("canvas");
            canvas.width = 256;
            canvas.height = 256;
            const context = canvas.getContext("2d");
            const side = Math.min(image.naturalWidth, image.naturalHeight);
            const sx = (image.naturalWidth - side) / 2;
            const sy = (image.naturalHeight - side) / 2;
            context.drawImage(image, sx, sy, side, side, 0, 0, 256, 256);
            URL.revokeObjectURL(objectUrl);
            resolve(canvas.toDataURL("image/webp", 0.86));
        };
        image.onerror = () => {
            URL.revokeObjectURL(objectUrl);
            reject(new Error("The selected image could not be opened."));
        };
        image.src = objectUrl;
    });
}

elements.file.addEventListener("change", async () => {
    const file = elements.file.files[0];
    pendingAvatar = "";
    elements.save.disabled = true;
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
        setStatus("Please choose an image smaller than 10 MB.", "error");
        return;
    }
    try {
        pendingAvatar = await resizeImage(file);
        showPreview(pendingAvatar);
        elements.save.disabled = false;
        setStatus("Preview ready. Select Save icon to apply it.");
    } catch (err) {
        setStatus(err.message, "error");
    }
});

elements.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!pendingAvatar) return;
    elements.save.disabled = true;
    setStatus("Saving...");
    try {
        const data = await SimpleWebSession.apiJson("/api/auth/avatar", {
            method: "PUT",
            headers: SimpleWebSession.authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ avatarData: pendingAvatar }),
        });
        currentUser.avatar_data = data.avatar_data;
        elements.remove.disabled = false;
        SimpleWebSession.renderUserBadge(elements.userStatus, currentUser);
        setStatus(data.message, "success");
    } catch (err) {
        elements.save.disabled = false;
        setStatus(err.message, "error");
    }
});

elements.remove.addEventListener("click", async () => {
    setStatus("Removing...");
    try {
        const data = await SimpleWebSession.apiJson("/api/auth/avatar", {
            method: "DELETE",
            headers: SimpleWebSession.authHeaders(),
        });
        currentUser.avatar_data = null;
        pendingAvatar = "";
        elements.file.value = "";
        elements.save.disabled = true;
        showPreview("");
        SimpleWebSession.renderUserBadge(elements.userStatus, currentUser);
        setStatus(data.message, "success");
    } catch (err) {
        setStatus(err.message, "error");
    }
});

elements.logout.addEventListener("click", async () => {
    try { await fetch("/api/auth/logout", { method: "POST", headers: SimpleWebSession.authHeaders() }); }
    finally { SimpleWebSession.clear(); SimpleWebSession.goToLogin(); }
});

SimpleWebSession.routePage().then(({ session, redirecting }) => {
    if (redirecting || !session) return;
    currentUser = session.user;
    showPreview(currentUser.avatar_data);
    SimpleWebSession.renderUserBadge(elements.userStatus, currentUser);
    elements.remove.disabled = !currentUser.avatar_data;
}).catch(() => SimpleWebSession.goToLogin());
