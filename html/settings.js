let currentUser = null;
let formBusy = false;

const elements = {
    changePasswordButton: document.getElementById("change-password-button"),
    confirmPassword: document.getElementById("confirm-password"),
    confirmStatus: document.getElementById("confirm-status"),
    currentPassword: document.getElementById("current-password"),
    logoutButton: document.getElementById("logout-button"),
    newPassword: document.getElementById("new-password"),
    newPasswordLimit: document.getElementById("new-password-limit"),
    passwordForm: document.getElementById("password-form"),
    requirementsSummary: document.getElementById("requirements-summary"),
    passwordStatus: document.getElementById("password-status"),
    twoFactorSummary: document.getElementById("two-factor-summary"),
    userStatus: document.getElementById("user-status"),
};

const ruleElements = new Map(
    Array.from(document.querySelectorAll("[data-password-rule]"), (element) => [
        element.dataset.passwordRule,
        element,
    ])
);

function setStatus(message, type = "") {
    elements.passwordStatus.textContent = message;
    elements.passwordStatus.className = type ? `status ${type}` : "status";
}

function getPasswordRules(password) {
    return SimpleWebPasswordPolicy.evaluate(
        password,
        currentUser?.username || ""
    );
}

function updateRequirementList(rules) {
    let metCount = 0;

    for (const [ruleName, element] of ruleElements) {
        const met = Boolean(rules[ruleName]);
        const check = element.querySelector(".requirement-check");

        element.classList.toggle("met", met);
        check.setAttribute("aria-label", met ? "Met" : "Not met");
        metCount += met ? 1 : 0;
    }

    elements.requirementsSummary.textContent =
        `${metCount} of ${ruleElements.size} password requirements met.`;
}

function updateFormState() {
    const password = elements.newPassword.value;
    const confirmation = elements.confirmPassword.value;
    const rules = getPasswordRules(password);
    const requirementsMet = Object.values(rules).every(Boolean);
    const passwordsMatch = Boolean(confirmation) && confirmation === password;

    updateRequirementList(rules);

    if (rules.maximumLength) {
        elements.newPasswordLimit.textContent = "";
        elements.newPasswordLimit.className = "field-hint";
    } else {
        elements.newPasswordLimit.textContent =
            `Password must be no more than ${SimpleWebPasswordPolicy.maximumLength} characters.`;
        elements.newPasswordLimit.className = "field-hint error";
    }

    if (!confirmation) {
        elements.confirmStatus.textContent = "";
        elements.confirmStatus.className = "field-hint";
    } else if (passwordsMatch) {
        elements.confirmStatus.textContent = "Passwords match.";
        elements.confirmStatus.className = "field-hint success";
    } else {
        elements.confirmStatus.textContent = "Passwords do not match.";
        elements.confirmStatus.className = "field-hint error";
    }

    elements.changePasswordButton.disabled = formBusy
        || !elements.currentPassword.value
        || !requirementsMet
        || !passwordsMatch;

    return { passwordsMatch, requirementsMet };
}

function setBusy(busy) {
    formBusy = busy;
    elements.currentPassword.disabled = busy;
    elements.newPassword.disabled = busy;
    elements.confirmPassword.disabled = busy;
    updateFormState();
}

async function logout() {
    try {
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: SimpleWebSession.authHeaders(),
        });
    } catch (err) {
        console.warn("Logout request failed", err);
    } finally {
        SimpleWebSession.clear();
        SimpleWebSession.goToLogin();
    }
}

async function changePassword() {
    const validation = updateFormState();

    if (!validation.requirementsMet || !validation.passwordsMatch) {
        setStatus("Please meet every password requirement.", "error");
        return;
    }

    setBusy(true);
    setStatus("Changing password...");

    try {
        const data = await SimpleWebSession.apiJson("/api/auth/change-password", {
            method: "POST",
            headers: SimpleWebSession.authHeaders({
                "Content-Type": "application/json",
            }),
            body: JSON.stringify({
                currentPassword: elements.currentPassword.value,
                newPassword: elements.newPassword.value,
            }),
        });

        elements.passwordForm.reset();
        setStatus(data.message || "Password changed.", "success");
    } catch (err) {
        if (err.status === 401) {
            SimpleWebSession.clear();
            SimpleWebSession.goToLogin();
            return;
        }

        setStatus(err.message, "error");
    } finally {
        setBusy(false);
    }
}

elements.passwordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!elements.passwordForm.reportValidity()) {
        return;
    }

    await changePassword();
});

elements.currentPassword.addEventListener("input", updateFormState);
elements.newPassword.addEventListener("input", updateFormState);
elements.confirmPassword.addEventListener("input", updateFormState);
elements.logoutButton.addEventListener("click", logout);

SimpleWebSession.routePage()
    .then(({ error, redirecting, session }) => {
        if (redirecting || !session) {
            return;
        }

        if (error) {
            SimpleWebSession.goToLogin();
            return;
        }

        currentUser = session.user;
        SimpleWebSession.renderUserBadge(elements.userStatus, currentUser);
        elements.twoFactorSummary.textContent = currentUser.two_factor_enabled
            ? "2FA is enabled. Manage or disable it with a current verification code."
            : "2FA is off. Add a verification code from your authenticator app.";
        updateFormState();
        elements.currentPassword.focus();
    })
    .catch((err) => {
        console.warn("Settings initialization failed", err);
        SimpleWebSession.goToLogin();
    });
