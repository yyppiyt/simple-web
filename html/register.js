const elements = {
    password: document.getElementById("password"),
    passwordLimit: document.getElementById("registration-password-limit"),
    registerButton: document.getElementById("register-button"),
    registerForm: document.getElementById("register-form"),
    requirementsSummary: document.getElementById(
        "registration-requirements-summary"
    ),
    status: document.getElementById("register-status"),
    username: document.getElementById("username"),
};

const ruleElements = new Map(
    Array.from(
        document.querySelectorAll("[data-registration-password-rule]"),
        (element) => [element.dataset.registrationPasswordRule, element]
    )
);

function setStatus(message, type = "") {
    elements.status.textContent = message;
    elements.status.className = type ? `status ${type}` : "status";
}

function setBusy(busy) {
    elements.registerButton.disabled = busy;
    elements.username.disabled = busy;
    elements.password.disabled = busy;
}

function getRegistrationPayload() {
    return {
        username: elements.username.value.trim(),
        password: elements.password.value,
    };
}

function updatePasswordRequirements() {
    const requirements = SimpleWebPasswordPolicy.evaluate(
        elements.password.value,
        elements.username.value.trim()
    );
    let metCount = 0;

    for (const [ruleName, element] of ruleElements) {
        const met = Boolean(requirements[ruleName]);
        const check = element.querySelector(".requirement-check");

        element.classList.toggle("met", met);
        check.setAttribute("aria-label", met ? "Met" : "Not met");
        metCount += met ? 1 : 0;
    }

    elements.requirementsSummary.textContent =
        `${metCount} of ${ruleElements.size} password requirements met.`;

    if (requirements.maximumLength) {
        elements.passwordLimit.textContent = "";
        elements.passwordLimit.className = "field-hint";
    } else {
        elements.passwordLimit.textContent =
            `Password must be no more than ${SimpleWebPasswordPolicy.maximumLength} characters.`;
        elements.passwordLimit.className = "field-hint error";
    }

    return Object.values(requirements).every(Boolean);
}

async function register() {
    if (!updatePasswordRequirements()) {
        setStatus("Please meet every password requirement.", "error");
        return;
    }

    setBusy(true);
    setStatus("Creating account...");

    try {
        const data = await SimpleWebSession.apiJson("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(getRegistrationPayload()),
        });

        SimpleWebSession.set(data);
        elements.password.value = "";
        SimpleWebSession.goToIndex();
    } catch (err) {
        setStatus(err.message, "error");
        setBusy(false);
    }
}

elements.registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await register();
});

elements.username.addEventListener("input", updatePasswordRequirements);
elements.password.addEventListener("input", updatePasswordRequirements);

SimpleWebSession.routePage()
    .then(({ error, redirecting }) => {
        if (redirecting) {
            return;
        }

        if (error) {
            setStatus("Unable to verify the current session. You can still create an account.", "error");
        }

        updatePasswordRequirements();

        if (!document.activeElement || document.activeElement === document.body) {
            elements.username.focus();
        }
    })
    .catch((err) => {
        document.documentElement.classList.remove("auth-pending");
        setStatus(err.message, "error");
    });
