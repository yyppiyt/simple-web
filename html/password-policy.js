(function () {
    "use strict";

    const minimumLength = 8;
    const maximumLength = 128;
    const commonPasswordValues = [
        "00000000",
        "11111111",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "1q2w3e4r",
        "1qaz2wsx",
        "abc123",
        "abc12345",
        "admin",
        "admin123",
        "baseball",
        "dragon",
        "football",
        "iloveyou",
        "letmein",
        "login",
        "master",
        "monkey",
        "monkey123",
        "p@ssw0rd",
        "passw0rd",
        "password",
        "password1",
        "password123",
        "princess",
        "qwerty",
        "qwerty1",
        "qwerty123",
        "qwertyuiop",
        "shadow",
        "sunshine",
        "superman",
        "trustno1",
        "welcome",
        "welcome1",
        "zaq12wsx",
    ];

    function normalizeText(value) {
        return String(value).normalize("NFKC").toLowerCase();
    }

    function getCommonPasswordKeys(value) {
        const normalized = normalizeText(value);
        const alphaNumeric = normalized.replace(/[^a-z0-9]/g, "");
        const deLeeted = normalized
            .replace(/[@4]/g, "a")
            .replace(/3/g, "e")
            .replace(/[0]/g, "o")
            .replace(/[$5]/g, "s")
            .replace(/7/g, "t")
            .replace(/[^a-z0-9]/g, "");

        return [...new Set([normalized, alphaNumeric, deLeeted])];
    }

    const commonPasswordKeys = new Set(
        commonPasswordValues.flatMap(getCommonPasswordKeys)
    );

    function evaluate(password, username = "") {
        const rawPassword = typeof password === "string" ? password : "";
        const normalizedPassword = normalizeText(rawPassword);
        const normalizedUsername = normalizeText(username);
        const passwordLength = Array.from(rawPassword).length;
        const common = getCommonPasswordKeys(rawPassword).some((key) => (
            commonPasswordKeys.has(key)
        ));

        return {
            username: Boolean(rawPassword) && (
                !normalizedUsername || !normalizedPassword.includes(normalizedUsername)
            ),
            mixedCase: /\p{Ll}/u.test(rawPassword) && /\p{Lu}/u.test(rawPassword),
            number: /\p{N}/u.test(rawPassword),
            special: /[\p{P}\p{S}]/u.test(rawPassword),
            common: Boolean(rawPassword) && !common,
            length: passwordLength >= minimumLength,
            maximumLength: passwordLength <= maximumLength,
        };
    }

    globalThis.SimpleWebPasswordPolicy = {
        evaluate,
        maximumLength,
        minimumLength,
    };
})();
