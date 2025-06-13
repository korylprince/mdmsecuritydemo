// Handle registration forms
document.getElementById('register-form').onsubmit = async function(e) {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const displayName = document.getElementById('reg-displayname').value;
    const password = document.getElementById('reg-password').value;

    // 1. Begin registration: get options from server
    const resp = await fetch(`/users/${encodeURIComponent(username)}/registration?display_name=${encodeURIComponent(displayName)}&password=${encodeURIComponent(password)}`);
    if (!resp.ok) {
        alert('Failed to start registration');
        return;
    }
    const options = await resp.json();

    options.publicKey.challenge = Uint8Array.from(
        atob(base64urlToBase64(options.publicKey.challenge)),
        c => c.charCodeAt(0)
    );
    options.publicKey.user.id = Uint8Array.from(
        atob(base64urlToBase64(options.publicKey.user.id)),
        c => c.charCodeAt(0)
    );
    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
            ...cred,
            id: Uint8Array.from(
                atob(base64urlToBase64(cred.id)),
                c => c.charCodeAt(0)
            )
        }));
    }
    let credential;
    try {
        credential = await navigator.credentials.create(options);
    } catch (err) {
        alert('WebAuthn error: ' + err);
        return;
    }

    const credentialJSON = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: bufferToBase64url(credential.response.attestationObject),
            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        }
    };
    const finishResp = await fetch(`/users/${encodeURIComponent(username)}/registration`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(credentialJSON)
    });
    if (finishResp.ok) {
        alert('Registration successful!');
        clearFormFields('register-form');
    } else {
        alert('Registration failed');
        clearFormFields('login-form');
    }
};

document.getElementById('clear-register').onclick = function() {
    clearFormFields('register-form');
};
