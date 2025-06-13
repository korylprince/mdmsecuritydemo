document.getElementById('login-form').onsubmit = async function(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    const resp = await fetch(`/users/${encodeURIComponent(username)}/login?password=${encodeURIComponent(password)}`);
    if (!resp.ok) {
        alert('Invalid username or password');
        return;
    }
    const options = await resp.json();

    options.publicKey.challenge = Uint8Array.from(
        atob(base64urlToBase64(options.publicKey.challenge)),
        c => c.charCodeAt(0)
    );
    if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: Uint8Array.from(
                atob(base64urlToBase64(cred.id)),
                c => c.charCodeAt(0)
            )
        }));
    }

    let assertion;
    try {
        assertion = await navigator.credentials.get(options);
    } catch (err) {
        alert('WebAuthn error: ' + err);
        return;
    }

    const credentialJSON = {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
            signature: bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
        }
    };
    const finishResp = await fetch(`/users/${encodeURIComponent(username)}/login`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(credentialJSON)
    });
    if (finishResp.ok) {
        clearFormFields('login-form');
        window.location.href = '/mdm/enroll/finish';
    } else {
        alert('Passkey login failed');
        clearFormFields('login-form');
    }
};

document.getElementById('clear-login').onclick = function() {
    clearFormFields('login-form');
};
