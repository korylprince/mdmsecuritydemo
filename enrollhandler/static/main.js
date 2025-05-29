function base64urlToBase64(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64;
}
function bufferToBase64url(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    let base64 = window.btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.getElementById('show-register').onclick = () => {
    document.getElementById('register-form-container').style.display = 'block';
};
document.getElementById('cancel-register').onclick = () => {
    document.getElementById('register-form-container').style.display = 'none';
};
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

    // 2. Call WebAuthn API
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
    // 3. Send credential to server to finish registration
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
        document.getElementById('register-form-container').style.display = 'none';
    } else {
        alert('Registration failed');
    }
};

document.getElementById('login-form').onsubmit = async function(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    // 1. Begin login: get options from server, include password
    const resp = await fetch(`/users/${encodeURIComponent(username)}/login?password=${encodeURIComponent(password)}`);
    if (!resp.ok) {
        alert('Invalid username or password');
        return;
    }
    const options = await resp.json();

    // 2. Prepare options for WebAuthn API
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

    // 3. Call WebAuthn API
    let assertion;
    try {
        assertion = await navigator.credentials.get(options);
    } catch (err) {
        alert('WebAuthn error: ' + err);
        return;
    }

    // 4. Send assertion to server to finish login
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
        alert('Login successful!');
        window.location.href = '/mdm/enroll/finish';
    } else {
        alert('Passkey login failed');
    }
};