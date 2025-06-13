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
function clearFormFields(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.reset();
    } else {
        console.warn(`Form with ID ${formId} not found`);
    }
}