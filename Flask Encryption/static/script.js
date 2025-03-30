// Toggle Dark Mode
document.querySelector(".hari").addEventListener("click", function () {
    document.body.classList.toggle("dark-mode");
});

// Encrypt Text
function encryptText() {
    let text = document.getElementById("textInput").value;
    let keySize = document.getElementById("textKeySize").value;
    let key = document.getElementById("textKey").value;

    fetch('/encrypt-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text, keySize: keySize, key: key })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("encryptedText").innerText = data.encrypted || data.error;
    });
}

// Decrypt Text
function decryptText() {
    let text = document.getElementById("textDecryptInput").value;
    let key = document.getElementById("textDecryptKey").value;

    fetch('/decrypt-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text, key: key })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("decryptedText").innerText = data.decrypted || data.error;
    });
}
