const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const passwordInput = document.getElementById('password');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const statusEl = document.getElementById('status');

let currentFile = null;

// Drag & Drop
['dragenter', 'dragover'].forEach(ev => {
  dropzone.addEventListener(ev, e => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add('dragover');
  });
});

['dragleave', 'drop'].forEach(ev => {
  dropzone.addEventListener(ev, e => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove('dragover');
  });
});

dropzone.addEventListener('drop', e => {
  const files = e.dataTransfer.files;
  if (files && files[0]) {
    currentFile = files[0];
    statusEl.textContent = `Datei geladen: ${currentFile.name}`;
  }
});

fileInput.addEventListener('change', e => {
  const files = e.target.files;
  if (files && files[0]) {
    currentFile = files[0];
    statusEl.textContent = `Datei geladen: ${currentFile.name}`;
  }
});

// Hilfsfunktionen Crypto
async function getKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function concatBuffers(...buffers) {
  let totalLength = buffers.reduce((sum, b) => sum + b.byteLength, 0);
  let tmp = new Uint8Array(totalLength);
  let offset = 0;
  for (const b of buffers) {
    tmp.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  }
  return tmp.buffer;
}

function downloadBlob(data, filename) {
  const blob = new Blob([data]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Verschlüsseln
encryptBtn.addEventListener('click', async () => {
  if (!currentFile) {
    statusEl.textContent = 'Keine Datei ausgewählt.';
    return;
  }
  const password = passwordInput.value;
  if (!password) {
    statusEl.textContent = 'Bitte Passwort eingeben.';
    return;
  }

  try {
    statusEl.textContent = 'Verschlüssele...';
    const fileArrayBuffer = await currentFile.arrayBuffer();

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await getKeyFromPassword(password, salt);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      fileArrayBuffer
    );

    // Format: [salt(16)][iv(12)][ciphertext(...)]
    const result = concatBuffers(salt.buffer, iv.buffer, ciphertext);
    downloadBlob(result, currentFile.name + '.enc');
    statusEl.textContent = 'Verschlüsselung fertig. Datei heruntergeladen.';
  } catch (err) {
    console.error(err);
    statusEl.textContent = 'Fehler bei der Verschlüsselung.';
  }
});

// Entschlüsseln
decryptBtn.addEventListener('click', async () => {
  if (!currentFile) {
    statusEl.textContent = 'Keine Datei ausgewählt.';
    return;
  }
  const password = passwordInput.value;
  if (!password) {
    statusEl.textContent = 'Bitte Passwort eingeben.';
    return;
  }

  try {
    statusEl.textContent = 'Entschlüssele...';
    const data = new Uint8Array(await currentFile.arrayBuffer());

    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);

    const key = await getKeyFromPassword(password, salt);

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    // Original-Dateiname grob rekonstruieren
    let name = currentFile.name.replace(/\.enc$/i, '');
    if (name === currentFile.name) {
      name = 'decrypted_' + currentFile.name;
    }

    downloadBlob(plaintext, name);
    statusEl.textContent = 'Entschlüsselung fertig. Datei heruntergeladen.';
  } catch (err) {
    console.error(err);
    statusEl.textContent = 'Fehler bei der Entschlüsselung (falsches Passwort oder beschädigte Datei?).';
  }
});