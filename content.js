/**
 * Content Script
 */

// Inject Styles
const style = document.createElement('link');
style.rel = 'stylesheet';
style.type = 'text/css';
style.href = chrome.runtime.getURL('content.css');
(document.head || document.documentElement).appendChild(style);

// --- LISTENERS ---
let lastClickedElement = null;

document.addEventListener('contextmenu', (event) => {
    lastClickedElement = event.target;
}, true);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'prompt-name') {
        showNamePrompt(request.value);
    } else if (request.action === 'insert-text') {
        insertText(request.text);
    } else if (request.action === 'copy-text') {
        navigator.clipboard.writeText(request.text).then(() => {
            showToast('In Zwischenablage kopiert!');
        }).catch(err => {
            console.error('Copy failed', err);
            showToast('Kopieren fehlgeschlagen: ' + err);
        });
    }
});

// --- INSERT TEXT ---
function insertText(text) {
    console.log('[LicenseVault] Attempting to insert text:', text);

    // Prefer last clicked if it's editable, otherwise active element
    let target = activeEl = document.activeElement;

    if (lastClickedElement && (
        lastClickedElement.tagName === 'INPUT' ||
        lastClickedElement.tagName === 'TEXTAREA' ||
        lastClickedElement.isContentEditable ||
        lastClickedElement.contentEditable === 'true'
    )) {
        target = lastClickedElement;
    }

    console.log('[LicenseVault] Target element:', target);

    if (!target) {
        console.warn('[LicenseVault] No target found.');
        return;
    }

    target.focus();

    // Strategy 1: execCommand (Best for Undo support and broad compatibility)
    const success = document.execCommand('insertText', false, text);
    if (success) {
        console.log('[LicenseVault] Inserted via execCommand');
        return;
    }

    // Strategy 2: Direct value manipulation (Fallback for inputs/textareas)
    if (typeof target.value !== 'undefined') {
        console.log('[LicenseVault] Fallback to value manipulation');
        const start = target.selectionStart || 0;
        const end = target.selectionEnd || 0;
        const originalVal = target.value;
        target.value = originalVal.substring(0, start) + text + originalVal.substring(end);

        const newPos = start + text.length;
        target.setSelectionRange(newPos, newPos);
        target.dispatchEvent(new Event('input', { bubbles: true }));
        target.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
        console.error('[LicenseVault] Could not insert text.');
    }
}

// --- MODAL ---
function showNamePrompt(value) {
    // Remove existing if any
    const existing = document.getElementById('lv-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'lv-modal-overlay';

    const card = document.createElement('div');
    card.id = 'lv-modal-card';
    card.innerHTML = `
        <h3 style="margin:0 0 10px 0; color:#e6edf3;">Als Lizenz speichern</h3>
        <input type="text" id="lv-input-name" placeholder="Name der Lizenz" style="width:100%; padding:8px; margin-bottom:10px; border-radius:4px; border:1px solid #30363d; background:#0d1117; color:white;">
        <div style="display:flex; justify-content:flex-end; gap:10px;">
            <button id="lv-btn-cancel" style="padding:5px 10px; cursor:pointer; background:transparent; border:1px solid #30363d; color:#c9d1d9; border-radius:4px;">Abbrechen</button>
            <button id="lv-btn-save" style="padding:5px 10px; cursor:pointer; background:#238636; border:none; color:white; border-radius:4px;">Speichern</button>
        </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const input = document.getElementById('lv-input-name');
    input.focus();

    // Handlers
    document.getElementById('lv-btn-cancel').onclick = () => overlay.remove();

    const save = () => {
        const name = input.value.trim();
        if (!name) return;

        chrome.runtime.sendMessage({
            action: 'save_new_license',
            data: { name: name, value: value }
        });

        overlay.remove();
        // Optional: Show toast
        showToast('Lizenz gespeichert!');
    };

    document.getElementById('lv-btn-save').onclick = save;
    input.onkeydown = (e) => {
        if (e.key === 'Enter') save();
        if (e.key === 'Escape') overlay.remove();
    };
}

function showToast(msg) {
    const toast = document.createElement('div');
    toast.textContent = msg;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #238636;
        color: white;
        padding: 10px 20px;
        border-radius: 4px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        z-index: 999999;
        font-family: sans-serif;
        font-size: 14px;
        animation: fadein 0.3s, fadeout 0.3s 2.5s forwards;
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}
