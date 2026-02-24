/**
 * Popup Logic
 */

const views = {
    unlock: document.getElementById('view-unlock'),
    setup: document.getElementById('view-setup'),
    dashboard: document.getElementById('view-dashboard'),
    editor: document.getElementById('view-editor')
};

const els = {
    headerActions: document.getElementById('header-actions'),
    autolockStatus: document.getElementById('autolock-status'),
    btnLock: document.getElementById('btn-lock'),
    formUnlock: document.getElementById('form-unlock'),
    unlockError: document.getElementById('unlock-error'),
    linkSetup: document.getElementById('link-setup'),

    formSetup: document.getElementById('form-setup'),
    btnCancelSetup: document.getElementById('btn-cancel-setup'),
    inputAutoLock: document.getElementById('input-autolock'),
    btnExport: document.getElementById('btn-export'),
    btnImportTrigger: document.getElementById('btn-import-trigger'),
    inputImportFile: document.getElementById('input-import-file'),

    btnToggleAdvanced: document.getElementById('btn-toggle-advanced'),
    advancedImportSection: document.getElementById('advanced-import'),

    btnDownloadSample: document.getElementById('btn-download-sample'),
    btnImportJsonTrigger: document.getElementById('btn-import-json-trigger'),
    inputImportJson: document.getElementById('input-import-json'),

    list: document.getElementById('license-list'),
    searchInput: document.getElementById('search-licenses'),
    btnAddView: document.getElementById('btn-add-view'),
    btnSettingsView: document.getElementById('btn-settings-view'),
    btnTrashToggle: document.getElementById('btn-trash-toggle'),
    btnSyncTrigger: document.getElementById('btn-sync-trigger'),

    formEditor: document.getElementById('form-editor'),
    editorTitle: document.getElementById('editor-title'),
    editId: document.getElementById('edit-id'),
    editName: document.getElementById('edit-name'),
    editValue: document.getElementById('edit-value'),
    btnCancelEdit: document.getElementById('btn-cancel-edit'),
    btnDelete: document.getElementById('btn-delete')
};

let masterPassword = null;
let licenses = [];
let showTrash = false;

// --- NAV ---
// --- INIT ---
document.addEventListener('DOMContentLoaded', async () => {

    // --- NAV ---
    function showView(viewName) {
        Object.values(views).forEach(el => el.classList.add('hidden'));
        views[viewName].classList.remove('hidden');

        if (viewName === 'dashboard') {
            els.headerActions.classList.remove('hidden');
            renderList();
        } else {
            els.headerActions.classList.add('hidden');
        }
    }
    // Check if vault is initialized
    const stored = await chrome.storage.local.get(['vault_check']);
    // We store a simple check to see if password exists (hashed or flag)
    // Actually, we can just check if 'encrypted_db' exists.
    const db = await chrome.storage.local.get(['encrypted_db']);

    if (!db.encrypted_db) {
        showView('setup');
        prepareSetupView(true); // Initial Setup Mode
    } else {
        // Load Settings FIRST to have them ready for session check
        const settings = await chrome.storage.local.get(['settings', 'biometrics_enabled', 'self_destruct']);

        // Self-Destruct UI
        const sd = settings.self_destruct || { enabled: false, count: 5 };
        const elSdEnabled = document.getElementById('input-self-destruct-enabled');
        const elSdCount = document.getElementById('input-self-destruct-count');

        if (elSdEnabled) elSdEnabled.checked = sd.enabled;
        if (elSdCount) elSdCount.value = sd.count || 5;

        // Auto-Lock UI Update
        if (settings.settings && settings.settings.autoLockMinutes) {
            els.inputAutoLock.value = settings.settings.autoLockMinutes;
            updateStatusBadge(settings.settings.autoLockMinutes);
        } else {
            updateStatusBadge(15);
        }

        // Check Session
        chrome.runtime.sendMessage({ action: 'check_session' }, (response) => {
            if (response && response.unlocked) {
                if (response.password) {
                    attemptUnlock(response.password);
                } else {
                    showView('unlock');
                }
            } else {
                // LOCKED STATE
                showView('unlock');

                // Soft Lock Check: Do we have a password in memory?
                const hasPasswordInMemory = response && response.password;

                // Show Biometrics Switch state in Settings (always reflects preference)
                const chk = document.getElementById('input-biometrics');
                if (chk && settings.biometrics_enabled) chk.checked = true;

                // Show Biometrics BUTTON ONLY if enabled AND password is available (Soft Lock)
                if (settings.biometrics_enabled && hasPasswordInMemory) {
                    const btnBio = document.getElementById('btn-biometric-unlock');
                    if (btnBio) {
                        btnBio.classList.remove('hidden');

                        // Auto-trigger
                        setTimeout(() => {
                            if (!views.unlock.classList.contains('hidden')) {
                                btnBio.click();
                            }
                        }, 300);
                    }
                }
            }
        });
    }

    // --- BIOMETRICS LISTENERS ---
    const btnBiometricUnlock = document.getElementById('btn-biometric-unlock');
    const inputBiometrics = document.getElementById('input-biometrics');

    // Helpers
    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const char of bytes) str += String.fromCharCode(char);
        return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64urlToBuffer(base64url) {
        const padding = '='.repeat((4 - base64url.length % 4) % 4);
        const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(base64);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) buffer[i] = raw.charCodeAt(i);
        return buffer.buffer;
    }

    if (btnBiometricUnlock) {
        btnBiometricUnlock.addEventListener('click', async () => {
            try {
                // Retrieve stored credential ID
                const stored = await chrome.storage.local.get(['biometric_credential_id']);
                const credentialId = stored.biometric_credential_id;

                // WebAuthn Challenge
                const challenge = new Uint8Array(32);
                window.crypto.getRandomValues(challenge);

                const publicKeyOptions = {
                    challenge: challenge,
                    timeout: 60000,
                    userVerification: "required"
                };

                // Internal Transport + AllowCredentials = Force Touch ID
                if (credentialId) {
                    publicKeyOptions.allowCredentials = [{
                        id: base64urlToBuffer(credentialId),
                        type: 'public-key',
                        transports: ['internal']
                    }];
                }

                await navigator.credentials.get({ publicKey: publicKeyOptions });

                // Success
                chrome.runtime.sendMessage({ action: 'unlock_biometric' }, (res) => {
                    if (res.success) {
                        chrome.runtime.sendMessage({ action: 'check_session' }, (session) => {
                            if (session && session.password) {
                                attemptUnlock(session.password);
                            } else {
                                alert('Sitzung abgelaufen. Bitte Passwort eingeben.');
                            }
                        });
                    } else {
                        alert('Biometrischer Unlock nicht möglich. Bitte Passwort nutzen.');
                    }
                });

            } catch (e) {
                console.warn('Biometric unlock cancelled/failed', e);
            }
        });
    }

    if (inputBiometrics) {
        inputBiometrics.addEventListener('change', async (e) => {
            const enabled = e.target.checked;
            if (enabled) {
                try {
                    // REGISTER NEW TOUCH ID (Platform Authenticator)
                    const challenge = new Uint8Array(32);
                    window.crypto.getRandomValues(challenge);

                    const userId = new Uint8Array(16);
                    window.crypto.getRandomValues(userId);

                    const createOptions = {
                        publicKey: {
                            challenge: challenge,
                            rp: { name: "Keepless" },
                            user: {
                                id: userId,
                                name: "user@vault",
                                displayName: "Vault User"
                            },
                            pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
                            authenticatorSelection: {
                                authenticatorAttachment: "platform",
                                userVerification: "required"
                            },
                            timeout: 60000,
                            attestation: "none"
                        }
                    };

                    const credential = await navigator.credentials.create(createOptions);

                    // Save Credential ID
                    const credId = bufferToBase64url(credential.rawId);
                    await chrome.storage.local.set({
                        biometrics_enabled: true,
                        biometric_credential_id: credId
                    });

                    chrome.runtime.sendMessage({ action: 'enable_biometrics', enabled: true });

                } catch (err) {
                    console.error(err);
                    e.target.checked = false;
                    alert('Touch ID Einrichtung fehlgeschlagen:\n' + err.message);
                }
            } else {
                await chrome.storage.local.set({ biometrics_enabled: false });
                chrome.storage.local.remove(['biometric_credential_id']);
                chrome.runtime.sendMessage({ action: 'enable_biometrics', enabled: false });
            }
        });
    }

    // --- UNLOCK ---
    els.formUnlock.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('input-password').value;
        await attemptUnlock(password);
    });

    async function attemptUnlock(password) {
        try {
            const db = await chrome.storage.local.get(['encrypted_db']);
            if (!db.encrypted_db) return; // Should not happen

            const jsonDb = await self.LicenseCrypto.decryptData(db.encrypted_db, password);
            let rawData = JSON.parse(jsonDb);

            // MIGRATION: Ensure all items have UUIDs and timestamps
            rawData = migrateData(rawData);

            licenses = rawData;
            masterPassword = password;

            // Notify BG to keep session alive and update context menus
            chrome.runtime.sendMessage({
                action: 'unlock_session',
                password: password,
                licenses: licenses
            });

            showView('dashboard');
            els.unlockError.textContent = '';
            document.getElementById('input-password').value = '';

            // Reset Failed Attempts Logic
            await chrome.storage.local.remove(['failed_attempts']);

        } catch (err) {
            console.error(err);

            // --- SELF DESTRUCT LOGIC ---
            const res = await chrome.storage.local.get(['self_destruct', 'failed_attempts']);
            const sd = res.self_destruct || { enabled: false, count: 5 };

            if (sd.enabled) {
                let fails = (res.failed_attempts || 0) + 1;
                await chrome.storage.local.set({ failed_attempts: fails });

                const remaining = sd.count - fails;

                if (remaining <= 0) {
                    // WIPE!
                    await chrome.storage.local.remove(['encrypted_db', 'settings', 'auth_token', 'failed_attempts', 'biometric_credential_id', 'biometrics_enabled']);
                    await chrome.runtime.sendMessage({ action: 'lock_session' });
                    alert('⛔️ ZU VIELE FEHLVERSUCHE.\n\nDer Tresor wurde sicherheitshalber gelöscht.');
                    window.location.reload();
                    return;
                } else {
                    els.unlockError.textContent = `Falsches Passwort! Noch ${remaining} Versuche bis zur Löschung.`;
                    return;
                }
            }

            els.unlockError.textContent = 'Falsches Passwort oder Fehler bei der Entschlüsselung.';
        }
    }

    // --- SETUP / PASSWORD CHANGE ---
    els.linkSetup.addEventListener('click', (e) => {
        e.preventDefault();
        // Setup Mode (Reset)
        showView('setup');
        prepareSetupView(false); // False = Not clean setup, but reset flow? Usually linkSetup means "Forgot Password" -> Reset
    });

    // We need to differentiate between "Initial Setup" and "Settings View"
    function prepareSetupView(isInitialSetup) {
        const oldPwRow = document.getElementById('input-old-password').parentElement;
        const btnReset = document.getElementById('btn-reset-vault');

        if (isInitialSetup) {
            // New Vault
            oldPwRow.classList.add('hidden');
            btnReset.classList.add('hidden');
            document.getElementById('input-old-password').required = false;
        } else {
            // Change Password
            oldPwRow.classList.remove('hidden');
            btnReset.classList.remove('hidden');
            document.getElementById('input-old-password').required = true;
        }
    }

    // Setup / Change Password Listener
    els.formSetup.addEventListener('submit', async (e) => {
        e.preventDefault();
        const oldPw = document.getElementById('input-old-password').value;
        const newPw = document.getElementById('input-new-password').value;
        const confirmPw = document.getElementById('input-confirm-password').value;

        if (newPw !== confirmPw) {
            alert('Die neuen Passwörter stimmen nicht überein.');
            return;
        }

        if (masterPassword) {
            // --- CHANGE PASSWORD (Re-Encrypt) ---
            if (oldPw !== masterPassword) {
                alert('Das alte Passwort ist falsch.');
                return;
            }

            if (!confirm('Möchten Sie das Master-Passwort wirklich ändern? Alle Daten werden neu verschlüsselt.')) return;

            // Re-encrypt with new password
            masterPassword = newPw; // Update memory
            await saveDb(); // Save with new key

            // Update Background Session so user stays logged in
            chrome.runtime.sendMessage({
                action: 'unlock_session',
                password: newPw,
                licenses: licenses
            });

            alert('Passwort erfolgreich geändert!');
            document.getElementById('input-old-password').value = '';
            document.getElementById('input-new-password').value = '';
            document.getElementById('input-confirm-password').value = '';

        } else {
            // --- INITIAL SETUP ---
            // No old password check needed
            masterPassword = newPw;
            licenses = [];
            await saveDb();
            showView('dashboard');
        }
    });

    // Explicit Reset Button
    const btnResetVault = document.getElementById('btn-reset-vault');
    if (btnResetVault) {
        btnResetVault.addEventListener('click', async () => {
            if (confirm('⚠️ ACHTUNG: Dies LÖSCHT unwiderruflich alle Daten im Tresor und setzt ihn zurück!\n\nSind Sie sicher?')) {
                if (confirm('Wirklich? Alle Lizenzen werden gelöscht!')) {
                    await chrome.storage.local.remove(['encrypted_db', 'settings', 'auth_token']);
                    await chrome.runtime.sendMessage({ action: 'lock_session' });
                    window.location.reload();
                }
            }
        });
    }


    const btnCancelTop = document.getElementById('btn-cancel-setup-top');
    if (btnCancelTop) {
        btnCancelTop.addEventListener('click', () => {
            if (licenses.length > 0) showView('dashboard');
            else showView('unlock');
        });
    }

    els.btnCancelSetup.addEventListener('click', () => {
        // If we have licenses, go to dashboard, else stay (or go unlock)
        if (licenses.length > 0) showView('dashboard');
        else showView('unlock');
    });

    // --- SETTINGS EXTRAS ---
    els.btnExport.addEventListener('click', async () => {
        const db = await chrome.storage.local.get(['encrypted_db']);
        if (!db.encrypted_db) return alert('Nichts zu exportieren.');

        const blob = new Blob([db.encrypted_db], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const date = new Date().toISOString().slice(0, 10);

        chrome.downloads.download({
            url: url,
            filename: `license-vault-backup-${date}.json`
        });
    });

    // --- SETTINGS LISTENER ---
    const elSdEnabled = document.getElementById('input-self-destruct-enabled');
    const elSdCount = document.getElementById('input-self-destruct-count');

    async function saveSdSettings() {
        const enabled = elSdEnabled.checked;
        const count = parseInt(elSdCount.value) || 5;
        await chrome.storage.local.set({
            self_destruct: { enabled, count }
        });
    }

    if (elSdEnabled) elSdEnabled.addEventListener('change', saveSdSettings);
    if (elSdCount) elSdCount.addEventListener('change', saveSdSettings);

    els.inputAutoLock.addEventListener('change', async () => {
        const min = parseInt(els.inputAutoLock.value);
        const settings = { autoLockMinutes: min };
        await chrome.storage.local.set({ settings });
        chrome.runtime.sendMessage({ action: 'update_settings', settings });
        updateStatusBadge(min);
    });

    // --- IMPORT ---
    els.btnImportTrigger.addEventListener('click', () => {
        els.inputImportFile.click();
    });

    els.inputImportFile.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        if (!confirm('ACHTUNG: Dies überschreibt ALLE aktuellen Lizenzen mit dem Backup.\n\nDer Tresor wird danach gesperrt. Wenn das Backup ein anderes Passwort hat, benötigen Sie dieses zum Entsperren.')) {
            els.inputImportFile.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const jsonStr = event.target.result;
                // Validate JSON format roughly
                const data = JSON.parse(jsonStr);
                if (!data.salt || !data.iv || !data.data) {
                    throw new Error('Ungültiges Backup-Format.');
                }

                // Save raw encrypted string
                await chrome.storage.local.set({ encrypted_db: jsonStr });

                // Clear biometrics if set, as key might change
                await chrome.storage.local.remove(['biometrics_enabled', 'biometric_credential_id']);

                // Logout
                masterPassword = null;
                licenses = [];
                chrome.runtime.sendMessage({ action: 'lock_session' });

                alert('Backup erfolgreich importiert. Bitte neu anmelden.');
                showView('unlock');

            } catch (err) {
                console.error(err);
                alert('Fehler beim Import: ' + err.message);
            }
            els.inputImportFile.value = '';
        };
        reader.readAsText(file);
    });

    // --- ADVANCED IMPORT TOGGLE ---
    if (els.btnToggleAdvanced) {
        els.btnToggleAdvanced.addEventListener('click', () => {
            els.advancedImportSection.classList.toggle('hidden');
            const isHidden = els.advancedImportSection.classList.contains('hidden');
            els.btnToggleAdvanced.textContent = isHidden ? 'Erweiterte Importe anzeigen' : 'Erweiterte Importe verbergen';
        });
    }



    // --- PLAINTEXT IMPORT & SAMPLE ---
    els.btnDownloadSample.addEventListener('click', () => {
        const sample = [
            { "name": "Beispiel Lizenz", "value": "1234-5678-ABCD" },
            { "name": "Windows Pro", "value": "AAAA-BBBB-CCCC" }
        ];
        const blob = new Blob([JSON.stringify(sample, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        chrome.downloads.download({
            url: url,
            filename: `license-import-sample.json`
        });
    });

    els.btnImportJsonTrigger.addEventListener('click', () => {
        els.inputImportJson.click();
    });

    els.inputImportJson.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const json = JSON.parse(event.target.result);
                if (!Array.isArray(json)) throw new Error('Format muss ein Array sein: [{"name":..., "value":...}]');

                let addedCount = 0;
                let skipCount = 0;

                json.forEach(item => {
                    if (!item.name || !item.value) return; // Skip invalid

                    // Check ALL items including deleted to find duplicates
                    const existingIdx = licenses.findIndex(l => l.name === item.name && l.value === item.value);

                    if (existingIdx === -1) {
                        // New item
                        const now = new Date().toISOString();
                        licenses.push({
                            id: crypto.randomUUID(),
                            name: item.name,
                            value: item.value,
                            created_at: now,
                            updated_at: now,
                            deleted: false
                        });
                        addedCount++;
                    } else {
                        // Already exists
                        const existing = licenses[existingIdx];
                        if (existing.deleted) {
                            // Resurrect it!
                            existing.deleted = false;
                            existing.updated_at = new Date().toISOString();
                            addedCount++; // Count as added (restored)
                        } else {
                            skipCount++;
                        }
                    }
                });

                await saveDb();
                alert(`Import fertig!\nDoppelte übersprungen: ${skipCount}\nNeu hinzugefügt: ${addedCount}`);

                // Go to dashboard to see results
                renderList();
                showView('dashboard');

            } catch (err) {
                console.error(err);
                alert('Fehler beim Import: ' + err.message);
            }
            els.inputImportJson.value = '';
        };
        reader.readAsText(file);
    });

    // --- DASHBOARD ---
    els.btnAddView.addEventListener('click', () => {
        openEditor();
    });

    els.btnSettingsView.addEventListener('click', () => {
        showView('setup');
        prepareSetupView(false); // Settings Mode
    });

    els.btnTrashToggle.addEventListener('click', () => {
        showTrash = !showTrash;
        els.btnTrashToggle.classList.toggle('active', showTrash);
        renderList();
    });

    // SYNC TRIGGER (Header)
    els.btnSyncTrigger.addEventListener('click', async () => {
        if (els.btnSyncTrigger.disabled) return;

        els.btnSyncTrigger.disabled = true;
        els.btnSyncTrigger.classList.add('spin-animation');

        try {
            const response = await chrome.runtime.sendMessage({ action: 'force_sync' });

            // Minimum spin time for UX
            await new Promise(r => setTimeout(r, 800));

            els.btnSyncTrigger.classList.remove('spin-animation');

            if (response && response.success) {
                // Success State
                els.btnSyncTrigger.textContent = '✅';
                els.btnSyncTrigger.title = 'Synchronisation erfolgreich';

                // Reload list
                if (masterPassword) attemptUnlock(masterPassword);

                setTimeout(() => {
                    els.btnSyncTrigger.textContent = '🔄';
                    els.btnSyncTrigger.title = 'Jetzt synchronisieren';
                    els.btnSyncTrigger.disabled = false;
                }, 2000);
            } else {
                throw new Error(response.error || 'Unknown error');
            }
        } catch (err) {
            console.error(err);
            els.btnSyncTrigger.classList.remove('spin-animation');
            els.btnSyncTrigger.textContent = '⚠️';
            els.btnSyncTrigger.title = 'Fehler: ' + err.message;
            setTimeout(() => {
                els.btnSyncTrigger.textContent = '🔄';
                els.btnSyncTrigger.title = 'Jetzt synchronisieren';
                els.btnSyncTrigger.disabled = false;
            }, 2000);
        }
    });

    els.searchInput.addEventListener('input', () => {
        renderList();
    });

    function renderList() {
        const filter = els.searchInput.value.toLowerCase();
        els.list.innerHTML = '';

        // Filter based on Trash Toggle
        // If showTrash is true: show ONLY deleted
        // If showTrash is false: show ONLY active (not deleted)
        const filteredLicenses = licenses.filter(l => {
            if (showTrash) return l.deleted;
            else return !l.deleted;
        });

        filteredLicenses.forEach(lic => {
            if (lic.name.toLowerCase().includes(filter)) {
                const el = document.createElement('div');
                el.className = 'license-item';

                if (showTrash) {
                    el.innerHTML = `
                <div style="opacity: 0.6;">
                    <div class="license-name">${escapeHtml(lic.name)}</div>
                    <div class="license-preview" style="text-decoration: line-through;">GELÖSCHT</div>
                </div>
                <div class="btn-row" style="gap:4px;">
                    <button class="btn-small btn-secondary restore-btn" title="Wiederherstellen">♻️</button>
                    <button class="btn-small btn-danger-outline delete-perm-btn" title="Endgültig löschen">❌</button>
                </div>
            `;
                    // Bind events for trash items
                    const btnRestore = el.querySelector('.restore-btn');
                    const btnPermDelete = el.querySelector('.delete-perm-btn');

                    btnRestore.onclick = (e) => {
                        e.stopPropagation();
                        restoreLicense(lic.id);
                    };

                    btnPermDelete.onclick = (e) => {
                        e.stopPropagation();
                        permanentDelete(lic.id);
                    };

                } else {
                    el.innerHTML = `
                <div>
                    <div class="license-name">${escapeHtml(lic.name)}</div>
                    <div class="license-preview">********</div>
                </div>
                <div>✏️</div>
            `;
                    el.onclick = () => openEditor(lic);
                }

                els.list.appendChild(el);
            }
        });

        if (filteredLicenses.length === 0) {
            if (showTrash) {
                els.list.innerHTML = '<div class="empty-state">Papierkorb ist leer.</div>';
            } else {
                els.list.innerHTML = '<div class="empty-state" style="padding:20px; text-align:center; color:#8b949e;">Keine Lizenzen.<br>Drücken Sie + oder nutzen Sie den Rechtsklick auf Webseiten.</div>';
            }
        }
    }

    async function restoreLicense(id) {
        const idx = licenses.findIndex(l => l.id == id);
        if (idx !== -1) {
            licenses[idx].deleted = false;
            licenses[idx].updated_at = new Date().toISOString();
            await saveDb();
            renderList();
        }
    }

    async function permanentDelete(id) {
        if (!confirm('Endgültig löschen? Dies kann nicht rückgängig gemacht werden.')) return;

        const idx = licenses.findIndex(l => l.id == id);
        if (idx !== -1) {
            licenses.splice(idx, 1); // Real delete
            await saveDb();
            renderList();
        }
    }

    // --- EDITOR ---
    function openEditor(license = null) {
        if (license) {
            els.editorTitle.textContent = 'Lizenz bearbeiten';
            els.editId.value = license.id;
            els.editName.value = license.name;
            els.editValue.value = license.value;
            els.btnDelete.classList.remove('hidden');
        } else {
            els.editorTitle.textContent = 'Lizenz hinzufügen';
            els.editId.value = '';
            els.editName.value = '';
            els.editValue.value = '';
            els.btnDelete.classList.add('hidden');
        }
        showView('editor');
    }

    els.btnCancelEdit.addEventListener('click', () => showView('dashboard'));

    els.formEditor.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = els.editId.value;
        const name = els.editName.value;
        const value = els.editValue.value;
        const now = new Date().toISOString();

        if (id) {
            // Edit
            const idx = licenses.findIndex(l => l.id == id);
            if (idx !== -1) {
                licenses[idx].name = name;
                licenses[idx].value = value;
                licenses[idx].updated_at = now;
                // Ensure deleted is false if we are saving it
                if (licenses[idx].deleted) licenses[idx].deleted = false;
            }
        } else {
            // New
            licenses.push({
                id: crypto.randomUUID(),
                name,
                value,
                created_at: now,
                updated_at: now,
                deleted: false
            });
        }

        await saveDb();
        showView('dashboard');
    });

    els.btnDelete.addEventListener('click', async () => {
        if (confirm('Wirklich löschen?')) {
            const id = els.editId.value;
            const idx = licenses.findIndex(l => l.id == id);

            if (idx !== -1) {
                // Soft Delete
                licenses[idx].deleted = true;
                licenses[idx].updated_at = new Date().toISOString();
            }

            await saveDb();
            showView('dashboard');
        }
    });

    // --- PERISTENCE ---
    async function saveDb() {
        const jsonStr = JSON.stringify(licenses);
        const encrypted = await self.LicenseCrypto.encryptData(jsonStr, masterPassword);

        await chrome.storage.local.set({ encrypted_db: encrypted });

        // Update context menus logic in BG
        chrome.runtime.sendMessage({
            action: 'update_data',
            licenses: licenses
        });
    }

    // --- HELPERS ---
    function migrateData(list) {
        const now = new Date().toISOString();
        return list.map(item => {
            // 1. Ensure UUID
            if (!item.id || !item.id.includes('-') || /^\d+$/.test(item.id)) {
                item.id = crypto.randomUUID();
            }

            // 2. Timestamps
            if (!item.created_at) item.created_at = now;
            if (!item.updated_at) item.updated_at = now;

            // 3. Flags
            if (item.deleted === undefined) item.deleted = false;

            return item;
        });
    }

    function escapeHtml(text) {
        if (!text) return text;
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // --- GLOBAL LOCK ---
    els.btnLock.addEventListener('click', async () => {
        masterPassword = null;
        licenses = [];
        await chrome.runtime.sendMessage({ action: 'lock_session' });
        window.location.reload(); // Force clean check for Biometric UI
    });

    // --- CLOUD SYNC ---
    const syncEls = {
        container: document.getElementById('sync-status-container'),
        statusText: document.getElementById('sync-status-text'),
        btnShowPair: document.getElementById('btn-show-pair'),
        formPair: document.getElementById('form-pair'),
        inputCode: document.getElementById('input-pair-code'),
        inputDeviceName: document.getElementById('input-device-name'),
        btnCancelPair: document.getElementById('btn-cancel-pair'),
        actions: document.getElementById('sync-actions'),
        btnForceSync: document.getElementById('btn-force-sync'),
        btnLogout: document.getElementById('btn-logout')
    };

    async function checkSyncStatus() {
        const auth = await chrome.storage.local.get(['auth_token', 'device_name', 'last_sync']);
        const badge = document.getElementById('sync-badge');
        const lastEl = document.getElementById('sync-last');

        if (auth.auth_token) {
            // Connected — nicer presentation without emojis
            syncEls.statusText.textContent = `Verbunden als "${auth.device_name || 'Gerät'}"`;
            if (badge) { badge.classList.remove('disconnected'); badge.classList.add('connected'); badge.textContent = 'Verbunden'; }
            syncEls.btnShowPair.classList.add('hidden');
            syncEls.formPair.classList.add('hidden');
            syncEls.actions.classList.remove('hidden');

            if (auth.last_sync) {
                const date = new Date(auth.last_sync).toLocaleString();
                if (lastEl) lastEl.textContent = `Letzter Sync: ${date}`;
            } else {
                if (lastEl) lastEl.textContent = '';
            }
        } else {
            // Not Connected
            syncEls.statusText.textContent = 'Nicht verbunden.';
            if (badge) { badge.classList.remove('connected'); badge.classList.add('disconnected'); badge.textContent = 'Nicht verbunden'; }
            if (lastEl) lastEl.textContent = '';
            syncEls.btnShowPair.classList.remove('hidden');
            syncEls.formPair.classList.add('hidden');
            syncEls.actions.classList.add('hidden');
        }
    }
    // Call on load
    checkSyncStatus().then(() => {
        // Check for pending pairing code from website
        chrome.storage.local.get(['pending_pairing_code'], (res) => {
            if (res.pending_pairing_code) {
                // Auto open pair form
                if (!syncEls.btnShowPair.classList.contains('hidden')) {
                    syncEls.btnShowPair.click();
                    syncEls.inputCode.value = res.pending_pairing_code;
                    // Optional: clear it
                    chrome.storage.local.remove(['pending_pairing_code']);
                }
            }
        });
    });

    syncEls.btnShowPair.addEventListener('click', () => {
        syncEls.btnShowPair.classList.add('hidden');
        syncEls.formPair.classList.remove('hidden');
    });

    syncEls.btnCancelPair.addEventListener('click', () => {
        syncEls.formPair.classList.add('hidden');
        checkSyncStatus(); // Reset UI
    });

    syncEls.formPair.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = syncEls.inputCode.value.toUpperCase();
        const name = syncEls.inputDeviceName.value;

        const msgEl = document.getElementById('pair-message');
        msgEl.classList.add('hidden');
        msgEl.className = 'hidden'; // Reset classes

        if (code.length < 6) {
            showMessage(msgEl, 'Bitte Code eingeben.', 'error');
            return;
        }

        // Show loading state
        const btnSubmit = syncEls.formPair.querySelector('button[type="submit"]');
        const originalBtnText = btnSubmit.textContent;
        btnSubmit.textContent = 'Verbinde...';
        btnSubmit.disabled = true;

        try {
            const res = await window.Api.pairDevice(code, name);

            if (!res.device_id) {
                alert('Warnung: Keine Device ID vom Server empfangen!');
            } else {
                // DEBUG: Confirm to user
                // alert('Gekoppelt! Device ID: ' + res.device_id); 
            }

            // Save Token
            await chrome.storage.local.set({
                auth_token: res.token,
                device_id: res.device_id,
                device_name: name,
                user_info: res.user // Expecting {id, name, email}
            });

            // Force background to reload storage
            chrome.runtime.sendMessage({ action: 'update_settings', settings: {} }); // Dummy call to wake up?

            // Success Message
            showMessage(msgEl, `✅ Erfolgreich gekoppelt!\nVerbunden mit: ${res.user.name} (${res.user.email})`, 'success');

            syncEls.inputCode.value = '';

            // Wait a moment then refresh UI
            setTimeout(() => {
                syncEls.formPair.classList.add('hidden'); // Hide form
                checkSyncStatus(); // Show status
                btnSubmit.textContent = originalBtnText;
                btnSubmit.disabled = false;
            }, 2000);

            // Check if we need to upload public key (B2B)
            // Generate key pair if not exists, then upload.
            // For now, let's keep it simple and just do sync.

            // Trigger initial sync
            chrome.runtime.sendMessage({ action: 'force_sync' });

        } catch (err) {
            console.error(err);
            showMessage(msgEl, `❌ Kopplung fehlgeschlagen:\n${err.message}`, 'error');
            btnSubmit.textContent = originalBtnText;
            btnSubmit.disabled = false;
        }
    });

    function showMessage(el, text, type) {
        el.innerText = text;
        el.classList.remove('hidden');
        el.style.display = 'block';

        if (type === 'success') {
            el.style.backgroundColor = '#d1fae5'; // green-100
            el.style.color = '#065f46'; // green-800
            el.style.border = '1px solid #34d399';
        } else {
            el.style.backgroundColor = '#fee2e2'; // red-100
            el.style.color = '#991b1b'; // red-800
            el.style.border = '1px solid #f87171';
        }
    }

    syncEls.btnLogout.addEventListener('click', async () => {
        if (confirm('Verbindung trennen?')) {
            await chrome.storage.local.remove(['auth_token', 'device_id', 'device_name', 'user_info', 'last_sync']);
            checkSyncStatus();
        }
    });

    syncEls.btnForceSync.addEventListener('click', async () => {
        const originalText = syncEls.btnForceSync.textContent;
        syncEls.btnForceSync.disabled = true;
        syncEls.btnForceSync.textContent = '⏳ Sync...';

        chrome.runtime.sendMessage({ action: 'force_sync' }, (response) => {
            if (response && response.success) {
                syncEls.btnForceSync.textContent = '✅ Synchronisiert!';
                syncEls.btnForceSync.classList.replace('btn-secondary', 'btn-primary'); // Optional visual pop
                checkSyncStatus();

                setTimeout(() => {
                    syncEls.btnForceSync.textContent = originalText;
                    syncEls.btnForceSync.classList.replace('btn-primary', 'btn-secondary');
                    syncEls.btnForceSync.disabled = false;
                }, 2000);
            } else {
                syncEls.btnForceSync.textContent = '❌ Fehler';
                alert('Sync fehlgeschlagen: ' + (response ? response.error : 'Unbekannt'));
                setTimeout(() => {
                    syncEls.btnForceSync.textContent = originalText;
                    syncEls.btnForceSync.disabled = false;
                }, 2000);
            }
        });
    }); // End btnForceSync
}); // End DOMContentLoaded

function updateStatusBadge(min) {
    min = parseInt(min);
    if (min === 0) {
        els.autolockStatus.textContent = '';
        els.autolockStatus.classList.add('hidden');
    } else {
        els.autolockStatus.textContent = `⏱️ ${min}m`;
        els.autolockStatus.classList.remove('hidden');
    }
}
