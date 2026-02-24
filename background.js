/**
 * Background Service Worker
 */

importScripts('lib/crypto.js'); // Available as self.LicenseCrypto or global functions
importScripts('lib/api.js');

// --- SESSION STATE ---
// We use chrome.storage.session for persistence across SW restarts (but not browser restarts)
// Fallback to memory if session storage fails (rare)

const getSession = async () => {
    try {
        const res = await chrome.storage.session.get(['unlocked', 'password', 'licenses', 'biometricsEnabled']);
        return {
            unlocked: res.unlocked || false,
            password: res.password || null,
            licenses: res.licenses || [],
            biometricsEnabled: res.biometricsEnabled || false
        };
    } catch (e) {
        console.warn('Session storage error:', e);
        return { unlocked: false, licenses: [] };
    }
};

const setSession = async (data) => {
    try {
        await chrome.storage.session.set(data);
    } catch (e) {
        console.error('Session save error:', e);
    }
};

let autoLockMinutes = 15; // Default

// --- INITIALIZE ---
const setupAlarms = () => {
    chrome.alarms.get('autoSync', (alarm) => {
        if (!alarm) {
            chrome.alarms.create('autoSync', { periodInMinutes: 5 }); // Reduced to 5 as per user request
        }
    });
};

chrome.runtime.onInstalled.addListener(() => {
    updateContextMenus();
    setupAlarms();
});

chrome.runtime.onStartup.addListener(() => {
    setupAlarms();
    // On startup (browser restart), session is cleared automatically by Chrome.
});

// Listener for alarms
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'autoSync') {
        const session = await getSession();
        if (session.unlocked) {
            await performSync();
        }
    }
});

chrome.storage.local.get(['settings', 'biometrics_enabled'], async (res) => {
    if (res.settings && res.settings.autoLockMinutes !== undefined) {
        autoLockMinutes = parseInt(res.settings.autoLockMinutes, 10);
        if (isNaN(autoLockMinutes)) autoLockMinutes = 15;
        updateIdleState();
    }
    // Sync Biometrics setting to session if needed
    if (res.biometrics_enabled) {
        await setSession({ biometricsEnabled: true });
    }
});


// --- IDLE CHECK ---
function updateIdleState() {
    if (autoLockMinutes > 0) {
        chrome.idle.setDetectionInterval(autoLockMinutes * 60);
    }
}

chrome.idle.onStateChanged.addListener(async (newState) => {
    if (autoLockMinutes > 0 && (newState === 'idle' || newState === 'locked')) {
        const session = await getSession();
        if (session.unlocked) {
            console.log('Auto-locking vault.');

            // Soft Lock check
            const local = await chrome.storage.local.get(['biometrics_enabled']);
            const keepPassword = local.biometrics_enabled === true;

            let updates = { unlocked: false, licenses: [] };
            if (!keepPassword) {
                updates.password = null;
            } else {
                updates.biometricsEnabled = true;
            }

            await setSession(updates);
            updateContextMenus();
        }
    }
});

// --- MESSAGING ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        const session = await getSession();

        if (request.action === 'check_session') {
            sendResponse({ unlocked: session.unlocked, password: session.password });

        } else if (request.action === 'unlock_session') {
            await setSession({
                unlocked: true,
                password: request.password,
                licenses: request.licenses || []
            });
            updateContextMenus();
            sendResponse({ success: true });

        } else if (request.action === 'lock_session') {
            try {
                let updates = { unlocked: false, licenses: [] };

                // Check Local Storage for Biometrics preference explicitly
                const local = await chrome.storage.local.get(['biometrics_enabled']);
                const keepPassword = local.biometrics_enabled === true;

                if (!keepPassword) {
                    updates.password = null;
                } else {
                    updates.biometricsEnabled = true;
                }

                await setSession(updates);

                // IMPORTANT: Await this to ensure UI is updated before response
                await updateContextMenus();

                sendResponse({ success: true });
            } catch (err) {
                console.error('Lock session failed:', err);
                sendResponse({ success: false, error: err.message });
            }

        } else if (request.action === 'enable_biometrics') {
            await setSession({ biometricsEnabled: request.enabled });
            chrome.storage.local.set({ biometrics_enabled: request.enabled });
            sendResponse({ success: true });

        } else if (request.action === 'unlock_biometric') {
            if (session.password) {
                await setSession({ unlocked: true });
                updateContextMenus();
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: 'Password not in memory' });
            }

        } else if (request.action === 'update_data') {
            if (session.unlocked) {
                await setSession({ licenses: request.licenses });
                updateContextMenus();
            }
            sendResponse({ success: true });

        } else if (request.action === 'save_new_license') {
            handleSaveLicense(request.data);

        } else if (request.action === 'update_settings') {
            if (request.settings.autoLockMinutes !== undefined) {
                autoLockMinutes = parseInt(request.settings.autoLockMinutes);
                updateIdleState();
            }

        } else if (request.action === 'force_sync') {
            const res = await performSync();
            sendResponse(res);
        }
    })();
    return true; // Keep channel open for async
});

// --- EXTERNAL MESSAGING (Website -> Extension) ---
chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
    if (request.action === 'pair_request') {
        // Website sent us a pairing code
        chrome.storage.local.set({ pending_pairing_code: request.code });
        sendResponse({ success: true });

        // Optional: Notify user to open extension
        // chrome.action.setBadgeText({ text: "PAIR" });
    }
});

// --- KEY MANAGEMENT ---
async function ensureKeyPairAndUpload(token) {
    let keys = await chrome.storage.local.get(['b2b_private_key', 'b2b_public_key']);

    if (!keys.b2b_private_key || !keys.b2b_public_key) {
        console.log('Generating B2B Key Pair...');
        const keyPair = await self.LicenseCrypto.generateKeyPair();

        // Export
        const pubSpki = await self.LicenseCrypto.exportPublicKey(keyPair.publicKey);
        const priJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

        // Save
        await chrome.storage.local.set({
            b2b_private_key: priJwk,
            b2b_public_key: pubSpki
        });

        keys = { b2b_private_key: priJwk, b2b_public_key: pubSpki };

        // Upload
        console.log('Uploading Public Key...');
        try {
            await Api.updatePublicKey(token, pubSpki);
        } catch (e) {
            console.error('Public key upload failed', e, { tokenPresent: !!token });
            // Rethrow so caller knows upload failed (sync should still attempt to continue)
            throw e;
        }
    } else {
        // Maybe upload anyway to be safe? Or check if server has it? 
        // For efficiency, let's assume if we have it locally, we uploaded it.
        // Or we can just try uploading it on every sync start (it's idempotent usually).
        // Let's do it on sync just to be sure.
        try {
            await Api.updatePublicKey(token, keys.b2b_public_key);
        } catch (e) { console.warn('Key upload failed/skipped', e); }
    }

    // Return Private Key object
    return await crypto.subtle.importKey(
        "jwk",
        keys.b2b_private_key,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
}

// --- SYNC ENGINE ---
async function performSync() {
    try {
        console.log('Starting Sync...');
        // REPLACED: sessionState with session fetched via getSession()
        const session = await getSession();

        if (!session.unlocked || !session.password) {
            console.warn('Sync aborted: Vault locked');
            return { success: false, error: 'Vault locked' };
        }

        const auth = await chrome.storage.local.get(['auth_token', 'last_sync', 'device_id']);
        if (!auth.auth_token) {
            console.warn('Sync aborted: Unauthenticated');
            return { success: false, error: 'Unauthenticated' };
        }

        // 0. Ensure Keys
        const privateKey = await ensureKeyPairAndUpload(auth.auth_token);

        // 1. Prepare items for push
        const encryptedItems = await Promise.all(session.licenses.map(async (lic) => {
            let blob, encKey = null;

            if (lic.sharedKey) {
                // Shared Item: Encrypt with existing Symmetric Key
                const json = JSON.stringify({ ...lic, sharedKey: undefined }); // Don't encrypt the key inside the blob

                // We need to import the sharedKey (raw hex) back to CryptoKey
                // Check if sharedKey is hex or what? Assuming Hex string.
                // Reconstruct Key from Hex
                const rawKeyBytes = new Uint8Array(lic.sharedKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const itemKey = await crypto.subtle.importKey("raw", rawKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]);

                const enc = new TextEncoder();
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, itemKey, enc.encode(json));

                blob = JSON.stringify({
                    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
                    data: Array.from(new Uint8Array(cipher)).map(b => b.toString(16).padStart(2, '0')).join('')
                    // No salt needed for raw key
                });

            } else {
                // Personal Item: Encrypt with Password (Legacy)
                const json = JSON.stringify(lic);
                blob = await self.LicenseCrypto.encryptData(json, session.password);
            }

            return {
                id: lic.id,
                encrypted_blob: blob,
                encrypted_key: null, // We don't update this for now.
                client_updated_at: lic.updated_at,
                deleted: lic.deleted
            };
        }));

        // 2. Call API (Include device_id!)
        console.log(`Pushing ${encryptedItems.length} items...`);
        let result;
        try {
            result = await Api.sync(auth.auth_token, encryptedItems, auth.last_sync, auth.device_id);
            console.log('Sync Response:', result);
        } catch (e) {
            // More diagnostic info for network / CORS failures
            console.error('Api.sync failed', e, {
                itemsCount: encryptedItems.length,
                payloadSize: (function () {
                    try { return new TextEncoder().encode(JSON.stringify(encryptedItems)).length; } catch (err) { return null; }
                })(),
                device_id: auth.device_id,
                tokenPresent: !!auth.auth_token
            });
            throw e;
        }

        // 3. Process Updates
        let changed = false;

        if (result.updates && result.updates.length > 0) {
            console.log(`Received ${result.updates.length} updates.`);
            for (const up of result.updates) {
                try {
                    let remoteLic;
                    let sharedKeyHex = null;

                    if (up.encrypted_key) {
                        // Shared Item!
                        // 1. Decrypt the Key
                        const itemKey = await self.LicenseCrypto.unwrapKey(up.encrypted_key, privateKey);

                        // Export itemKey to Hex to store in session
                        const rawExport = await crypto.subtle.exportKey("raw", itemKey);
                        sharedKeyHex = Array.from(new Uint8Array(rawExport)).map(b => b.toString(16).padStart(2, '0')).join('');

                        // 2. Decrypt the Blob using this Key
                        const blobObj = JSON.parse(up.encrypted_blob);

                        const iv = new Uint8Array(blobObj.iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                        const data = new Uint8Array(blobObj.data.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

                        const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, itemKey, data);
                        const json = new TextDecoder().decode(dec);
                        remoteLic = JSON.parse(json);

                        // Attach sharedKey so we know how to encrypt it back
                        remoteLic.sharedKey = sharedKeyHex;

                    } else {
                        // Personal Item (Legacy Password)
                        const json = await self.LicenseCrypto.decryptData(up.encrypted_blob, session.password);
                        remoteLic = JSON.parse(json);
                    }

                    // Upsert Logic
                    const idx = session.licenses.findIndex(l => l.id === remoteLic.id);
                    if (idx !== -1) {
                        session.licenses[idx] = remoteLic;
                    } else {
                        session.licenses.push(remoteLic);
                    }
                    changed = true;
                } catch (e) {
                    console.error('Failed to decrypt remote item', up.id, e);
                }
            }

            if (changed) {
                // Save to local storage (All encrypted with Master Password)
                const dbJson = JSON.stringify(session.licenses);
                const encryptedDb = await self.LicenseCrypto.encryptData(dbJson, session.password);
                await chrome.storage.local.set({ encrypted_db: encryptedDb });

                // IMPORTANT: Update Session Storage too!
                await setSession({ licenses: session.licenses });

                updateContextMenus();
            }
        }

        // 4. Update Last Sync, but check if we have a valid server_time
        if (result.server_time) {
            await chrome.storage.local.set({ last_sync: result.server_time });
        }

        console.log('Sync completed successfully.');
        return { success: true };

    } catch (err) {
        console.error('Sync error:', err);
        return { success: false, error: err.message };
    }
}

// --- CONTEXT MENUS ---
// --- CONTEXT MENUS ---
async function updateContextMenus() {
    const session = await getSession();
    chrome.contextMenus.removeAll();

    if (!session.unlocked) {
        chrome.contextMenus.create({
            id: 'unlock-vault',
            title: '🔒 Keepless entsperren',
            contexts: ['all']
        });
        return;
    }

    // unlocked
    chrome.contextMenus.create({
        id: 'save-license',
        title: '💾 Auswahl als Lizenz speichern',
        contexts: ['selection']
    });

    // Parent menu for insertion
    const activeLicenses = session.licenses.filter(l => !l.deleted);

    if (activeLicenses.length > 0) {
        chrome.contextMenus.create({
            id: 'insert-root',
            title: '🔑 Lizenz einfügen',
            contexts: ['editable']
        });

        activeLicenses.forEach(lic => {
            chrome.contextMenus.create({
                id: `insert-${lic.id}`,
                parentId: 'insert-root',
                title: lic.name,
                contexts: ['editable']
            });
        });

        // Copy Menu
        chrome.contextMenus.create({
            id: 'copy-root',
            title: '📋 Lizenz kopieren',
            contexts: ['all']
        });

        activeLicenses.forEach(lic => {
            chrome.contextMenus.create({
                id: `copy-${lic.id}`,
                parentId: 'copy-root',
                title: lic.name,
                contexts: ['all']
            });
        });

    } else {
        chrome.contextMenus.create({
            id: 'insert-empty',
            title: '(Keine Lizenzen)',
            contexts: ['editable'],
            enabled: false
        });
    }
}

// --- MENU ACTIONS ---
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'unlock-vault') {
        chrome.action.openPopup();
    } else if (info.menuItemId === 'save-license') {
        const text = info.selectionText;
        chrome.tabs.sendMessage(tab.id, {
            action: 'prompt-name',
            value: text
        });
    } else if (info.menuItemId.startsWith('insert-')) {
        const session = await getSession();
        const id = info.menuItemId.replace('insert-', '');
        const lic = session.licenses.find(l => l.id == id);
        if (lic) {
            chrome.tabs.sendMessage(tab.id, {
                action: 'insert-text',
                text: lic.value
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.warn('Could not send message to tab:', chrome.runtime.lastError.message);
                }
            });
        }
    } else if (info.menuItemId.startsWith('copy-')) {
        const session = await getSession();
        const id = info.menuItemId.replace('copy-', '');
        const lic = session.licenses.find(l => l.id == id);
        if (lic) {
            chrome.tabs.sendMessage(tab.id, {
                action: 'copy-text',
                text: lic.value
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.log('Content script not ready, injecting...');
                    chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ['content.js']
                    }, () => {
                        chrome.tabs.sendMessage(tab.id, {
                            action: 'copy-text',
                            text: lic.value
                        });
                    });
                }
            });
        }
    }
});

// --- SAVE NEW ---
async function handleSaveLicense(data) {
    const session = await getSession();

    if (!session.unlocked || !session.password) return;

    const now = new Date().toISOString();
    const newLic = {
        id: crypto.randomUUID(),
        name: data.name,
        value: data.value,
        created_at: now,
        updated_at: now,
        deleted: false
    };

    session.licenses.push(newLic);

    // Encrypt
    const jsonStr = JSON.stringify(session.licenses);
    const encrypted = await self.LicenseCrypto.encryptData(jsonStr, session.password);

    await chrome.storage.local.set({ encrypted_db: encrypted });
    await setSession({ licenses: session.licenses });

    updateContextMenus();
}
