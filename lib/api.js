const API_URL = "https://licensevault.test/api";

const Api = {
    async pairDevice(code, deviceName) {
        const response = await fetch(`${API_URL}/device/pair`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                device_name: deviceName
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.message || 'Pairing failed');
        }

        return await response.json();
    },

    async sync(token, items, lastSync = null, deviceId = null) {
        const response = await fetch(`${API_URL}/sync`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                items: items,
                last_sync: lastSync,
                device_id: deviceId
            })
        });

        if (!response.ok) {
            if (response.status === 401) throw new Error('Unauthenticated');
            const err = await response.json();
            throw new Error(err.message || 'Sync failed');
        }

        return await response.json();
    },

    async fetchPublicKey(token, userId) {
        const response = await fetch(`${API_URL}/user/${userId}/key`, {
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        if (!response.ok) throw new Error('Failed to fetch key');
        return await response.json();
    },

    async updatePublicKey(token, publicKey) {
        const response = await fetch(`${API_URL}/user/key`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ public_key: publicKey })
        });
        if (!response.ok) throw new Error('Failed to update key');
        return await response.json();
    }
};

// Expose to global scope (self works in Window and Worker)
self.Api = Api;
