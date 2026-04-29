const axios = require('axios');
const db = require('../db');
const logger = require('./logger');

const BASE_URL = process.env.ZYVENOX_MAIL_URL || 'https://mail.zyvenox.my.id/api';
const API_KEY = process.env.ZYVENOX_API_KEY || null;

const apiClientOpts = {
    baseURL: BASE_URL,
    headers: {
        'Content-Type': 'application/json',
        ...(API_KEY ? { 'X-API-Key': API_KEY } : {})
    },
    timeout: 10000
};

const proxyUrl = process.env.GENERAL_PROXY_URL;
if (proxyUrl) {
    const { HttpsProxyAgent } = require('https-proxy-agent');
    apiClientOpts.httpsAgent = new HttpsProxyAgent(proxyUrl);
    apiClientOpts.proxy = false;
}

const apiClient = axios.create(apiClientOpts);

/**
 * Generate email baru dari ZYVENOX Mail API.
 * Menggantikan LuckMail purchaseEmail().
 * token = alamat email itu sendiri (ZYVENOX tidak pakai token terpisah).
 * @returns {Promise<{token: string, email: string, purchaseId: string}>}
 */
async function purchaseEmail() {
    try {
        // 1. Ambil daftar domain yang tersedia
        const domainsRes = await apiClient.get('/domains');
        const domains = domainsRes.data?.domains || [];
        if (domains.length === 0) throw new Error('Tidak ada domain tersedia dari ZYVENOX API');

        // 2. Pilih domain secara acak
        const domain = domains[Math.floor(Math.random() * domains.length)];
        logger.info(`[ZyvenoxMail] Membuat email dengan domain: ${domain}`);

        // 3. Generate email random
        const genRes = await apiClient.post('/mailboxes/generate', { domain });

        // Response bisa berupa string atau object dengan field email
        let email = null;
        if (typeof genRes.data === 'string') {
            email = genRes.data.trim();
        } else if (genRes.data?.email) {
            email = genRes.data.email;
        } else if (genRes.data?.address) {
            email = genRes.data.address;
        }

        if (!email || !email.includes('@')) {
            throw new Error('Response email tidak valid dari ZYVENOX: ' + JSON.stringify(genRes.data));
        }

        // 4. Bersihkan inbox lama (jika ada)
        try {
            await apiClient.delete(`/mailboxes/${email}`);
        } catch {}

        // 5. Simpan ke orders.json (token = email address)
        db.saveOrder(email, email, 'purchased');
        logger.info(`[ZyvenoxMail] Email berhasil dibuat: ${email}`);

        return { token: email, email, purchaseId: email };
    } catch (error) {
        logger.error(`[ZyvenoxMail] Gagal membuat email: ${error.message}`);
        throw error;
    }
}

/**
 * Polling OTP dari inbox ZYVENOX.
 * Menggantikan LuckMail fetchVerificationCode().
 * @param {string} token - Alamat email (token = email pada ZYVENOX)
 * @param {string} email - Alamat email
 * @returns {Promise<string|null>} - Kode OTP 6-digit atau null jika timeout
 */
async function fetchVerificationCode(token, email) {
    const address = token || email;
    const maxRetries = 30; // 30 x 3s = 90 detik total
    const delayMs = 3000;
    const lastOtp = db.getOtpCache(email);

    logger.info(`[ZyvenoxMail] Memulai polling OTP untuk ${address}...`);
    if (lastOtp) {
        logger.debug(`[ZyvenoxMail] OTP sebelumnya di cache: ${lastOtp}, akan di-ignore.`);
    }

    for (let i = 0; i < maxRetries; i++) {
        try {
            await new Promise(resolve => setTimeout(resolve, delayMs));

            const response = await apiClient.get(`/mailboxes/${address}/otp`, {
                params: { service: 'openai' }
            });

            if (response.data && response.data.otp) {
                const rawOtp = String(response.data.otp);
                // Ekstrak 6 digit
                const match = rawOtp.match(/\b(\d{6})\b/);
                if (match && match[1]) {
                    const extractedOtp = match[1];

                    if (extractedOtp === lastOtp) {
                        logger.debug(`[ZyvenoxMail] OTP ${extractedOtp} sudah lama. Lanjut polling... (${i+1}/${maxRetries})`);
                        continue;
                    }

                    logger.success(`[ZyvenoxMail] Kode verifikasi ditemukan: ${extractedOtp}`);
                    db.saveOtpCache(email, extractedOtp);
                    return extractedOtp;
                }
            }
        } catch (error) {
            if (error.response?.status === 404) {
                // Email/OTP belum masuk, lanjut polling
            } else {
                logger.debug(`[ZyvenoxMail] Error polling: ${error.message}`);
            }
        }

        if (i % 3 === 0) {
            logger.info(`[ZyvenoxMail] Menunggu OTP untuk ${address}... (${(i + 1) * delayMs / 1000}s)`);
        }
    }

    logger.warn(`[ZyvenoxMail] Timeout 90 detik. OTP tidak ditemukan untuk ${address}.`);
    return null;
}

/**
 * Hapus inbox / batalkan email.
 * Menggantikan LuckMail cancelEmail().
 * @param {string} purchaseId - Alamat email (purchaseId = email pada ZYVENOX)
 */
async function cancelEmail(purchaseId) {
    try {
        await apiClient.delete(`/mailboxes/${purchaseId}`);
        logger.info(`[ZyvenoxMail] Inbox ${purchaseId} dibersihkan (cancel).`);
        db.saveOrder(purchaseId, 'cancelled', 'cancelled');
    } catch (e) {
        logger.debug(`[ZyvenoxMail] Gagal hapus inbox ${purchaseId}: ${e.message}`);
    }
}

module.exports = {
    purchaseEmail,
    fetchVerificationCode,
    cancelEmail
};
