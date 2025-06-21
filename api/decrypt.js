// api/decrypt.js
const multer = require('multer');
const crypto = require('crypto');
const Jimp = require('jimp');

// Use memory storage for Multer
const upload = multer({ storage: multer.memoryStorage() });

// --- CORS Configuration (Same as encrypt.js) ---
const ALLOWED_ORIGINS = [
    'https://yourdomain.com', // Replace with your actual frontend domain
    'http://yourdomain.com',
    'https://www.yourdomain.com',
    // 'http://localhost:3000',
    // 'http://localhost:8080'
];

// --- Secret Key Management ---
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    console.error("ERROR: ENCRYPTION_KEY is not set or is not 64 hexadecimal characters long.");
}
const KEY_BUFFER = ENCRYPTION_KEY ? Buffer.from(ENCRYPTION_KEY, 'hex') : Buffer.alloc(32, 0);

// --- AES Utility Functions ---
const ALGORITHM = 'aes-256-cbc';

function decrypt(encryptedDataHex, ivHex) {
    if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
        throw new Error("Decryption key is not properly configured.");
    }
    const iv = Buffer.from(ivHex, 'hex');
    const encryptedTextBuffer = Buffer.from(encryptedDataHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY_BUFFER, iv);
    let decrypted = decipher.update(encryptedTextBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted; // Returns a Buffer
}

// Vercel Serverless Function entry point
module.exports = async (req, res) => {
    // 1. Handle CORS Preflight
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // 2. Ensure it's a POST request
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    // 3. Process file upload using Multer
    await new Promise((resolve, reject) => {
        // Multer needs to parse the form data before we can access req.body
        upload.single('image')(req, res, (err) => {
            if (err) {
                console.error("Multer upload error:", err);
                return reject(err);
            }
            resolve();
        });
    });

    if (!req.file) {
        return res.status(400).send('No encrypted image file uploaded.');
    }

    // Access IV and originalMimeType from req.body (form fields)
    const iv = req.body.iv;
    const originalMimeType = req.body.originalMimeType; // Sent from frontend

    if (!iv || !originalMimeType) {
        return res.status(400).send('Decryption IV or Original MIME Type is missing.');
    }

    try {
        // The uploaded file (`req.file.buffer`) is the "noisy" PNG created by the frontend.
        // We need to extract the raw encrypted data from its pixels.
        const uploadedEncryptedJimpImage = await Jimp.read(req.file.buffer);

        // Extract the "encrypted data" (pixels) from the image as a buffer
        let extractedEncryptedDataBuffer = Buffer.alloc(uploadedEncryptedJimpImage.bitmap.data.length);
        for (let i = 0; i < uploadedEncryptedJimpImage.bitmap.data.length; i++) {
            extractedEncryptedDataBuffer[i] = uploadedEncryptedJimpImage.bitmap.data[i];
        }
        const extractedEncryptedDataHex = extractedEncryptedDataBuffer.toString('hex');

        // Decrypt the extracted data
        const decryptedImageBuffer = decrypt(extractedEncryptedDataHex, iv);

        // Convert the decrypted buffer back to a Base64 string for display on the frontend
        const base64DecryptedImage = `data:${originalMimeType};base64,${decryptedImageBuffer.toString('base64')}`;

        res.status(200).json({ decryptedImageData: base64DecryptedImage });

    } catch (error) {
        console.error('Decryption processing error:', error);
        res.status(500).send(`Error decrypting image: ${error.message}. Please ensure the correct IV and MIME type were provided.`);
    }
};
