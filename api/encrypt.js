// api/encrypt.js
const multer = require('multer');
const crypto = require('crypto');
const Jimp = require('jimp');

// Use memory storage for Multer as Vercel Functions are stateless
const upload = multer({ storage: multer.memoryStorage() });

// --- CORS Configuration ---
// Define your allowed origins. Replace with your actual cPanel domain(s).
const ALLOWED_ORIGINS = [
    'https://yourdomain.com', // Replace with your actual frontend domain
    'http://yourdomain.com',
    'https://www.yourdomain.com',
    // For local testing of your frontend pointing to Vercel dev:
    // 'http://localhost:3000', // Example if your local frontend runs on this port
    // 'http://localhost:8080' // Another common local port
];

// --- Secret Key Management ---
// IMPORTANT: Access from Vercel's environment variables
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) { // AES-256 requires 32 bytes = 64 hex chars
    console.error("ERROR: ENCRYPTION_KEY is not set or is not 64 hexadecimal characters long.");
    // In a production environment, you might want to return an error here or make the deployment fail.
    // For local `vercel dev`, this warning is fine.
}
// Convert hex string to Buffer for cryptographic operations
const KEY_BUFFER = ENCRYPTION_KEY ? Buffer.from(ENCRYPTION_KEY, 'hex') : Buffer.alloc(32, 0); // Fallback for dev

// --- AES Utility Functions ---
const ALGORITHM = 'aes-256-cbc'; // AES 256-bit in CBC mode

function encrypt(buffer) {
    if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
        throw new Error("Encryption key is not properly configured.");
    }
    const iv = crypto.randomBytes(16); // IV must be unique for each encryption
    const cipher = crypto.createCipheriv(ALGORITHM, KEY_BUFFER, iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    // Return IV as hex and encrypted data as hex string
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

// Vercel Serverless Function entry point
module.exports = async (req, res) => {
    // 1. Handle CORS Preflight (OPTIONS requests)
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS'); // Only allow POST for actual requests, OPTIONS for preflight
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type'); // Allow the Content-Type header (for form data)

    if (req.method === 'OPTIONS') {
        return res.status(200).end(); // Respond to preflight requests
    }

    // 2. Ensure it's a POST request
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    // 3. Process file upload using Multer
    await new Promise((resolve, reject) => {
        upload.single('image')(req, res, (err) => {
            if (err) {
                console.error("Multer upload error:", err);
                return reject(err);
            }
            resolve();
        });
    });

    if (!req.file) {
        return res.status(400).send('No image file uploaded.');
    }

    try {
        const imageBuffer = req.file.buffer; // Image data from memory
        const originalFileName = req.file.originalname;
        const originalMimeType = req.file.mimetype;

        // Perform encryption
        const { iv, encryptedData } = encrypt(imageBuffer);

        // Send back the necessary data to the frontend
        res.status(200).json({
            encryptedData: encryptedData,       // Hex string of the encrypted binary data
            iv: iv,                             // Hex string of the IV
            originalFileName: originalFileName, // Original name for client-side download naming
            originalMimeType: originalMimeType  // Original MIME type for client-side decryption
        });

    } catch (error) {
        console.error('Encryption processing error:', error);
        res.status(500).send(`Error during encryption: ${error.message}`);
    }
};
