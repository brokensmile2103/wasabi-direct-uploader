<?php
/**
 * ============================================================
 * Wasabi Direct Uploader – Self-Hosted Presigned Upload Tool
 * ============================================================
 * 
 * Description:
 * PHP-based one-file uploader for directly uploading files
 * to Wasabi (or any S3-compatible storage) using presigned URLs.
 * Fully client-side PUT upload – no SDK required.
 * 
 * Features:
 * - Simple login authentication (session-based)
 * - Direct upload to Wasabi with Presigned PUT URLs
 * - Drag & drop multiple files, with total progress tracking
 * - Natural sort output with multiple formats:
 *   → Plain URLs, HTML <img>/<a>/<video>, Markdown, BBCode, or custom template
 * - Optional CDN base URL override
 * - Configurable prefix/date folders, filename normalization
 * - Supports MIME filtering, lowercase normalization, and random prefixing
 * - Auto-generates signed URLs using AWS Signature v4
 * 
 * System Requirements:
 * - PHP >= 7.4 (recommended PHP 8.0+)
 * - Extensions: hash, json, openssl, mbstring
 * - HTTPS enabled (strongly recommended)
 * - Correct Wasabi CORS policy allowing PUT/GET from your origin
 * 
 * Usage:
 * 1. Fill in REGION, BUCKET, ACCESS KEY, and SECRET KEY in CONFIG section
 * 2. (Optional) Set CDN_BASE if using a CDN proxy domain
 * 3. Set USERNAME & PASSWORD for login below
 * 4. Serve this file over HTTPS
 * 5. Login → drag files → get Wasabi URLs, HTML, or Markdown ready
 * 
 * Example CORS Configuration (Wasabi bucket):
 *   AllowedOrigins: [https://yourdomain.com]
 *   AllowedMethods: [PUT, GET, HEAD]
 *   AllowedHeaders: ["*"]
 *   ExposeHeaders:  ["ETag"]
 *   MaxAgeSeconds:  3000
 * 
 * Developed by: Init HTML
 * Website: https://inithtml.com
 * Version: 1.2.1
 * Updated: 2025-12-02
 * 
 * ============================================================
 */

session_start();

/* ========================= WASABI CONFIG =========================
 * REGION: e.g. "ap-southeast-1" or "us-east-1"
 * BUCKET: your Wasabi bucket name (dots allowed; tool auto switches to path-style)
 * ACCESS KEY / SECRET KEY: your Wasabi keys
 * CDN_BASE: optional, e.g. "https://cdn.example.com" (leave empty to use Wasabi URLs)
 * EXPIRES_SECONDS: presigned URL lifetime, e.g. 3600 (1h)
 * ALLOW_MIME: [] = allow all types; or restrict like ['image/jpeg','image/png']
 * FORCE_LOWERCASE: normalize filenames to lowercase
 * ADD_RANDOM_PREFIX: add 12-hex prefix to reduce collisions
 */
$WASABI_REGION       = '';                 // e.g. 'ap-southeast-1'
$WASABI_BUCKET       = '';                 // e.g. 'my.bucket.name'
$AWS_ACCESS_KEY      = '';                 // e.g. 'AKIA...'
$AWS_SECRET_KEY      = '';                 // e.g. 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY...'
$CDN_BASE            = '';                 // e.g. 'https://cdn.example.com' or leave empty
$EXPIRES_SECONDS     = 3600;               // default 3600 seconds
$ALLOW_MIME          = [];                 // [] = allow all
$FORCE_LOWERCASE     = true;               // force lowercase filenames
$ADD_RANDOM_PREFIX   = true;               // add random 12-hex prefix
/* ===================================================================== */

/* ========================= LOGIN CONFIG =========================
 * USERNAME / PASSWORD:
 * - PASSWORD có thể là plain text hoặc password_hash()
 * - Nếu là hash, script tự dùng password_verify()
 * - Nếu là plain, dùng hash_equals() để tránh timing attack
 */
define('USERNAME', 'admin');     // Đổi username sau khi up!
define('PASSWORD', 'Admin@123'); // Có thể dùng password_hash() luôn cho chắc

// Simple login rate limiting: max 5 failed attempts per IP per 5 minutes
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5;
const LOGIN_RATE_LIMIT_WINDOW       = 300; // seconds
/* ================================================================ */

function get_login_rate_limit_key(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return 'wasabi_login_attempts_' . md5($ip);
}

function check_login_rate_limit(): bool {
    $key = get_login_rate_limit_key();

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'time' => time()];
        return true;
    }

    $data = $_SESSION[$key];

    // Reset sau khi hết cửa sổ 5 phút
    if (time() - $data['time'] > LOGIN_RATE_LIMIT_WINDOW) {
        $_SESSION[$key] = ['count' => 0, 'time' => time()];
        return true;
    }

    // Block nếu vượt quá số lần cho phép
    if ($data['count'] >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS) {
        return false;
    }

    return true;
}

function increment_login_attempts(): void {
    $key = get_login_rate_limit_key();

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'time' => time()];
    }

    $_SESSION[$key]['count']++;
}

function reset_login_attempts(): void {
    $key = get_login_rate_limit_key();
    unset($_SESSION[$key]);
}

// Helper: detect if stored PASSWORD is plain text or password_hash
function verify_password_login(string $inputPassword): bool {
    $stored = PASSWORD;

    // Nếu PASSWORD là hash (tạo bởi password_hash())
    $info = password_get_info($stored);
    if (!empty($info['algo'])) {
        return password_verify($inputPassword, $stored);
    }

    // Nếu PASSWORD là plain text (dùng hash_equals để tránh timing attack)
    return hash_equals($stored, $inputPassword);
}

// Handle login (with simple rate limit)
if (isset($_POST['login'])) {
    // Check rate limit trước
    if (!check_login_rate_limit()) {
        $error = 'Too many failed login attempts. Please wait 5 minutes and try again.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($username === USERNAME && verify_password_login($password)) {
            $_SESSION['logged_in'] = true;

            // Đăng nhập thành công => reset counter
            reset_login_attempts();
        } else {
            // Đăng nhập sai => tăng số lần thử
            increment_login_attempts();
            $error = 'Invalid username or password!';
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

$is_authed = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

function hmacb($k, $d) { return hash_hmac('sha256', $d, $k, true); }

function sigv4_key($secret, $date, $region, $service = 's3') {
    $k = hmacb('AWS4' . $secret, $date);
    $k = hmacb($k, $region);
    $k = hmacb($k, $service);
    return hmacb($k, 'aws4_request');
}

function iso8601Z($t) { return gmdate('Ymd\THis\Z', $t); }

function sanitize_slug($name, $lower = true) {
    $base = pathinfo($name, PATHINFO_FILENAME);
    $ext  = pathinfo($name, PATHINFO_EXTENSION);
    $base = @iconv('UTF-8', 'ASCII//TRANSLIT', $base);
    $base = preg_replace('~[^A-Za-z0-9_.-]+~', '-', $base);
    $base = preg_replace('~-{2,}~', '-', $base);
    $base = trim($base, '-.');
    if ($lower) {
        $base = strtolower($base);
        $ext  = strtolower($ext);
    }
    $base = $base ?: 'file';
    return [$base, $ext];
}

/**
 * Build public URL (respect CDN if set).
 * If CDN_BASE is empty, uses Wasabi. For buckets with dots, switch to path-style.
 */
function public_url($key) {
    global $WASABI_REGION, $WASABI_BUCKET, $CDN_BASE;
    $key = ltrim($key, '/');

    if ($CDN_BASE) {
        return rtrim($CDN_BASE, '/') . '/' . $key;
    }

    $host   = ($WASABI_REGION === 'us-east-1') ? 's3.wasabisys.com' : "s3.$WASABI_REGION.wasabisys.com";
    $hasDot = strpos($WASABI_BUCKET, '.') !== false;

    if ($hasDot) {
        // path-style: https://s3.region.wasabisys.com/bucket.name/key
        return 'https://' . $host . '/' . rawurlencode($WASABI_BUCKET) . '/' . str_replace('%2F', '/', rawurlencode($key));
    }

    // virtual-host: https://bucket.s3.region.wasabisys.com/key
    return 'https://' . $WASABI_BUCKET . '.' . $host . '/' . str_replace('%2F', '/', rawurlencode($key));
}

/* ===== Presign API ===== */
if (isset($_GET['action']) && $_GET['action'] === 'presign') {
    header('Content-Type: application/json; charset=utf-8');

    // Chặn API nếu chưa login
    if (!$is_authed) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    try {
        global $WASABI_REGION, $WASABI_BUCKET, $AWS_ACCESS_KEY, $AWS_SECRET_KEY, $EXPIRES_SECONDS, $ALLOW_MIME, $FORCE_LOWERCASE, $ADD_RANDOM_PREFIX;

        if (!$WASABI_REGION || !$WASABI_BUCKET || !$AWS_ACCESS_KEY || !$AWS_SECRET_KEY) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing CONFIG. Please fill REGION/BUCKET/ACCESS KEY/SECRET KEY.']);
            exit;
        }

        // Inputs
        $prefix     = (string)($_POST['prefix'] ?? 'uploads');
        $use_date   = ($_POST['use_date'] ?? '1') === '1';
        $keep_name  = ($_POST['keep_name'] ?? '0') === '1';
        $lowercase  = ($_POST['lowercase'] ?? ($FORCE_LOWERCASE ? '1' : '0')) === '1';
        $tpl        = (string)($_POST['tpl'] ?? '{url}');
        $files      = json_decode($_POST['files'] ?? '[]', true);

        if (!is_array($files) || !$files) {
            http_response_code(400);
            echo json_encode(['error' => 'No files payload.']);
            exit;
        }

        // Normalize prefix to clean path "a/b/c"
        $prefix = trim($prefix);
        $prefix = trim($prefix, "/ \t\n\r\0\x0B");
        $prefix = $prefix === '' ? '' : preg_replace('~[\\/]+~', '/', $prefix);

        // Endpoint + addressing mode
        $host_core      = ($WASABI_REGION === 'us-east-1') ? 's3.wasabisys.com' : "s3.$WASABI_REGION.wasabisys.com";
        $bucket_has_dot = strpos($WASABI_BUCKET, '.') !== false;

        $endpoint_h     = $bucket_has_dot ? $host_core : ($WASABI_BUCKET . '.' . $host_core);
        $url_base       = 'https://' . $endpoint_h;

        $now            = time();
        $amzdate        = iso8601Z($now);
        $date           = gmdate('Ymd', $now);
        $service        = 's3';
        $scope          = "$date/$WASABI_REGION/$service/aws4_request";
        $algo           = 'AWS4-HMAC-SHA256';
        $signed_headers = 'host';
        $payload_hash   = 'UNSIGNED-PAYLOAD';
        $date_path      = $use_date ? gmdate('Y/m/d', $now) : '';

        // Natural sort by name
        usort($files, fn($a, $b) => strnatcasecmp($a['name'] ?? '', $b['name'] ?? ''));

        $out     = [];
        $signKey = sigv4_key($AWS_SECRET_KEY, $date, $WASABI_REGION, $service);

        foreach ($files as $idx => $f) {
            $orig = (string)($f['name'] ?? 'file');
            $mime = (string)($f['mime'] ?? 'application/octet-stream');

            if ($ALLOW_MIME && !in_array($mime, $ALLOW_MIME, true)) {
                http_response_code(400);
                echo json_encode(['error' => 'Unsupported mime type: ' . $mime]);
                exit;
            }

            if ($keep_name) {
                $base = pathinfo($orig, PATHINFO_FILENAME);
                $ext  = pathinfo($orig, PATHINFO_EXTENSION);
                if ($lowercase) {
                    $base = strtolower($base);
                    $ext  = strtolower($ext);
                }
                $base = trim($base) !== '' ? $base : 'file';
            } else {
                [$base, $ext] = sanitize_slug($orig, $lowercase);
            }

            $ext  = $ext ?: trim(pathinfo($orig, PATHINFO_EXTENSION)) ?: 'bin';
            $rand = $ADD_RANDOM_PREFIX ? (bin2hex(random_bytes(6)) . '-') : '';

            $parts = array_filter([$prefix, $date_path], fn($s) => $s !== '');
            $dir   = implode('/', $parts);
            $dir   = $dir === '' ? '' : ($dir . '/');

            $key = $dir . $rand . $base . '.' . $ext;

            // Query params (sorted)
            $params = [
                'X-Amz-Algorithm'      => $algo,
                'X-Amz-Credential'     => $AWS_ACCESS_KEY . '/' . $scope,
                'X-Amz-Date'           => $amzdate,
                'X-Amz-Expires'        => (string)$EXPIRES_SECONDS,
                'X-Amz-SignedHeaders'  => $signed_headers,
                'X-Amz-Content-Sha256' => $payload_hash
            ];
            ksort($params, SORT_STRING);

            // Canonical URI (path-style when bucket has dot)
            $key_enc = str_replace('%2F', '/', rawurlencode($key));
            if ($bucket_has_dot) {
                $canonical_uri = '/' . rawurlencode($WASABI_BUCKET) . '/' . $key_enc;
            } else {
                $canonical_uri = '/' . $key_enc;
            }

            $canonical_query   = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
            $canonical_headers = 'host:' . $endpoint_h . "\n";
            $canonical_req     = "PUT\n{$canonical_uri}\n{$canonical_query}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";
            $string_to_sign    = "$algo\n$amzdate\n$scope\n" . hash('sha256', $canonical_req);
            $signature         = hash_hmac('sha256', $string_to_sign, $signKey);

            $put_url = $url_base . $canonical_uri . '?' . $canonical_query . '&X-Amz-Signature=' . $signature;

            $out[] = [
                'put_url'   => $put_url,
                'final_url' => public_url($key),
                'headers'   => ['Content-Type' => $mime],
                'name'      => $orig,
                'order'     => $idx + 1,
                'tpl'       => $tpl
            ];
        }

        echo json_encode(['ok' => true, 'items' => $out]);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Unexpected']);
    }
    exit;
}

if (!$is_authed) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Wasabi Direct Uploader - Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #020617 100%);min-height: 100vh;display: flex;align-items: center;justify-content: center;color: #e5e7eb}
            .login-box {background: #020617;padding: 32px 28px;border-radius: 16px;box-shadow: 0 20px 60px rgba(0,0,0,0.6);width: 100%;max-width: 380px;border: 1px solid #1f2937}
            h2 {margin-bottom: 20px;color: #e5e7eb;text-align: center;font-size: 22px}
            .sub {text-align: center;font-size: 13px;color: #9ca3af;margin-bottom: 20px}
            .form-group {margin-bottom: 18px}
            label {display: block;margin-bottom: 6px;color: #9ca3af;font-size: 13px;font-weight: 500}
            input[type="text"],input[type="password"] {width: 100%;padding: 11px 12px;border-radius: 9px;border: 1px solid #374151;background: #020617;color: #e5e7eb;font-size: 14px;transition: border-color 0.2s, box-shadow 0.2s, background 0.2s}
            input[type="text"]:focus,input[type="password"]:focus {outline: none;border-color: #60a5fa;box-shadow: 0 0 0 1px rgba(96,165,250,0.4);background: #020617}
            .btn {width: 100%;padding: 12px;background: linear-gradient(135deg, #60a5fa 0%, #2563eb 100%);color: #0b1120;border: none;border-radius: 9px;font-size: 15px;font-weight: 600;cursor: pointer;transition: transform 0.15s, box-shadow 0.15s, opacity 0.15s}
            .btn:hover {transform: translateY(-1px);box-shadow: 0 10px 25px rgba(37, 99, 235, 0.45)}
            .error {background: rgba(220, 38, 38, 0.08);border: 1px solid rgba(239, 68, 68, 0.6);color: #fecaca;padding: 10px 12px;border-radius: 8px;margin-bottom: 16px;font-size: 13px;text-align: center}
            .brand {text-align: center;margin-top: 18px;font-size: 12px;color: #6b7280}
            .brand a {color: #e5e7eb;text-decoration: none}
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Wasabi Direct Uploader</h2>
            <div class="sub">Sign in to use the presigned upload tool</div>
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Enter username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Enter password" required>
                </div>
                <button type="submit" name="login" class="btn">Login</button>
            </form>
            <div class="brand">
                &copy; <?php echo date('Y'); ?> <a href="https://inithtml.com/" target="_blank" rel="noopener">Init HTML</a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Wasabi Direct Uploader → URLs / HTML / Markdown</title>
    <style>
        :root{--bg:#0b0f14;--panel:#0f1622;--text:#e5e7eb;--muted:#9aa4b2;--line:#1e293b;--acc:#60a5fa}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui}
        .wrap{max-width:960px;margin:32px auto;padding:0 16px}
        header{margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;gap:10px}
        header h1{font-size:22px;margin:0}
        header p{color:var(--muted);margin:6px 0 0;font-size:13px}
        .logout-link{font-size:13px;color:var(--muted);text-decoration:none;padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:rgba(15,23,42,0.9)}
        .logout-link:hover{border-color:var(--acc);color:var(--text)}
        .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px}
        .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
        label.small{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}
        input[type=text], select{width:100%;background:#0b0f14;color:var(--text);border:1px solid #223;border-radius:10px;padding:10px}
        input[type=checkbox]{transform:translateY(1px)}
        .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
        .dz{border:2px dashed #334155;border-radius:14px;padding:22px;text-align:center}
        .btn{background:var(--acc);color:#06131f;border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer}
        .btn[disabled]{opacity:.6;cursor:not-allowed}
        .muted{color:var(--muted)}
        .progress{height:10px;background:#0e1522;border-radius:999px;overflow:hidden}
        .progress i{display:block;height:100%;width:0;background:var(--acc)}
        textarea{width:100%;min-height:240px;background:#0b0f14;color:var(--text);border:1px solid #223;border-radius:10px;padding:12px;font-family:ui-monospace,Consolas,Monaco,Menlo,monospace}
        footer{color:var(--muted);font-size:12px;text-align:center;margin:14px 0}
        .help{font-size:12px;color:var(--muted)}
        a{color:var(--acc)}
    </style>
</head>
<body>
    <div class="wrap">
        <header>
            <div>
                <h1>Wasabi Direct Uploader → URLs / HTML / Markdown</h1>
                <p class="muted">Drag & drop files → Upload → Export list of URL/HTML/Markdown (batch, natural order).</p>
            </div>
            <a href="?logout=1" class="logout-link">Logout</a>
        </header>

        <section class="card">
            <div class="grid3">
                <div>
                    <label class="small">Key prefix (root directory)</label>
                    <input id="prefix" type="text" placeholder="e.g., uploads/project-a">
                </div>
                <div>
                    <label class="small">Output format</label>
                    <select id="fmt">
                        <option value="plain">Plain URLs</option>
                        <option value="html-img">HTML &lt;img&gt;</option>
                        <option value="html-a">HTML &lt;a&gt; link</option>
                        <option value="html-video">HTML &lt;video&gt;</option>
                        <option value="md-img">Markdown Image</option>
                        <option value="md-link">Markdown Link</option>
                        <option value="bb-img">BBCode [img]</option>
                        <option value="custom">Custom template</option>
                    </select>
                </div>
                <div>
                    <label class="small">Template (for Custom)</label>
                    <input id="tpl" type="text" placeholder="{url}  |  name:{name}  |  ext:{ext}">
                    <div class="help">{url} {name} {base} {ext} {i}</div>
                </div>
            </div>
            <div style="height:10px"></div>
            <div class="row">
                <label><input id="useDate" type="checkbox" checked> Append date folders (Y/m/d)</label>
                <label><input id="keepName" type="checkbox"> Keep original file name</label>
                <label><input id="lowercase" type="checkbox" checked> Lowercase</label>
            </div>
            <div style="height:10px"></div>
            <div id="dz" class="dz">
                <p><b>Drag & drop</b> files here or <label class="btn"><input id="pick" type="file" multiple hidden>Choose files</label></p>
                <p class="muted">Supports all file types (you can restrict in CONFIG).</p>
            </div>
            <div style="height:10px"></div>
            <div class="row">
                <button id="start" class="btn" disabled>Upload</button>
                <span id="selInfo" class="muted">No file selected</span>
            </div>
        </section>

        <section class="card">
            <div class="row" style="margin-bottom:8px">
                <div class="progress" style="flex:1"><i id="bar"></i></div>
                <span id="stat" class="muted">0%</span>
            </div>
            <div class="row">
                <button id="copyAll" class="btn" disabled>Copy all</button>
                <span id="count" class="muted">0 file</span>
            </div>
            <div style="height:8px"></div>
            <textarea id="out" spellcheck="false" placeholder="Output will appear here..."></textarea>
        </section>

        <p class="help">
            Wasabi CORS suggestion (Bucket → CORS): allow PUT/GET from this origin.<br>
            Methods: PUT, GET, HEAD | AllowedHeaders: * | ExposeHeaders: ETag | MaxAgeSeconds: 3000
        </p>

        <footer>&copy; <a href="https://inithtml.com/" style="text-decoration: none; color: #fff;">Init HTML</a></footer>
    </div>

    <script>
    (() => {
        // ===== CONFIG FROM PHP =====
        const ALLOW     = <?php echo json_encode($ALLOW_MIME); ?>;

        // ===== DOM =====
        const dz        = document.getElementById('dz');
        const pick      = document.getElementById('pick');
        const start     = document.getElementById('start');
        const selInfo   = document.getElementById('selInfo');
        const bar       = document.getElementById('bar');
        const stat      = document.getElementById('stat');
        const out       = document.getElementById('out');
        const count     = document.getElementById('count');
        const copyAll   = document.getElementById('copyAll');

        const prefix    = document.getElementById('prefix');
        const fmt       = document.getElementById('fmt');
        const tpl       = document.getElementById('tpl');
        const useDate   = document.getElementById('useDate');
        const keepName  = document.getElementById('keepName');
        const lowercase = document.getElementById('lowercase');

        // ===== STATE =====
        let chosen = [];
        const dimsMap = new Map(); // File -> {w,h} | null

        // ===== HELPERS =====
        function humanSort(files) {
            return files.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
        }

        function info() {
            if (!chosen.length) {
                selInfo.textContent = 'No file selected';
                start.disabled = true;
                return;
            }
            selInfo.textContent = chosen.length + ' file(s) selected';
            start.disabled = false;
        }

        function setProgress(p) {
            const clamped = Math.max(0, Math.min(100, p));
            bar.style.width = clamped + '%';
            stat.textContent = Math.round(clamped) + '%';
        }

        function setCount(n) {
            count.textContent = n + ' file' + (n !== 1 ? 's' : '');
            copyAll.disabled = n === 0;
        }

        function addFiles(fs) {
            const arr = Array.from(fs).filter(f => {
                if (!ALLOW || !ALLOW.length) return true;
                return ALLOW.includes(f.type);
            });
            if (!arr.length) return;
            chosen = humanSort(arr);
            info();
        }

        // --- Sniff media dimensions (NEW) ---
        function sniffImageDims(file) {
            return new Promise((resolve) => {
                const url = URL.createObjectURL(file);
                const img = new Image();
                img.onload = () => {
                    resolve({ w: img.naturalWidth, h: img.naturalHeight });
                    URL.revokeObjectURL(url);
                };
                img.onerror = () => { resolve(null); URL.revokeObjectURL(url); };
                img.src = url;
            });
        }

        function sniffVideoDims(file) {
            return new Promise((resolve) => {
                const url = URL.createObjectURL(file);
                const v = document.createElement('video');
                v.preload = 'metadata';
                v.onloadedmetadata = () => {
                    resolve({ w: v.videoWidth || null, h: v.videoHeight || null });
                    URL.revokeObjectURL(url);
                };
                v.onerror = () => { resolve(null); URL.revokeObjectURL(url); };
                v.src = url;
            });
        }

        async function sniffDims(file) {
            try {
                if (file.type?.startsWith('image/')) return await sniffImageDims(file);
                if (file.type?.startsWith('video/')) return await sniffVideoDims(file);
            } catch (_) {}
            return null;
        }

        // Build one output line (patched to include width/height for HTML)
        function buildLine(format, url, f, idx, customTpl) {
            const name = f.name || '';
            const base = name.replace(/\.[^.]*$/, '');
            const ext  = (name.split('.').pop() || '').toLowerCase();
            const i    = idx + 1;
            const dims = dimsMap.get(f) || null; // {w,h} | null
            const wh   = (dims && dims.w && dims.h) ? ` width="${dims.w}" height="${dims.h}"` : '';

            switch (format) {
                case 'plain':
                    return url;
                case 'html-img':
                    return `<img src="${url}" alt="${base}" loading="lazy" decoding="async"${wh}>`;
                case 'html-a':
                    return `<a href="${url}" target="_blank" rel="noopener">${name}</a>`;
                case 'html-video':
                    return `<video src="${url}" controls preload="metadata"${wh}></video>`;
                case 'md-img':
                    return `![${base}](${url})`;
                case 'md-link':
                    return `[${name}](${url})`;
                case 'bb-img':
                    return `[img]${url}[/img]`;
                case 'custom':
                    return (customTpl || '{url}')
                        .replaceAll('{url}', url)
                        .replaceAll('{name}', name)
                        .replaceAll('{base}', base)
                        .replaceAll('{ext}', ext)
                        .replaceAll('{i}', String(i));
                default:
                    return url;
            }
        }

        async function presignBatch(files) {
            const payload = {
                prefix:    prefix.value.trim(),
                use_date:  useDate.checked ? '1' : '0',
                keep_name: keepName.checked ? '1' : '0',
                lowercase: lowercase.checked ? '1' : '0',
                tpl:       tpl.value.trim(),
                files:     JSON.stringify(files.map(f => ({ name: f.name, mime: f.type })))
            };
            const u = new URL(location.href);
            u.searchParams.set('action', 'presign');
            const res = await fetch(u, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(payload)
            });
            if (!res.ok) throw new Error(await res.text());
            return res.json();
        }

        async function uploadAll() {
            if (!chosen.length) return;
            out.value = '';
            setCount(0);
            setProgress(0);

            // NEW: sniff kích thước trước để build HTML có width/height
            const dimsArr = await Promise.all(chosen.map(sniffDims));
            dimsArr.forEach((d, idx) => dimsMap.set(chosen[idx], d));

            const ps = await presignBatch(chosen);
            const items = ps.items; // aligned với chosen

            const totalBytes = chosen.reduce((s, f) => s + f.size, 0) || 1;
            let sent = 0;
            let doneCount = 0;

            // Upload tuần tự để giữ thứ tự output + tính progress đơn giản
            for (let i = 0; i < items.length; i++) {
                const file = chosen[i];
                const item = items[i];

                await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            const delta = e.loaded - (xhr._last || 0);
                            xhr._last = e.loaded;
                            sent += Math.max(0, delta);
                            setProgress((sent / totalBytes) * 100);
                        }
                    };
                    xhr.onreadystatechange = () => {
                        if (xhr.readyState === 4) {
                            if (xhr.status >= 200 && xhr.status < 300) resolve();
                            else reject(new Error('Upload failed ' + xhr.status));
                        }
                    };
                    xhr.open('PUT', item.put_url, true);
                    xhr.setRequestHeader('Content-Type', item.headers['Content-Type']);
                    xhr.send(file);
                });

                doneCount++;
                const line = buildLine(fmt.value, item.final_url, file, i, tpl.value.trim());
                out.value += line + "\n";
                setCount(doneCount);
            }

            setProgress(100);
        }

        // ===== EVENTS =====
        pick.addEventListener('change', (e) => { addFiles(e.target.files); e.target.value = ''; });

        ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, (e) => {
            e.preventDefault(); dz.style.background = '#0a1120';
        }));
        ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, (e) => {
            e.preventDefault(); dz.style.background = '';
        }));
        dz.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));

        start.addEventListener('click', () => {
            if (!chosen.length) { alert('Please choose files first.'); return; }
            uploadAll().catch(err => alert(err.message));
        });

        copyAll.addEventListener('click', () => {
            if (!out.value) return;
            navigator.clipboard.writeText(out.value);
            copyAll.textContent = 'Copied';
            setTimeout(() => copyAll.textContent = 'Copy all', 900);
        });
    })();
    </script>
</body>
</html>
