<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: '';
$initialPassword = getenv('DVWA_LAB_PASSWORD') ?: '';
if ($user === '' || $initialPassword === '') {
    fwrite(STDERR, "Set sandbox-only DVWA_LAB_USER and DVWA_LAB_PASSWORD.\n");
    exit(2);
}

function requestPage($c, string $url, ?array $fields = null): array
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
        throw new RuntimeException('user_token missing from secure form');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function resetDb(string $base): void
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-csrf-fixed-setup-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-csrf-test/1.0',
    ]);
    try {
        [$setup] = requestPage($c, $base . '/setup.php');
        [, $status] = requestPage($c, $base . '/setup.php', [
            'create_db' => 'Create / Reset Database',
            'user_token' => tokenFrom($setup),
        ]);
        if ($status !== 200) {
            throw new RuntimeException('Isolated DB reset failed');
        }
    } finally {
        @unlink($jar);
    }
}

function loginSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-csrf-fixed-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-csrf-test/1.0',
    ]);
    try {
        [$page] = requestPage($c, $base . '/login.php');
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => tokenFrom($page),
        ]);
        if ($status !== 200 || stripos($body, 'Login failed') !== false || str_contains($url, 'login.php')) {
            throw new RuntimeException('DVWA login failed');
        }
        foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
            $parts = explode("\t", $line);
            if (count($parts) >= 7 && $parts[5] === 'PHPSESSID' && preg_match('/^[A-Za-z0-9,-]+$/', $parts[6])) {
                return $parts[6];
            }
        }
        throw new RuntimeException('Authenticated session cookie not found');
    } finally {
        @unlink($jar);
    }
}

function moduleToken(string $base, string $sessionId, string $level): string
{
    $c = curl_init($base . '/vulnerabilities/csrf/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-csrf-test/1.0',
    ]);
    $page = curl_exec($c);
    if ($page === false || (int)curl_getinfo($c, CURLINFO_HTTP_CODE) !== 200) {
        throw new RuntimeException(strtoupper($level) . ' patched CSRF page failed');
    }
    return tokenFrom($page);
}

function changePassword(string $base, string $sessionId, string $level, string $method, array $fields, bool $crossSite): array
{
    $url = $base . '/vulnerabilities/csrf/';
    $headers = [];
    if ($crossSite) {
        $headers = ['Origin: http://attacker.invalid', 'Referer: http://attacker.invalid/csrf.html'];
    }
    if ($method === 'GET') {
        $url .= '?' . http_build_query($fields);
    }
    $c = curl_init($url);
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-csrf-test/1.0',
        CURLOPT_HTTPHEADER => $headers,
    ]);
    if ($method === 'POST') {
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query($fields));
    }
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' change request failed: ' . curl_error($c));
    }
    return [$body, (int)curl_getinfo($c, CURLINFO_HTTP_CODE)];
}

function loginWorks(string $base, string $user, string $password): bool
{
    try {
        loginSession($base, $user, $password);
        return true;
    } catch (Throwable $e) {
        return false;
    }
}

foreach (['low', 'medium', 'high'] as $level) {
    resetDb($base);
    $sessionId = loginSession($base, $user, $initialPassword);
    $attackPassword = 'Sandbox-CSRF-Attempt-' . $level . '-' . bin2hex(random_bytes(8));
    $fields = [
        'password_current' => $initialPassword,
        'password_new' => $attackPassword,
        'password_conf' => $attackPassword,
        'Change' => 'Change',
    ];

    [$getBody] = changePassword($base, $sessionId, $level, 'GET', $fields, true);
    $getChanged = loginWorks($base, $user, $attackPassword);
    if (loginWorks($base, $user, $initialPassword) === false) {
        throw new RuntimeException(strtoupper($level) . ' GET probe left unexpected password state');
    }
    if ($getChanged) {
        throw new RuntimeException(strtoupper($level) . ' cross-site GET changed password after patch');
    }

    $token = moduleToken($base, $sessionId, $level);
    [$postBody] = changePassword($base, $sessionId, $level, 'POST', $fields, true);
    $postChanged = loginWorks($base, $user, $attackPassword);
    $oldStillWorks = loginWorks($base, $user, $initialPassword);
    if ($postChanged || !$oldStillWorks) {
        throw new RuntimeException(strtoupper($level) . ' missing-token POST changed password');
    }
    echo strtoupper($level) . ' cross-site GET changed=false; missing-token POST changed=false; original_password_valid=true' . "\n";

    $token = moduleToken($base, $sessionId, $level);
    $legitPassword = 'Sandbox-CSRF-Legit-' . $level . '-' . bin2hex(random_bytes(8));
    [$legitBody] = changePassword($base, $sessionId, $level, 'POST', [
        'password_current' => $initialPassword,
        'password_new' => $legitPassword,
        'password_conf' => $legitPassword,
        'Change' => 'Change',
        'user_token' => $token,
    ], false);
    $legitWorks = loginWorks($base, $user, $legitPassword);
    $oldAfterLegit = loginWorks($base, $user, $initialPassword);
    echo strtoupper($level) . ' valid_token_and_current_password=' . (strpos($legitBody, 'Password Changed.') !== false ? 'accepted' : 'not-accepted')
        . '; new_password_login=' . ($legitWorks ? 'true' : 'false') . '; old_password_login=' . ($oldAfterLegit ? 'true' : 'false') . "\n";
    if (!$legitWorks || $oldAfterLegit) {
        throw new RuntimeException(strtoupper($level) . ' legitimate form regression failed');
    }
    echo strtoupper($level) . "_PATCH_CSRF_AND_LEGIT_FLOW_CONFIRMED\n";
}
