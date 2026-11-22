<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: 'admin';
$initialPassword = getenv('DVWA_LAB_INITIAL_PASSWORD') ?: '';
$attackPassword = getenv('DVWA_LAB_ATTACK_PASSWORD') ?: '';
if ($initialPassword === '' || $attackPassword === '') {
    fwrite(STDERR, "Set sandbox-only initial and attack passwords.\n");
    exit(2);
}

function req($c, string $url, ?array $fields = null): array
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

function tokenIn(string $body): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $body, $m)) {
        throw new RuntimeException('user_token missing');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function loginOk(string $base, string $user, string $password): bool
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-check-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fix-check/1.0',
    ]);
    try {
        [$page] = req($c, $base . '/login.php');
        [$body, $status, $url] = req($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => tokenIn($page),
        ]);
        return $status === 200 && stripos($body, 'Login failed') === false && !str_contains($url, 'login.php');
    } finally {
        @unlink($jar);
    }
}

$jar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-setup-');
$c = curl_init();
curl_setopt_array($c, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_TIMEOUT => 12,
    CURLOPT_COOKIEFILE => $jar,
    CURLOPT_COOKIEJAR => $jar,
    CURLOPT_USERAGENT => 'DVWA-isolated-fix-check/1.0',
]);
try {
    [$setup] = req($c, $base . '/setup.php');
    [, $setupStatus] = req($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => tokenIn($setup),
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Sandbox database reset failed');
    }

    [$loginPage] = req($c, $base . '/login.php');
    [$loginBody, $loginStatus, $loginUrl] = req($c, $base . '/login.php', [
        'username' => $user,
        'password' => $initialPassword,
        'Login' => 'Login',
        'user_token' => tokenIn($loginPage),
    ]);
    if ($loginStatus !== 200 || stripos($loginBody, 'Login failed') !== false || str_contains($loginUrl, 'login.php')) {
        throw new RuntimeException('Sandbox default login failed; no attack request sent');
    }
    $sessionId = null;
    foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
        $parts = explode("\t", $line);
        if (count($parts) >= 7 && $parts[5] === 'PHPSESSID') {
            $sessionId = $parts[6];
        }
    }
    if ($sessionId === null || !preg_match('/^[A-Za-z0-9,-]+$/', $sessionId)) {
        throw new RuntimeException('Sandbox session cookie not found');
    }

    $module = curl_init($base . '/vulnerabilities/captcha/');
    curl_setopt_array($module, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=low',
        CURLOPT_USERAGENT => 'DVWA-isolated-fix-check/1.0',
    ]);
    $page = curl_exec($module);
    $pageStatus = (int)curl_getinfo($module, CURLINFO_HTTP_CODE);
    if ($page === false || $pageStatus !== 200) {
        throw new RuntimeException('Patched module GET did not return HTTP 200');
    }
    curl_setopt($module, CURLOPT_URL, $base . '/vulnerabilities/captcha/');
    curl_setopt($module, CURLOPT_POST, true);
    curl_setopt($module, CURLOPT_POSTFIELDS, http_build_query([
        'step' => '2',
        'password_new' => $attackPassword,
        'password_conf' => $attackPassword,
        'Change' => 'Change',
    ]));
    $response = curl_exec($module);
    if ($response === false) {
        throw new RuntimeException('Direct step=2 request failed: ' . curl_error($module));
    }
    echo 'patched direct step=2 POST: HTTP ' . (int)curl_getinfo($module, CURLINFO_HTTP_CODE) . "\n";

    $originalStillWorks = loginOk($base, $user, $initialPassword);
    $attackPasswordWorks = loginOk($base, $user, $attackPassword);
    echo 'original password still valid=' . ($originalStillWorks ? 'true' : 'false') . "\n";
    echo 'attacker-supplied password valid=' . ($attackPasswordWorks ? 'true' : 'false') . "\n";
    if (!$originalStillWorks || $attackPasswordWorks) {
        throw new RuntimeException('Patch did not block the direct step=2 password change');
    }
    echo "PATCHED_STEP2_BYPASS_BLOCKED\n";
} finally {
    @unlink($jar);
}
