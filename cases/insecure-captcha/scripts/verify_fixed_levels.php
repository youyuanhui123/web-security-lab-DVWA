<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: 'admin';
$initialPassword = getenv('DVWA_LAB_INITIAL_PASSWORD') ?: '';
if ($initialPassword === '') {
    fwrite(STDERR, "Set sandbox-only initial password.\n");
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

function extractUserToken(string $body): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $body, $m)) {
        throw new RuntimeException('user_token not present on login/setup page');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function loginSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fix-check/1.0',
    ]);
    try {
        [$page] = requestPage($c, $base . '/login.php');
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => extractUserToken($page),
        ]);
        if ($status !== 200 || stripos($body, 'Login failed') !== false || str_contains($url, 'login.php')) {
            throw new RuntimeException('Sandbox login failed; attack not sent');
        }
        foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
            $p = explode("\t", $line);
            if (count($p) >= 7 && $p[5] === 'PHPSESSID' && preg_match('/^[A-Za-z0-9,-]+$/', $p[6])) {
                return $p[6];
            }
        }
        throw new RuntimeException('Authenticated PHPSESSID not found');
    } finally {
        @unlink($jar);
    }
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

$jar = tempnam(sys_get_temp_dir(), 'dvwa-captcha-setup-');
$c = curl_init();
curl_setopt_array($c, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_COOKIEFILE => $jar,
    CURLOPT_COOKIEJAR => $jar,
    CURLOPT_USERAGENT => 'DVWA-isolated-fix-check/1.0',
]);
try {
    [$setup] = requestPage($c, $base . '/setup.php');
    [, $setupStatus] = requestPage($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => extractUserToken($setup),
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Sandbox database reset failed');
    }
    echo "isolated DB initialized\n";
} finally {
    @unlink($jar);
}

$attacks = [
    'low' => [
        'fields' => ['step' => '2'],
        'user_agent' => 'DVWA-isolated-fix-check/1.0',
    ],
    'medium' => [
        'fields' => ['step' => '2', 'passed_captcha' => 'true'],
        'user_agent' => 'DVWA-isolated-fix-check/1.0',
    ],
    'high' => [
        'fields' => ['g-recaptcha-response' => 'hidd3n_valu3'],
        'user_agent' => 'reCAPTCHA',
    ],
];

foreach ($attacks as $mode => $attack) {
    $sessionId = loginSession($base, $user, $initialPassword);
    $attempt = 'Sandbox-Blocked-' . $mode . '-' . bin2hex(random_bytes(8));
    $fields = $attack['fields'] + [
        'password_new' => $attempt,
        'password_conf' => $attempt,
        'Change' => 'Change',
    ];
    $c = curl_init($base . '/vulnerabilities/captcha/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $mode,
        CURLOPT_USERAGENT => $attack['user_agent'],
    ]);
    $preflight = curl_exec($c);
    if ($preflight === false || (int)curl_getinfo($c, CURLINFO_HTTP_CODE) !== 200) {
        throw new RuntimeException(strtoupper($mode) . ' patched module GET failed');
    }
    curl_setopt($c, CURLOPT_URL, $base . '/vulnerabilities/captcha/');
    curl_setopt($c, CURLOPT_POST, true);
    curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query($fields));
    $response = curl_exec($c);
    if ($response === false) {
        throw new RuntimeException(strtoupper($mode) . ' attack request failed: ' . curl_error($c));
    }
    echo strtoupper($mode) . ' forged request HTTP ' . (int)curl_getinfo($c, CURLINFO_HTTP_CODE) . "\n";

    $originalWorks = loginWorks($base, $user, $initialPassword);
    $forgedWorks = loginWorks($base, $user, $attempt);
    echo strtoupper($mode) . ' original password=' . ($originalWorks ? 'valid' : 'invalid')
        . '; forged password=' . ($forgedWorks ? 'valid' : 'invalid') . "\n";
    if (!$originalWorks || $forgedWorks) {
        throw new RuntimeException(strtoupper($mode) . ' patched flow did not block the forged password update');
    }
    echo strtoupper($mode) . "_PATCH_BLOCK_CONFIRMED\n";
}
