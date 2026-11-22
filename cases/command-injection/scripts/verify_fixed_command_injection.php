<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: '';
$password = getenv('DVWA_LAB_PASSWORD') ?: '';
if ($user === '' || $password === '') {
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
        throw new RuntimeException('user_token missing from patched form');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function resetDb(string $base): void
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-cmdi-fixed-setup-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-cmdi-test/1.0',
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
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-cmdi-fixed-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-cmdi-test/1.0',
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
    $c = curl_init($base . '/vulnerabilities/exec/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-cmdi-test/1.0',
    ]);
    $page = curl_exec($c);
    if ($page === false || (int)curl_getinfo($c, CURLINFO_HTTP_CODE) !== 200) {
        throw new RuntimeException(strtoupper($level) . ' patched page failed to load');
    }
    return tokenFrom($page);
}

function sendTarget(string $base, string $sessionId, string $level, string $ip, string $token): string
{
    $c = curl_init($base . '/vulnerabilities/exec/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-cmdi-test/1.0',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['ip' => $ip, 'Submit' => 'Submit', 'user_token' => $token]),
    ]);
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' POST failed: ' . curl_error($c));
    }
    return $body;
}

resetDb($base);
echo "isolated database initialized\n";
$sessionId = loginSession($base, $user, $password);
$payload = '127.0.0.1|printf CMDI_LAB_PROOF';
foreach (['low', 'medium', 'high'] as $level) {
    $safeToken = moduleToken($base, $sessionId, $level);
    $safeBody = sendTarget($base, $sessionId, $level, '127.0.0.1', $safeToken);
    $safeAccepted = strpos($safeBody, 'ERROR: You have entered an invalid IP.') === false;

    $attackToken = moduleToken($base, $sessionId, $level);
    $attackBody = sendTarget($base, $sessionId, $level, $payload, $attackToken);
    $marker = strpos($attackBody, 'CMDI_LAB_PROOF') !== false;
    $rejected = strpos($attackBody, 'ERROR: You have entered an invalid IP.') !== false;
    echo strtoupper($level) . ' valid_ip_accepted=' . ($safeAccepted ? 'true' : 'false')
        . '; injected_marker=' . ($marker ? 'present' : 'absent')
        . '; invalid_ip_rejected=' . ($rejected ? 'true' : 'false') . "\n";
    if (!$safeAccepted || $marker || !$rejected) {
        throw new RuntimeException(strtoupper($level) . ' command injection fix regression failed');
    }
    echo strtoupper($level) . "_COMMAND_INJECTION_BLOCKED\n";
}
