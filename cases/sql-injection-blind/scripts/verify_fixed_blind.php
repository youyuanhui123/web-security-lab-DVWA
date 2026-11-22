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

function extractToken(string $body): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $body, $m)) {
        throw new RuntimeException('user_token not found');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function loginSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-blind-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-blind-test/1.0',
    ]);
    try {
        [$page] = requestPage($c, $base . '/login.php');
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => extractToken($page),
        ]);
        if ($status !== 200 || stripos($body, 'Login failed') !== false || str_contains($url, 'login.php')) {
            throw new RuntimeException('Sandbox login failed');
        }
        foreach (curl_getinfo($c, CURLINFO_COOKIELIST) ?: [] as $line) {
            $p = explode("\t", $line);
            if (count($p) >= 7 && $p[5] === 'PHPSESSID' && preg_match('/^[A-Za-z0-9,-]+$/', $p[6])) {
                return $p[6];
            }
        }
        throw new RuntimeException('Authenticated session cookie missing');
    } finally {
        @unlink($jar);
    }
}

function moduleGet(string $base, string $sessionId, string $level): string
{
    $c = curl_init($base . '/vulnerabilities/sqli_blind/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-blind-test/1.0',
    ]);
    $body = curl_exec($c);
    if ($body === false || (int)curl_getinfo($c, CURLINFO_HTTP_CODE) !== 200) {
        throw new RuntimeException(strtoupper($level) . ' patched page failed to load');
    }
    return $body;
}

function submitId(string $base, string $sessionId, string $level, string $id, string $token, bool $oldPost = false, bool $oldCookie = false): array
{
    $query = http_build_query(['id' => $id, 'Submit' => 'Submit', 'user_token' => $token]);
    $url = $base . '/vulnerabilities/sqli_blind/?' . $query;
    $cookie = 'PHPSESSID=' . $sessionId . '; security=' . $level;
    if ($oldCookie) {
        $cookie .= '; id=' . $id;
    }
    $c = curl_init($url);
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => $cookie,
        CURLOPT_USERAGENT => 'DVWA-isolated-fixed-blind-test/1.0',
    ]);
    if ($oldPost) {
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query(['id' => $id, 'Submit' => 'Submit', 'user_token' => $token]));
    }
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' request failed: ' . curl_error($c));
    }
    return [$body, (int)curl_getinfo($c, CURLINFO_HTTP_CODE)];
}

$jar = tempnam(sys_get_temp_dir(), 'dvwa-blind-setup-');
$c = curl_init();
curl_setopt_array($c, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_COOKIEFILE => $jar,
    CURLOPT_COOKIEJAR => $jar,
    CURLOPT_USERAGENT => 'DVWA-isolated-fixed-blind-test/1.0',
]);
try {
    [$setup] = requestPage($c, $base . '/setup.php');
    [, $status] = requestPage($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => extractToken($setup),
    ]);
    if ($status !== 200) {
        throw new RuntimeException('Sandbox DB setup failed');
    }
    echo "isolated database initialized\n";
} finally {
    @unlink($jar);
}

$sessionId = loginSession($base, $user, $password);
$attacks = [
    'low' => ["1' AND '1'='1", false, false],
    'medium' => ['1 OR 1=1', true, false],
    'high' => ["1'OR'1'='1", false, true],
];
foreach ($attacks as $level => [$payload, $asPost, $asCookie]) {
    $token = extractToken(moduleGet($base, $sessionId, $level));
    [$controlBody] = submitId($base, $sessionId, $level, '1', $token);
    $control = strpos($controlBody, 'User ID exists in the database.') !== false;
    if (!$control) {
        throw new RuntimeException(strtoupper($level) . ' valid-ID control failed');
    }

    $token = extractToken(moduleGet($base, $sessionId, $level));
    [$attackBody, $attackStatus] = submitId($base, $sessionId, $level, $payload, $token, $asPost, $asCookie);
    $exists = strpos($attackBody, 'User ID exists in the database.') !== false;
    $missing = strpos($attackBody, 'User ID is MISSING from the database.') !== false;
    echo strtoupper($level) . " control=exists attack_http={$attackStatus} attack_exists=" . ($exists ? 'true' : 'false')
        . ' attack_missing=' . ($missing ? 'true' : 'false') . "\n";
    if ($exists || !$missing) {
        throw new RuntimeException(strtoupper($level) . ' blind SQLi payload was not blocked');
    }
    echo strtoupper($level) . "_PATCH_BLOCK_CONFIRMED\n";
}
