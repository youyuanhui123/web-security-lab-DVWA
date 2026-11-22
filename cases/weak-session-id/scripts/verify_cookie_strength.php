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
        throw new RuntimeException('user_token missing');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function authenticatedSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-weak-id-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-weak-session-test/1.0',
    ]);
    try {
        [$loginPage] = requestPage($c, $base . '/login.php');
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => tokenFrom($loginPage),
        ]);
        if ($status !== 200 || stripos($body, 'Login failed') !== false || str_contains($url, 'login.php')) {
            throw new RuntimeException('Login failed before cookie probes');
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

function issueCookie(string $base, string $sessionId, string $level): array
{
    $setCookies = [];
    $c = curl_init($base . '/vulnerabilities/weak_id/');
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-weak-session-test/1.0',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => '',
        CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$setCookies): int {
            if (stripos($line, 'Set-Cookie:') === 0) {
                $setCookies[] = trim(substr($line, strlen('Set-Cookie:')));
            }
            return strlen($line);
        },
    ]);
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' POST failed: ' . curl_error($c));
    }
    if ((int)curl_getinfo($c, CURLINFO_HTTP_CODE) !== 200) {
        throw new RuntimeException(strtoupper($level) . ' module returned non-200');
    }
    foreach ($setCookies as $header) {
        if (preg_match('/^dvwaSession=([^;]*)(.*)$/i', $header, $m)) {
            return [$m[1], $m[2]];
        }
    }
    throw new RuntimeException(strtoupper($level) . ' response did not set dvwaSession');
}

$jar = tempnam(sys_get_temp_dir(), 'dvwa-weak-id-setup-');
$c = curl_init();
curl_setopt_array($c, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_COOKIEFILE => $jar,
    CURLOPT_COOKIEJAR => $jar,
    CURLOPT_USERAGENT => 'DVWA-isolated-weak-session-test/1.0',
]);
try {
    [$setupPage] = requestPage($c, $base . '/setup.php');
    [, $setupStatus] = requestPage($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => tokenFrom($setupPage),
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Isolated database initialization failed');
    }
    echo "isolated database initialized\n";
} finally {
    @unlink($jar);
}

$sessionId = authenticatedSession($base, $user, $password);
foreach (['low', 'medium', 'high', 'impossible'] as $level) {
    [$first, $firstAttrs] = issueCookie($base, $sessionId, $level);
    [$second, $secondAttrs] = issueCookie($base, $sessionId, $level);
    if ($level === 'low') {
        $ok = $first === '1' && $second === '2';
        echo 'LOW sequential counter=' . ($ok ? 'confirmed' : 'not-confirmed') . "\n";
    } elseif ($level === 'medium') {
        $ok = preg_match('/^\d{10}$/', $first) === 1 && preg_match('/^\d{10}$/', $second) === 1;
        echo 'MEDIUM Unix-timestamp format=' . ($ok ? 'confirmed' : 'not-confirmed') . "\n";
    } elseif ($level === 'high') {
        $ok = $first === hash('md5', '1') && $second === hash('md5', '2');
        echo 'HIGH md5-of-counter=' . ($ok ? 'confirmed' : 'not-confirmed') . "\n";
    } else {
        $flags = strtolower($firstAttrs . $secondAttrs);
        $ok = preg_match('/^[a-f0-9]{40}$/', $first) === 1
            && preg_match('/^[a-f0-9]{40}$/', $second) === 1
            && !hash_equals($first, $second)
            && str_contains($flags, 'secure')
            && str_contains($flags, 'httponly');
        echo 'IMPOSSIBLE random 160-bit format, distinct pair, Secure/HttpOnly=' . ($ok ? 'confirmed' : 'not-confirmed') . "\n";
    }
    if (!$ok) {
        throw new RuntimeException(strtoupper($level) . ' session-cookie acceptance criteria not met');
    }
    echo strtoupper($level) . "_COOKIE_BEHAVIOR_CONFIRMED\n";
}
