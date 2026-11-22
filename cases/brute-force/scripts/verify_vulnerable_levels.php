<?php

declare(strict_types=1);

$base = 'http://127.0.0.1';
$user = getenv('DVWA_LAB_USER') ?: '';
$password = getenv('DVWA_LAB_PASSWORD') ?: '';
$levels = array_filter(array_map('trim', explode(',', getenv('DVWA_LAB_LEVELS') ?: 'low,medium,high')));
$attemptCount = max(1, min(3, (int)(getenv('DVWA_LAB_ATTEMPTS') ?: 3)));
if ($user === '' || $password === '' || !$levels) {
    fwrite(STDERR, "Set sandbox-only DVWA_LAB_USER and DVWA_LAB_PASSWORD.\n");
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
        throw new RuntimeException('user_token missing');
    }
    return html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function resetDb(string $base): void
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-brute-setup-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-brute-test/1.0',
    ]);
    try {
        [$setup] = pageRequest($c, $base . '/setup.php');
        [, $status] = pageRequest($c, $base . '/setup.php', [
            'create_db' => 'Create / Reset Database',
            'user_token' => tokenFrom($setup),
        ]);
        if ($status !== 200) {
            throw new RuntimeException('Isolated database reset failed');
        }
    } finally {
        @unlink($jar);
    }
}

function loginSession(string $base, string $user, string $password): string
{
    $jar = tempnam(sys_get_temp_dir(), 'dvwa-brute-login-');
    $c = curl_init();
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_USERAGENT => 'DVWA-isolated-brute-test/1.0',
    ]);
    try {
        [$page] = pageRequest($c, $base . '/login.php');
        [$body, $status, $url] = pageRequest($c, $base . '/login.php', [
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

function attempt(string $base, string $sessionId, string $level, string $user, string $password): array
{
    $fields = ['username' => $user, 'password' => $password, 'Login' => 'Login'];
    if ($level === 'high') {
        $pageClient = curl_init($base . '/vulnerabilities/brute/');
        curl_setopt_array($pageClient, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=high',
            CURLOPT_USERAGENT => 'DVWA-isolated-brute-test/1.0',
        ]);
        $page = curl_exec($pageClient);
        if ($page === false) {
            throw new RuntimeException('Could not fetch High-level form token');
        }
        $fields['user_token'] = tokenFrom($page);
    }
    $url = $base . '/vulnerabilities/brute/?' . http_build_query($fields);
    $c = curl_init($url);
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => 'PHPSESSID=' . $sessionId . '; security=' . $level,
        CURLOPT_USERAGENT => 'DVWA-isolated-brute-test/1.0',
    ]);
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' login request failed: ' . curl_error($c));
    }
    return [$body, (int)curl_getinfo($c, CURLINFO_HTTP_CODE), (float)curl_getinfo($c, CURLINFO_TOTAL_TIME)];
}

foreach ($levels as $level) {
    resetDb($base);
    $sessionId = loginSession($base, $user, $password);
    $failedAttempts = 0;
    $durations = [];
    for ($i = 0; $i < $attemptCount; $i++) {
        [$body, $status, $elapsed] = attempt($base, $sessionId, $level, 'admin', 'definitely-wrong');
        $failedSignal = $status === 200 && strpos($body, 'Username and/or password incorrect.') !== false;
        if (!$failedSignal) {
            echo strtoupper($level) . " invalid probe diagnostic: HTTP={$status} failure_marker=" . (strpos($body, 'Username and/or password incorrect.') !== false ? 'true' : 'false') . ' bytes=' . strlen($body) . ' text=' . substr(trim(preg_replace('/\\s+/', ' ', strip_tags($body))), 0, 180) . "\n";
        }
        if ($failedSignal) {
            $failedAttempts++;
        }
        $durations[] = $elapsed;
    }
    [$validBody, $validStatus] = attempt($base, $sessionId, $level, 'admin', $password);
    $validStillAccepted = $validStatus === 200 && strpos($validBody, 'Welcome to the password protected area') !== false;
    if (!$validStillAccepted) {
        echo strtoupper($level) . " valid probe diagnostic: HTTP={$validStatus} welcome_marker=" . (strpos($validBody, 'Welcome to the password protected area') !== false ? 'true' : 'false') . ' bytes=' . strlen($validBody) . "\n";
    }
    echo strtoupper($level) . " invalid_attempts={$failedAttempts}/{$attemptCount}; correct_password_still_accepted=" . ($validStillAccepted ? 'true' : 'false') . "\n";
    if ($failedAttempts !== $attemptCount || !$validStillAccepted) {
        throw new RuntimeException(strtoupper($level) . ' baseline behavior differs from source expectation');
    }
    echo strtoupper($level) . "_NO_LOCKOUT_CONFIRMED\n";
}
