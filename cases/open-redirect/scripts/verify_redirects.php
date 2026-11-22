<?php

$mode = $argv[1] ?? '';
if (!in_array($mode, ['vulnerable', 'fixed'], true)) {
    fwrite(STDERR, "usage: php verify_redirects.php vulnerable|fixed\n");
    exit(2);
}

$cases = [
    ['name' => 'low-absolute', 'level' => 'low', 'value' => 'https://example.invalid/redirect-proof'],
    ['name' => 'medium-protocol-relative', 'level' => 'medium', 'value' => '//example.invalid/redirect-proof'],
    ['name' => 'high-substring', 'level' => 'high', 'value' => 'https://example.invalid/?next=info.php'],
];
if ($mode === 'fixed') {
    $cases[] = ['name' => 'fixed-safe-low', 'level' => 'low', 'value' => '1', 'safe_location' => 'info.php?id=1'];
    $cases[] = ['name' => 'fixed-safe-medium', 'level' => 'medium', 'value' => '2', 'safe_location' => 'info.php?id=2'];
    $cases[] = ['name' => 'fixed-safe-high', 'level' => 'high', 'value' => '1', 'safe_location' => 'info.php?id=1'];
}

$allPassed = true;
$results = [];
foreach ($cases as $case) {
    $url = 'http://127.0.0.1/vulnerabilities/open_redirect/source/' . $case['level'] . '.php?' . http_build_query(['redirect' => $case['value']]);
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 5,
    ]);
    $raw = curl_exec($curl);
    if ($raw === false) {
        fwrite(STDERR, curl_error($curl) . "\n");
        exit(3);
    }
    $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $location = '';
    if (preg_match('/^Location:\s*(.*?)\s*$/im', $raw, $match)) {
        $location = trim($match[1]);
    }

    if ($mode === 'vulnerable') {
        $passed = $status === 302 && $location === $case['value'];
    } elseif (isset($case['safe_location'])) {
        $passed = $status === 302 && $location === $case['safe_location'];
    } else {
        $passed = $status !== 302 && $location === '';
    }
    $allPassed = $allPassed && $passed;
    $results[] = ['case' => $case['name'], 'status' => $status, 'location' => $location, 'pass' => $passed];
}

echo json_encode(['mode' => $mode, 'checks' => $results, 'all_passed' => $allPassed], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
exit($allPassed ? 0 : 1);
