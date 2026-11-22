<?php

declare(strict_types=1);

/**
 * Reference remediation for the DVWA MySQL user lookup.
 * This is a standalone example; it does not modify the upstream container.
 */
function lookupUser(PDO $db, string $rawId): ?array
{
    // Accept only decimal digits before converting to an integer.
    if ($rawId === '' || !ctype_digit($rawId)) {
        return null;
    }

    $id = (int) $rawId;
    $stmt = $db->prepare(
        'SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1'
    );
    $stmt->bindValue(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row;
}

// Optional local CLI regression check. Credentials are supplied through env vars.
if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $dsn = getenv('DVWA_TEST_DSN');
    $user = getenv('DVWA_TEST_USER');
    $password = getenv('DVWA_TEST_PASSWORD');
    if ($dsn === false || $user === false || $password === false) {
        fwrite(STDERR, "Set DVWA_TEST_DSN, DVWA_TEST_USER, and DVWA_TEST_PASSWORD.\n");
        exit(2);
    }

    $db = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $cases = [
        'normal ID' => '1',
        'true condition input' => "1' AND '1'='1",
        'false condition input' => "1' AND '1'='2",
    ];

    foreach ($cases as $label => $input) {
        $row = lookupUser($db, $input);
        printf("%s: %s\n", $label, $row === null ? 'no row' : $row['first_name']);
    }
}
