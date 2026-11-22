<?php

function renderGreeting(string $name): string
{
    $safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<pre>Hello ' . $safeName . '</pre>';
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    foreach ([
        'normal marker' => 'LAB_MARK',
        'HTML tag' => '<b>LAB_MARK</b>',
        'event-handler probe' => '<img src=x onerror=document.title="XSS_LAB_PROOF">',
    ] as $label => $input) {
        printf("%s: %s\n", $label, renderGreeting($input));
    }
}
