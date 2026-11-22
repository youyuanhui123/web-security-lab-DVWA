<?php

function renderGuestbookRow(string $name, string $comment): string
{
    $safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeComment = htmlspecialchars($comment, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<div>Name: ' . $safeName . '<br />Message: ' . $safeComment . '<br /></div>';
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    printf("normal: %s\n", renderGuestbookRow('LAB_USER', 'ordinary note'));
    printf("markup: %s\n", renderGuestbookRow('LAB_USER', '<img src=x onerror=alert(1)>'));
}
