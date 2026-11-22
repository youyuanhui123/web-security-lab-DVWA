<?php

declare(strict_types=1);

/** Validate and re-encode an image into a PNG at the supplied private path. */
function normalizeImageUpload(string $source, string $destination): bool
{
    $maxBytes = 2 * 1024 * 1024;
    if (!is_file($source) || filesize($source) < 1 || filesize($source) > $maxBytes) {
        return false;
    }

    $info = @getimagesize($source);
    $allowedTypes = [IMAGETYPE_JPEG => 'image/jpeg', IMAGETYPE_PNG => 'image/png'];
    if ($info === false || !isset($allowedTypes[$info[2]]) || ($info['mime'] ?? '') !== $allowedTypes[$info[2]]) {
        return false;
    }
    if ($info[0] > 4096 || $info[1] > 4096 || ($info[0] * $info[1]) > 10000000) {
        return false;
    }

    $bytes = file_get_contents($source);
    $image = $bytes === false ? false : @imagecreatefromstring($bytes);
    if ($image === false) {
        return false;
    }

    imagealphablending($image, false);
    imagesavealpha($image, true);
    $ok = imagepng($image, $destination, 6);
    if (!$ok) {
        @unlink($destination);
        return false;
    }
    @chmod($destination, 0600);
    return true;
}

/** Store only a re-encoded image outside the web root; return an opaque id. */
function storeImageUpload(array $upload, string $privateDirectory): ?string
{
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK
        || !isset($upload['tmp_name'])
        || !is_uploaded_file($upload['tmp_name'])) {
        return null;
    }
    if (!is_dir($privateDirectory) && !mkdir($privateDirectory, 0700, true) && !is_dir($privateDirectory)) {
        return null;
    }

    $id = bin2hex(random_bytes(16));
    $destination = rtrim($privateDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $id . '.png';
    return normalizeImageUpload($upload['tmp_name'], $destination) ? $id : null;
}

if (PHP_SAPI !== 'cli' && isset($_POST['Upload'])) {
    $privateDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'dvwa-private-uploads';
    $id = storeImageUpload($_FILES['uploaded'] ?? [], $privateDirectory);
    if ($id === null) {
        $html .= '<pre>Upload rejected: provide a valid PNG/JPEG image within the configured limits.</pre>';
    } else {
        $safeId = htmlspecialchars($id, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html .= '<pre>Image accepted and stored privately. Reference: ' . $safeId . '</pre>';
    }
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    if ($argc !== 3) {
        fwrite(STDERR, "Usage: php fixed_upload.php INPUT_IMAGE OUTPUT_PNG\n");
        exit(2);
    }
    if (!normalizeImageUpload($argv[1], $argv[2])) {
        fwrite(STDERR, "rejected: not an allowed, decodable image\n");
        exit(1);
    }
    echo "accepted and re-encoded as PNG\n";
}
