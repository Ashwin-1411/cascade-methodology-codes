<?php

if (array_key_exists("redirect", $_GET)) {
    // Sanitize the input to remove any potentially harmful characters
    $redirect = filter_var($_GET['redirect'], FILTER_SANITIZE_URL);

    // Check if the sanitized URL is empty
    if ($redirect === false || $redirect === '') {
        http_response_code(500);
        echo "<p>Invalid redirect target.</p>";
        exit;
    }

    // Validate the URL to ensure it does not contain absolute URLs
    if (filter_var($redirect, FILTER_VALIDATE_URL) !== false && !preg_match("/^http(s)?:\/\/(www\.)?/", $redirect)) {
        header("Location: " . $redirect);
        exit;
    } else {
        http_response_code(500);
        echo "<p>Absolute URLs not allowed.</p>";
        exit;
    }
} else {
    http_response_code(500);
    echo "<p>Missing redirect target.</p>";
    exit;
}
?>