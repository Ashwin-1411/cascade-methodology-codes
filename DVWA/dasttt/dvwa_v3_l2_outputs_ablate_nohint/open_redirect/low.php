<?php

// Check if 'redirect' parameter exists and is not empty
if (isset($_GET['redirect']) && !empty($_GET['redirect'])) {
    // Validate and sanitize the redirect URL to prevent Open Redirect attacks
    $redirect_url = filter_var($_GET['redirect'], FILTER_VALIDATE_URL, FILTER_FLAG_QUERY_ALLOWED);

    if ($redirect_url !== false) {
        // Ensure the redirect URL is on the same domain to prevent Open Redirect attacks
        $parsed_url = parse_url($redirect_url);
        if ($parsed_url['host'] === $_SERVER['HTTP_HOST']) {
            header("Location: " . $redirect_url);
            exit;
        } else {
            http_response_code(403);
            echo "<p>Forbidden redirect target.</p>";
            exit;
        }
    } else {
        http_response_code(400);
        echo "<p>Invalid redirect target.</p>";
        exit;
    }
}

http_response_code(500);
echo "<p>Missing redirect target.</p>";
exit;
?>