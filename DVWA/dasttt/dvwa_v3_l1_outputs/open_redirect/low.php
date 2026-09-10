<?php

if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
    // Sanitize the redirect URL to prevent open redirect vulnerabilities
    $redirectUrl = filter_var($_GET['redirect'], FILTER_VALIDATE_URL);
    
    if ($redirectUrl !== false) {
        header("Location: " . $redirectUrl);
        exit;
    }
}

http_response_code(500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>