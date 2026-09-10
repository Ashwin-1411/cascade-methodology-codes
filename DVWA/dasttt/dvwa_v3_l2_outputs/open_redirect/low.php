<?php

// Define a whitelist of allowed redirect targets
$allowed_redirects = [
    1 => "http://example.com/page1",
    2 => "http://example.com/page2",
    3 => "http://example.com/page3"
];

if (array_key_exists("redirect", $_GET) && is_numeric($_GET['redirect'])) {
    $redirect_id = (int)$_GET['redirect'];
    if (array_key_exists($redirect_id, $allowed_redirects)) {
        header("location: " . $allowed_redirects[$redirect_id]);
        exit;
    }
}

http_response_code(500);
?>
<p>Missing or invalid redirect target.</p>
<?php
exit;
?>