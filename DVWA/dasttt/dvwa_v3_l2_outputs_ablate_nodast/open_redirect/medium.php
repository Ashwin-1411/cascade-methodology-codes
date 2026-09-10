<?php

$allowedRedirects = [
    1 => 'https://example.com/page1',
    2 => 'https://example.com/page2',
    // Add more allowed redirects as needed
];

if (array_key_exists("redirect", $_GET) && is_numeric($_GET['redirect'])) {
    $redirectId = intval($_GET['redirect']);
    
    if (isset($allowedRedirects[$redirectId])) {
        header("location: " . $allowedRedirects[$redirectId]);
        exit;
    } else {
        http_response_code(400);
        echo "<p>Invalid redirect target.</p>";
        exit;
    }
}

http_response_code(400);
echo "<p>Missing or invalid redirect target.</p>";
exit;

?>