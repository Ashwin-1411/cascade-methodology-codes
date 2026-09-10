<?php

// Define a whitelist of allowed redirect IDs and their corresponding URLs
$allowedRedirects = [
    1 => "http://example.com/page1",
    2 => "http://example.com/page2",
    3 => "http://example.com/page3"
];

if (array_key_exists("redirect", $_GET) && is_numeric($_GET['redirect'])) {
    $redirectId = (int)$_GET['redirect'];
    
    if (array_key_exists($redirectId, $allowedRedirects)) {
        header("Location: " . $allowedRedirects[$redirectId]);
        exit;
    } else {
        http_response_code(400);
        ?>
        <p>Invalid redirect target.</p>
        <?php
        exit;
    }
}

http_response_code(400);
?>
<p>Missing or invalid redirect target.</p>
<?php
exit;
?>