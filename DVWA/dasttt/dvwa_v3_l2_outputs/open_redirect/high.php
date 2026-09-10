<?php

// Define a whitelist of allowed redirect targets
$allowed_redirects = [
    1 => "info.php",
    2 => "about.php",
    3 => "contact.php"
];

if (array_key_exists("redirect", $_GET) && is_numeric($_GET['redirect'])) {
    $redirect_id = (int)$_GET['redirect'];
    if (array_key_exists($redirect_id, $allowed_redirects)) {
        header("location: " . $allowed_redirects[$redirect_id]);
        exit;
    } else {
        http_response_code(500);
        ?>
        <p>Invalid redirect target.</p>
        <?php
        exit;
    }
}

http_response_code(500);
?>
<p>Missing or invalid redirect target.</p>
<?php
exit;
?>