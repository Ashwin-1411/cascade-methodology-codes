<?php

// Define allowed redirects and their corresponding URLs
$allowed_redirects = [
    1 => 'info.php',
    2 => 'about.php',
    // Add more allowed redirects as needed
];

if (array_key_exists("redirect", $_GET)) {
    $redirect_id = intval($_GET['redirect']);

    if (isset($allowed_redirects[$redirect_id])) {
        header("location: " . $allowed_redirects[$redirect_id]);
        exit;
    } else {
        http_response_code(500);
        ?>
        <p>You can only redirect to the allowed pages.</p>
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