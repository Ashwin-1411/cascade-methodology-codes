<?php

if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
    // Sanitize the input to prevent open redirect vulnerabilities
    $redirect = filter_var($_GET['redirect'], FILTER_SANITIZE_URL);

    if (strpos($redirect, "info.php") !== false) {
        header("Location: " . $redirect);
        exit;
    } else {
        http_response_code(500);
        ?>
        <p>You can only redirect to the info page.</p>
        <?php
        exit;
    }
}

http_response_code(500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>