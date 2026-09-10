<?php

if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
    if (filter_var($_GET['redirect'], FILTER_VALIDATE_URL)) {
        http_response_code(500);
        ?>
        <p>Absolute URLs not allowed.</p>
        <?php
        exit;
    } else {
        // Sanitize the input to prevent open redirects
        $redirect = filter_var($_GET['redirect'], FILTER_SANITIZE_URL);
        if ($redirect !== false) {
            header("Location: " . $redirect);
            exit;
        }
    }
}

http_response_code(500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>