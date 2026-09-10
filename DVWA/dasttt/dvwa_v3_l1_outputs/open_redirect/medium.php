<?php

if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
    if (filter_var($_GET['redirect'], FILTER_VALIDATE_URL)) {
        http_response_code(500);
        ?>
        <p>Absolute URLs not allowed.</p>
        <?php
        exit;
    } else {
        header("location: " . htmlspecialchars($_GET['redirect']));
        exit;
    }
}

http_response_code(500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>