<?php

if (array_key_exists("redirect", $_GET) && filter_var($_GET['redirect'], FILTER_VALIDATE_URL)) {
    header("Location: " . $_GET['redirect']);
    exit;
}

http_response_code(500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>