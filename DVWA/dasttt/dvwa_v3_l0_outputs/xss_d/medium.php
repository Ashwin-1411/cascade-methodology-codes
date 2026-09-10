<?php

// Is there any input?
if (array_key_exists("default", $_GET) && !is_null($_GET['default'])) {
    $default = $_GET['default'];

    // Do not allow script tags
    if (stripos($default, "<script") !== false) {
        header("location: ?default=English");
        exit;
    }

    // Sanitize input to prevent XSS
    $default = htmlspecialchars($default, ENT_QUOTES, 'UTF-8');
}

?>