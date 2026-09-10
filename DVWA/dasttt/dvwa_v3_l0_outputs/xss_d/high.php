<?php

// Is there any input?
if (array_key_exists("default", $_GET) && !is_null($_GET['default'])) {

    // White list the allowable languages
    $allowed_languages = ["French", "English", "German", "Spanish"];
    if (in_array($_GET['default'], $allowed_languages)) {
        // ok
    } else {
        header("location: ?default=English");
        exit;
    }
}

?>