<?php

// Check if the 'redirect' parameter exists and is not empty
if (isset($_GET["redirect"]) && !empty($_GET["redirect"])) {
    // Sanitize the input to remove any potential malicious characters
    $redirect = filter_var($_GET["redirect"], FILTER_SANITIZE_URL);

    // Validate that the redirect URL starts with "info.php"
    if (strpos($redirect, "info.php") === 0) {
        // Ensure the redirect URL does not contain any additional path segments
        if ($redirect == "info.php" || strpos($redirect, "info.php/") === 0) {
            header("Location: " . $redirect);
            exit;
        } else {
            http_response_code(500);
            echo "<p>You can only redirect to the info page.</p>";
            exit;
        }
    } else {
        http_response_code(500);
        echo "<p>You can only redirect to the info page.</p>";
        exit;
    }
} else {
    http_response_code(500);
    echo "<p>Missing redirect target.</p>";
    exit;
}
?>