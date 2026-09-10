<?php
/*

Only the admin user is allowed to access this page.

Have a look at this file for possible vulnerabilities: 

* vulnerabilities/authbypass/change_user_details.php

*/

// Ensure the function dvwaCurrentUser() is defined and behaves as expected
if (!function_exists('dvwaCurrentUser')) {
    function dvwaCurrentUser() {
        // Placeholder implementation, replace with actual logic
        return $_SESSION['username'] ?? '';
    }
}

if (dvwaCurrentUser() !== "admin") {
    print "Unauthorised";
    http_response_code(403);
    exit;
}
?>