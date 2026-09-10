<?php
/*

Only the admin user is allowed to access this page.

Have a look at these two files for possible vulnerabilities: 

* vulnerabilities/authbypass/get_user_data.php
* vulnerabilities/authbypass/change_user_details.php

*/

// Ensure the function dvwaCurrentUser() is defined and behaves as expected
if (!function_exists('dvwaCurrentUser')) {
    function dvwaCurrentUser() {
        // Placeholder implementation, replace with actual function logic
        return $_SESSION['username'] ?? '';
    }
}

if (dvwaCurrentUser() !== "admin") {
    print "Unauthorised";
    http_response_code(403);
    exit;
}
?>