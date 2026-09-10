<?php
/*

Only the admin user is allowed to access this page.

Have a look at these two files for possible vulnerabilities: 

* vulnerabilities/authbypass/get_user_data.php
* vulnerabilities/authbypass/change_user_details.php

*/

session_start(); // Ensure session is started

if (!isset($_SESSION['username']) || $_SESSION['username'] !== "admin") {
	print "Unauthorised";
	http_response_code(403);
	exit;
}
?>