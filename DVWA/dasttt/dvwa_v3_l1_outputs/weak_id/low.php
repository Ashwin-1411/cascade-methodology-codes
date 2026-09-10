<?php

session_start(); // Start the session to use $_SESSION superglobal

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id'])) {
		$_SESSION['last_session_id'] = 0;
	}
	$_SESSION['last_session_id']++;
	$cookie_value = $_SESSION['last_session_id'];
	setcookie("dvwaSession", $cookie_value, [
		'expires' => time() + 86400, // Set cookie to expire in 24 hours
		'path' => '/', // Make the cookie available on all pages
		'secure' => true, // Only send the cookie over HTTPS
		'httponly' => true, // Prevent JavaScript from accessing the cookie
		'samesite' => 'Strict' // Restrict cookie to same-site requests
	]);
}
?>