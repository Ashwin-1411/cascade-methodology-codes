<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = time();
	setcookie("dvwaSession", $cookie_value, [
		'expires' => time() + 3600, // Set a reasonable expiration time (e.g., 1 hour)
		'path' => '/',
		'domain' => $_SERVER['HTTP_HOST'],
		'secure' => true, // Ensure the cookie is sent over HTTPS
		'httponly' => true, // Prevent JavaScript access to the cookie
		'samesite' => 'Strict' // Restrict cross-site requests
	]);
}
?>