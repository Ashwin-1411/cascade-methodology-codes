<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = time();
	setcookie("dvwaSession", $cookie_value, [
		'expires' => time() + 86400, // Set cookie to expire in 24 hours
		'path' => '/',
		'secure' => true, // Ensure cookie is sent over HTTPS
		'httponly' => true, // Prevent JavaScript access to the cookie
		'samesite' => 'Strict' // Restrict cookie to same-site requests
	]);
}
?>