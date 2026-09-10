<?php

session_start();

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id'])) {
		$_SESSION['last_session_id'] = 0;
	}
	$_SESSION['last_session_id']++;
	
	// Generate a strong random cookie value
	$cookie_value = bin2hex(random_bytes(32));
	setcookie("dvwaSession", $cookie_value, [
		'expires' => time() + 86400, // 1 day
		'secure' => true,
		'httponly' => true,
		'samesite' => 'Strict'
	]);
}
?>