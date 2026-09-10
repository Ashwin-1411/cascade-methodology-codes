<?php

session_start();

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id'])) {
		$_SESSION['last_session_id'] = 0;
	}
	$_SESSION['last_session_id']++;
	$cookie_value = $_SESSION['last_session_id'];
	setcookie("dvwaSession", $cookie_value, [
		'expires' => time() + 86400, // 1 day
		'path' => '/',
		'secure' => true,
		'httponly' => true,
		'samesite' => 'Strict'
	]);
}
?>