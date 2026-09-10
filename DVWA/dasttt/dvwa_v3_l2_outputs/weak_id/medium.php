<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// Generate a strong random cookie value
	$cookie_value = bin2hex(random_bytes(32));
	setcookie("dvwaSession", $cookie_value, [
		'secure' => true,
		'httponly' => true,
	]);
}
?>