<?php

session_start();

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id_high'])) {
		$_SESSION['last_session_id_high'] = 0;
	}
	$_SESSION['last_session_id_high']++;
	$cookie_value = hash('sha256', $_SESSION['last_session_id_high'] . uniqid() . session_id());
	setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], true, true);
}

?>