<?php

$change = false;
$request_type = "html";
$return_message = "Request Failed";

if ($_SERVER['REQUEST_METHOD'] == "POST" && array_key_exists ("CONTENT_TYPE", $_SERVER) && $_SERVER['CONTENT_TYPE'] == "application/json") {
	$data = json_decode(file_get_contents('php://input'), true);
	$request_type = "json";
	if (array_key_exists("HTTP_USER_TOKEN", $_SERVER) &&
		array_key_exists("password_new", $data) &&
		array_key_exists("password_conf", $data) &&
		array_key_exists("Change", $data)) {
		$token = $_SERVER['HTTP_USER_TOKEN'];
		$pass_new = $data["password_new"];
		$pass_conf = $data["password_conf"];
		$change = true;
	}
} else {
	if (array_key_exists("user_token", $_REQUEST) &&
		array_key_exists("password_new", $_REQUEST) &&
		array_key_exists("password_conf", $_REQUEST) &&
		array_key_exists("Change", $_REQUEST)) {
		$token = $_REQUEST["user_token"];
		$pass_new = $_REQUEST["password_new"];
		$pass_conf = $_REQUEST["password_conf"];
		$change = true;
	}
}

if ($change) {
	// Check Anti-CSRF token
	checkToken( $token, $_SESSION[ 'session_token' ], 'index.php' );

	// Do the passwords match?
	if( $pass_new == $pass_conf ) {
		// They do!
		$pass_new = password_hash($pass_new, PASSWORD_DEFAULT);

		// Update the database
		$current_user = dvwaCurrentUser();
		$insert = "UPDATE `users` SET password = ? WHERE user = ?;";
		$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $insert);
		mysqli_stmt_bind_param($stmt, "ss", $pass_new, $current_user);
		$result = mysqli_stmt_execute($stmt);

		// Feedback for the user
		$return_message = "Password Changed.";
	} else {
		// Issue with passwords matching
		$return_message = "Passwords did not match.";
	}

	mysqli_close($GLOBALS["___mysqli_ston"]);

	if ($request_type == "json") {
		generateSessionToken();
		header ("Content-Type: application/json");
		print json_encode (array("Message" =>$return_message));
		exit;
	} else {
		$html .= "<pre>" . htmlspecialchars($return_message) . "</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>