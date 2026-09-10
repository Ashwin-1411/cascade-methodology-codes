<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Sanitize username input
	$user = $_GET[ 'username' ];
	$user = filter_var($user, FILTER_SANITIZE_STRING);

	// Sanitize password input
	$pass = $_GET[ 'password' ];
	$pass = filter_var($pass, FILTER_SANITIZE_STRING);
	$pass = md5( $pass );

	// Prepare and execute the query
	$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT * FROM `users` WHERE user = ? AND password = ?");
	$stmt->bind_param("ss", $user, $pass);
	$stmt->execute();
	$result = $stmt->get_result();

	if( $result->num_rows == 1 ) {
		// Get users details
		$row    = $result->fetch_assoc();
		$avatar = htmlspecialchars($row["avatar"]);

		// Login successful
		$html .= "<p>Welcome to the password protected area " . htmlspecialchars($user) . "</p>";
		$html .= "<img src=\"" . htmlspecialchars($avatar) . "\" />";
	}
	else {
		// Login failed
		sleep( 2 );
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	$stmt->close();
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>