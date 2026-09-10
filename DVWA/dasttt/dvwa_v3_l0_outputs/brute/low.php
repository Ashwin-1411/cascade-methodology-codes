<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];

	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );

	// Prepare the database query
	$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT * FROM `users` WHERE user = ? AND password = ?");
	$stmt->bind_param("ss", $user, $pass);
	$stmt->execute();
	$result = $stmt->get_result();

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = htmlspecialchars($row["avatar"]);

		// Login successful
		$html .= "<p>Welcome to the password protected area " . htmlspecialchars($user) . "</p>";
		$html .= "<img src=\"" . $avatar . "\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	$stmt->close();
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>