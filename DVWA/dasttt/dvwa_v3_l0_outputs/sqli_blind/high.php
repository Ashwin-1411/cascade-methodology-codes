<?php

if( isset( $_COOKIE[ 'id' ] ) ) {
	// Get input
	$id = $_COOKIE[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;";
			try {
				$stmt = $GLOBALS["___mysqli_ston"]->prepare($query);
				$stmt->bind_param("s", $id);
				$stmt->execute();
				$result = $stmt->get_result();
			} catch (Exception $e) {
				$result = false;
			}

			$exists = false;
			if ($result !== false) {
				// Get results
				$exists = ($result->num_rows > 0);
			}

			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;";
			try {
				$stmt = $sqlite_db_connection->prepare($query);
				$stmt->bindValue(1, $id);
				$stmt->execute();
				$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
				$exists = !empty($results);
			} catch(Exception $e) {
				$exists = false;
			}

			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	}
	else {
		// Might sleep a random amount
		if( rand( 0, 5 ) == 3 ) {
			sleep( rand( 2, 4 ) );
		}

		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

?>