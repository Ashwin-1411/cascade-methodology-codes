<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = $_GET[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ?;";
			try {
				$stmt = $GLOBALS["___mysqli_ston"]->prepare($query);
				$stmt->bind_param("i", $id);
				$stmt->execute();
				$result = $stmt->get_result();
			} catch (Exception $e) {
				print "There was an error.";
				exit;
			}

			$exists = false;
			if ($result !== false) {
				$exists = ($result->num_rows > 0);
			}
			$stmt->close();
			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ?;";
			try {
				$stmt = $sqlite_db_connection->prepare($query);
				$stmt->bindValue(1, $id, SQLITE3_INTEGER);
				$results = $stmt->execute();
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}

			$stmt->close();
			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

}

?>