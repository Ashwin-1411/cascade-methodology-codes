<?php

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input
	$id = $_SESSION[ 'id' ];

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;";
			$stmt = $GLOBALS["___mysqli_ston"]->prepare($query);
			$stmt->bind_param("i", $id);
			$stmt->execute();
			$result = $stmt->get_result();

			// Get results
			while( $row = $result->fetch_assoc() ) {
				// Get values
				$first = htmlspecialchars($row["first_name"]);
				$last  = htmlspecialchars($row["last_name"]);

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			$stmt->close();
			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);		
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;";
			$stmt = $sqlite_db_connection->prepare($query);
			$stmt->bindValue(1, $id, SQLITE3_INTEGER);
			$results = $stmt->execute();

			if ($results) {
				while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
					// Get values
					$first = htmlspecialchars($row["first_name"]);
					$last  = htmlspecialchars($row["last_name"]);

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db_connection->lastErrorMsg();
			}
			$stmt->close();
			break;
	}
}

?>