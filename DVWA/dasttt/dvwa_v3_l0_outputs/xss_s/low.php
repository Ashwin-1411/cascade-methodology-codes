<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

	// Sanitize name input
	$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( ?, ? );";
	$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
	mysqli_stmt_bind_param($stmt, "ss", $message, $name);
	$result = mysqli_stmt_execute($stmt) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	mysqli_stmt_close($stmt);
	//mysql_close();
}

?>