<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = htmlspecialchars( strip_tags( $message ) );

	// Sanitize name input
	$name = htmlspecialchars( str_replace( '<script>', '', $name ) );

	// Prepare and bind
	$stmt = $GLOBALS["___mysqli_ston"]->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)");
	$stmt->bind_param("ss", $message, $name);

	// Execute the statement
	$stmt->execute();

	// Close the statement
	$stmt->close();

	//mysql_close();
}

?>