<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = htmlspecialchars( strip_tags( $message ) );

	// Sanitize name input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );

	// Prepare and execute query
	$stmt = $GLOBALS["___mysqli_ston"]->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)");
	$stmt->bind_param("ss", $message, $name);
	$stmt->execute();
	$stmt->close();

	//mysql_close();
}

?>