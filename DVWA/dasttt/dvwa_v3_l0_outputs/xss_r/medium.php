<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = htmlspecialchars($_GET[ 'name' ], ENT_QUOTES, 'UTF-8');

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>