<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Validate input to ensure it is a valid IP address
	if (filter_var($target, FILTER_VALIDATE_IP) === false) {
		die("Invalid IP address");
	}

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = escapeshellarg($target);
		$cmd = shell_exec( 'ping  ' . $cmd );
	}
	else {
		// *nix
		$cmd = escapeshellarg($target);
		$cmd = shell_exec( 'ping  -c 4 ' . $cmd );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>