<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = trim($_REQUEST[ 'ip' ]);

	// Set blacklist
	$substitutions = array(
		'||' => '',
		'&'  => '',
		';'  => '',
		'| ' => '',
		'-'  => '',
		'$'  => '',
		'('  => '',
		')'  => '',
		'`'  => '',
	);

	// Remove any of the characters in the array (blacklist).
	$target = str_replace( array_keys( $substitutions ), $substitutions, $target );

	// Validate the target to ensure it is a valid IP address
	if (filter_var($target, FILTER_VALIDATE_IP) === false) {
		$html .= "<pre>Invalid IP address</pre>";
	} else {
		// Determine OS and execute the ping command.
		if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
			// Windows
			$cmd = shell_exec( 'ping  ' . escapeshellarg($target) );
		} else {
			// *nix
			$cmd = shell_exec( 'ping  -c 4 ' . escapeshellarg($target) );
		}

		// Feedback for the end user
		$html .= "<pre>{$cmd}</pre>";
	}
}

?>