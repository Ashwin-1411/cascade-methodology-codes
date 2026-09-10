<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// Validate the file extension
	$file_extension = strtolower(pathinfo($target_path, PATHINFO_EXTENSION));
	$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];

	if (!in_array($file_extension, $allowed_extensions)) {
		$html .= '<pre>Invalid file type. Only JPG, JPEG, PNG, and GIF files are allowed.</pre>';
	} else {
		// Can we move the file to the upload folder?
		if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
			// No
			$html .= '<pre>Your image was not uploaded.</pre>';
		} else {
			// Yes!
			$html .= "<pre>{$target_path} successfully uploaded!</pre>";
		}
	}
}

?>