<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// Check if the file is an actual image
	$image_info = getimagesize($_FILES['uploaded']['tmp_name']);
	if ($image_info === false) {
		$html .= '<pre>Invalid image file.</pre>';
	} else {
		// Get the MIME type and file extension
		$file_type = $_FILES['uploaded']['type'];
		$file_extension = strtolower(pathinfo($_FILES['uploaded']['name'], PATHINFO_EXTENSION));

		// Define allowed MIME types and extensions
		$allowed_types = ['image/jpeg', 'image/png'];
		$allowed_extensions = ['jpg', 'jpeg', 'png'];

		// Validate MIME type and file extension
		if (in_array($file_type, $allowed_types) && in_array($file_extension, $allowed_extensions)) {
			// Can we move the file to the upload folder?
			if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
				// No
				$html .= '<pre>Your image was not uploaded.</pre>';
			} else {
				// Yes!
				$html .= "<pre>{$target_path} successfully uploaded!</pre>";
			}
		} else {
			$html .= '<pre>Unsupported file type or extension.</pre>';
		}
	}
}

?>