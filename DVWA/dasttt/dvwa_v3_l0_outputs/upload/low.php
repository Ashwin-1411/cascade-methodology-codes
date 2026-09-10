<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// Validate file extension
	$file_extension = strtolower(pathinfo($target_path, PATHINFO_EXTENSION));
	if ($file_extension !== 'jpg' && $file_extension !== 'jpeg' && $file_extension !== 'png') {
		$html .= '<pre>Invalid file type. Only JPG, JPEG, and PNG files are allowed.</pre>';
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