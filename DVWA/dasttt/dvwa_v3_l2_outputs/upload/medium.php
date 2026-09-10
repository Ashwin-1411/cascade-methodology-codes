<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// File information
	$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
	$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
	$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

	// Check if the file is a real image
	$image_info = getimagesize($_FILES['uploaded']['tmp_name']);
	if ($image_info !== false) {
		// Get the MIME type from the image info
		$mime_type = $image_info['mime'];

		// Is it an image?
		if( ( $mime_type == "image/jpeg" || $mime_type == "image/png" ) &&
			( $uploaded_size < 100000 ) ) {

			// Check the file extension
			$file_extension = strtolower(pathinfo($uploaded_name, PATHINFO_EXTENSION));
			if ($file_extension === 'jpg' || $file_extension === 'jpeg' || $file_extension === 'png') {
				// Can we move the file to the upload folder?
				if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
					// No
					$html .= '<pre>Your image was not uploaded.</pre>';
				}
				else {
					// Yes!
					$html .= "<pre>{$target_path} successfully uploaded!</pre>";
				}
			} else {
				// Invalid file extension
				$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
			}
		}
		else {
			// Invalid MIME type
			$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
		}
	} else {
		// Not a real image
		$html .= '<pre>Your image was not uploaded. Please upload a valid image file.</pre>';
	}
}

?>