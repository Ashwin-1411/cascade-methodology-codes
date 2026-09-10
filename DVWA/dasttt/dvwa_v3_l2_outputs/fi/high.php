<?php

// The page we wish to display
$file = $_GET['page'];

// Define a whitelist of allowed files
$allowed_files = ['file1.php', 'file2.php', 'file3.php']; // Add all allowed files here

// Check if the requested file is in the whitelist
if (!in_array($file, $allowed_files)) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

// Include the requested file
include $file;

?>