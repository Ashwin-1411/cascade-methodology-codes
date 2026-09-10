<?php

// The page we wish to display
$file = $_GET['page'];

// Input validation
if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $file) || $file == "include.php") {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?>