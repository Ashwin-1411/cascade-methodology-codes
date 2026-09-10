<?php
// Remove the client-side script inclusion
// $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js"></script>';

// Add server-side validation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $phrase = $_POST['phrase'];
    $expectedToken = strrev('XX' . $phrase . 'XX');
    
    if ($phrase === 'success' && isset($_POST['token']) && $_POST['token'] === $expectedToken) {
        // Process the valid request
        $page[ 'body' ] .= "Success!";
    } else {
        // Handle invalid request
        $page[ 'body' ] .= "Invalid input or token.";
    }
}
?>