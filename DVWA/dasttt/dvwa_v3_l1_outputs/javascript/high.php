<?php
// Remove the client-side script inclusion
// $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js"></script>';

// Add server-side validation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['phrase']) && $_POST['phrase'] === 'success') {
    // Compute the token server-side
    $token = hash('sha256', hash('sha256', 'XX' . strrev($_POST['phrase'])) . 'ZZ');
    // Proceed with the token as needed
} else {
    // Handle invalid input or request method
}
?>