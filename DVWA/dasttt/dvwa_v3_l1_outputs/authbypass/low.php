<?php
/*

Nothing to see here for this vulnerability, have a look
instead at the dvwaHtmlEcho function in:

* dvwa/includes/dvwaPage.inc.php

*/

// Check if the current user is 'admin'
if (dvwaCurrentUser() !== 'admin') {
    echo 'Unauthorised';
    http_response_code(403);
    exit;
}

?>