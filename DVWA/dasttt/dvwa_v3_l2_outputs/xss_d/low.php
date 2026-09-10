<?php

if (array_key_exists('default', $_GET)) {
    switch ($_GET['default']) {
        case 'French':
        case 'English':
        case 'German':
        case 'Spanish':
            break;
        default:
            header('Location: ?default=English');
            exit;
    }
}

?>