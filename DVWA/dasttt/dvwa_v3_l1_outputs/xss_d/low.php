<?php

# Define the allowed languages
$allowed_languages = ['English', 'French', 'Spanish', 'German'];

# Get the default language from the GET parameter
$default_language = isset($_GET['default']) ? $_GET['default'] : 'English';

# Validate the default language against the whitelist
if (!in_array($default_language, $allowed_languages)) {
    // Redirect to the default language if it's not in the whitelist
    header("Location: ?default=English");
    exit();
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Language Selector</title>
</head>
<body>
    <form>
        <label for="language">Choose Language:</label>
        <select id="language" name="language">
            <?php
            foreach ($allowed_languages as $lang) {
                $selected = ($lang === $default_language) ? 'selected' : '';
                echo "<option value='$lang' $selected>$lang</option>";
            }
            ?>
        </select>
    </form>
</body>
</html>