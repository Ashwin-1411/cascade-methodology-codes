<?php
$page[ 'body' ] .= <<<EOF
<script>
	function generate_token() {
		var phrase = document.getElementById("phrase").value;
		document.getElementById("token").value = '';
	}
</script>
EOF;

if (isset($_POST['phrase']) && isset($_POST['token'])) {
    if ($_POST['phrase'] !== 'success') {
        $page[ 'body' ] .= '<pre>Wrong phrase. Try again.</pre>';
    } else {
        $page[ 'body' ] .= '<pre>Well done!</pre>';
    }
}

$token = md5(str_rot13('success'));
$page[ 'body' ] .= "<input type='hidden' id='token' name='token' value='$token'>";
?>