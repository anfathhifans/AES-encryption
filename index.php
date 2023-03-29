<?php
include 'AES.class.php';

use MyLib\encryption\AES;

try {

    $encrypted = AES::encrypt('Lorum Ipsum');
    echo $encrypted;

    echo '<br/>';

    echo AES::decrypt($encrypted);

} catch (\Throwable $e) {
    die($e->getMessage());
}

?>