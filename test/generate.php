<?php

require '../src/phpRSA/RSA.php';


$sign = phpRSA\RSA::generatePair('./pem',256);

print_r($sign);

?>