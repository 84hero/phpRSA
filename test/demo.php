<?php

require '../src/phpRSA/RSA.php';

$data = 'signStr-' . time();

$sign = phpRSA\RSA::sign($data, './pem/privateKey.pem');
$res = phpRSA\RSA::verify($sign, $data, './pem/publicKey.pem');
$encStr = phpRSA\RSA::encrypt($data, './pem/publicKey.pem');
$decStr = phpRSA\RSA::decrypt($encStr, './pem/privateKey.pem');

var_dump($sign);
var_dump($res);
var_dump($encStr);
var_dump($decStr);


$RSA = new phpRSA\RSA('./pem/publicKey.pem','./pem/privateKey.pem');
$sign = $RSA->sign($data);
$res = $RSA->verify($sign, $data);
$encStr = $RSA->encrypt($data);
$decStr = $RSA->decrypt($encStr);

var_dump($sign);
var_dump($res);
var_dump($encStr);
var_dump($decStr);


?>