# RSA

A Simple RSA Class For PHP


#Install

```
composer require "84hero/php-rsa:dev-master"

```
```
require_once "./vendor/autoload.php";

```

#Use
#####Generate RSA key
```
$pair = phpRSA\RSA::generatePair('./pem',2048);

```
#####Example 1
```
$sign = phpRSA\RSA::sign($data, './pem/privateKey.pem');
$res = phpRSA\RSA::verify($sign, $data, './pem/publicKey.pem');
$encStr = phpRSA\RSA::encrypt($data, './pem/publicKey.pem');
$decStr = phpRSA\RSA::decrypt($encStr, './pem/privateKey.pem');
```

#####Example 2
```
use phpRSA\RSA;
$RSA = new RSA('./pem/publicKey.pem','./pem/privateKey.pem');
$sign = $RSA->sign($data);
$res = $RSA->verify($sign, $data);
$encStr = $RSA->encrypt($data);
$decStr = $RSA->decrypt($encStr);

```

#####Example 3
```
$privateKeyContent = file_get_content('./pem/privateKey.pem');
$publicKeyContent = file_get_content('./pem/publicKey.pem');
  
$sign = phpRSA\RSA::sign($data,$privateKeyContent);
$res = phpRSA\RSA::verify($sign, $data, $publicKeyContent);
$encStr = phpRSA\RSA::encrypt($data, $publicKeyContent);
$decStr = phpRSA\RSA::decrypt($encStr, $privateKeyContent);
```