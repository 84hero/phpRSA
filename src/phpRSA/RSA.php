<?php
namespace phpRSA;

/**
 * Class RSA
 * @package phpRSA
 */

class RSA
{
    private static $privKeyContent = '';
    private static $pubKeyContent = '';

    public function __construct($pubKey = '', $priv = '', $passphrase = '')
    {
        if ($pubKey !== '' && $priv !== '') {
            self::parsePrivKey($priv, $passphrase);
            self::parsePubKey($pubKey);
        }
    }

    private static function parsePrivKey($key, $passphrase = '')
    {

        //处理文件证书
        if (is_file($key)) {
            $key = file_get_contents($key);
        }

        $keyContent = $key;

        //处理压缩证书
        if (strpos($keyContent, '---') !== 0) {
            $keyContent = "-----BEGIN RSA PRIVATE KEY-----"
                . PHP_EOL . wordwrap($keyContent, 64, "\n", true)
                . PHP_EOL . "-----END RSA PRIVATE KEY-----";
        }

        //获取私钥密文
        if ($keyContent = openssl_get_privatekey($keyContent, $passphrase)) {
            self::$privKeyContent = $keyContent;
        }
    }

    private static function parsePubKey($key)
    {
        //处理文件证书
        if (is_file($key)) {
            $key = file_get_contents($key);
        }
        $keyContent = $key;
        //处理压缩证书
        if (strpos($keyContent, '---') !== 0) {
            $keyContent = "-----BEGIN PUBLIC KEY-----"
                . PHP_EOL . wordwrap($keyContent, 64, "\n", true)
                . PHP_EOL . "-----END PUBLIC KEY-----";
        }

        //获取私钥密文
        if ($keyContent = openssl_get_publickey($keyContent)) {
            self::$pubKeyContent = $keyContent;
        }

    }

    public static function generatePair($dir = '', $bits = 2048)
    {
        if ($bits < 512) {
            return false;
        }

        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $res = openssl_pkey_new($config);

        openssl_pkey_export($res, $privKey);

        $pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey["key"];

        if (is_dir($dir)) {
            file_put_contents("{$dir}/privateKey.pem", $privKey);
            file_put_contents("{$dir}/publicKey.pem", $pubKey);
        }
        $result['privKey'] = $privKey;
        $result['pubKey'] = $pubKey;
        return $result;
    }

    public static function encrypt($data, $publicKey = '')
    {
        // 加载公钥
        if ($publicKey !== '') {
            self::parsePubKey($publicKey);
        }
        $publicKey = self::$pubKeyContent;
        // 使用公钥进行加密
        $maxLen = 245;
        $count = intval(ceil(strlen($data) / $maxLen));

        $lastEncryptedData = '';

        for ($i = 0; $i < $count; $i++) {
            $encryptedData = '';
            openssl_public_encrypt(substr($data, $i * $maxLen, $maxLen), $encryptedData, $publicKey);
            $lastEncryptedData .= $encryptedData;
        }

        return base64_encode($lastEncryptedData);
    }

    public static function decrypt($data, $privateKey = '', $passphrase = '')
    {
        if ($privateKey !== '') {
            self::parsePrivKey($privateKey, $passphrase);
        }
        // 加载私钥
        $privateKey = self::$privKeyContent;

        $data = base64_decode($data);
        $maxLen = 256;

        $count = intval(ceil(strlen($data) / $maxLen));
        $lastSensitiveData = '';

        // 使用公钥进行加密
        for ($i = 0; $i < $count; $i++) {
            $sensitiveData = '';
            openssl_private_decrypt(substr($data, $i * $maxLen, $maxLen), $sensitiveData, $privateKey);
            $lastSensitiveData .= $sensitiveData;

        }

        return $lastSensitiveData;
    }

    public static function sign($data, $privateKey = '', $passphrase = '')
    {

        if ($privateKey !== '') {
            self::parsePrivKey($privateKey, $passphrase);
        }

        // 摘要及签名的算法
        $digestAlgo = 'sha512';
        $algo = OPENSSL_ALGO_SHA1;

        // 加载私钥
        $privateKey = self::$privKeyContent;
        // 生成摘要
        $digest = openssl_digest($data, $digestAlgo);
        // 签名
        $signature = '';

        openssl_sign($digest, $signature, $privateKey, $algo);

        $signature = base64_encode($signature);

        return $signature;
    }

    public static function verify($signature, $data, $publicKey = '')
    {
        // 摘要及签名的算法，同上面一致
        $digestAlgo = 'sha512';
        $algo = OPENSSL_ALGO_SHA1;
        // 加载公钥
        if ($publicKey !== '') {
            self::parsePubKey($publicKey);
        }
        $publicKey = self::$pubKeyContent;
        // 生成摘要
        $digest = openssl_digest($data, $digestAlgo);

        // 验签
        $verify = openssl_verify($digest, base64_decode($signature), $publicKey, $algo);
        return ($verify == 1); // int(1)表示验签成功
    }
}

?>