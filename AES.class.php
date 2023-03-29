<?php
namespace MyLib\encryption;

class AES
{
    const KEY_1 = 'jZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=';
    const KEY_2 = '1xkOsZT/lJRiVRS20XjIf5nFlz4ow5iWnSIz8pYKVz4=';

    # supported value from hash_hmac_algos()
    # https://www.php.net/manual/en/function.hash-hmac-algos.php
    const HMAC_KEY = 'sha3-512'; 

    # supported value from openssl_get_cipher_methods()
    # https://www.php.net/manual/en/function.openssl-get-cipher-methods.php
    const ENCRYPT_METHOD = 'aes-256-cbc'; 
    
    public function __construct(){}

    public function __validate($data, $encryptMethod, $hashKey)
    {
        if ($data === false) {
            throw new \UnexpectedValueException("Invalid data format!");
        }
        if (!in_array($encryptMethod, openssl_get_cipher_methods())) {
            throw new \UnexpectedValueException(sprintf('Invalid encryption method : %s', $encryptMethod));
        }
        if (!in_array($hashKey, hash_hmac_algos())) {
            throw new \UnexpectedValueException(sprintf('Invalid hashing algorithm : %s', $hashKey));
        }
    }

    public static function encrypt(string $plaintext, $encryptMethod = self::ENCRYPT_METHOD, $hashKey = self::HMAC_KEY)
    {   
        self::__validate($plaintext, $encryptMethod, $hashKey);

        $iv_length = openssl_cipher_iv_length($encryptMethod);
        $iv = openssl_random_pseudo_bytes($iv_length);
                
        $ciphertext = openssl_encrypt($plaintext, $encryptMethod, base64_decode(self::KEY_1), OPENSSL_RAW_DATA ,$iv);    
        $mac = hash_hmac($hashKey, $ciphertext, base64_decode(self::KEY_2), TRUE);
        $encrypted = $iv . $mac . $ciphertext;     

        $output = base64_encode($encrypted);    
        return $output;
    }

    public static function decrypt(string $ciphertext, $encryptMethod = self::ENCRYPT_METHOD, $hashKey = self::HMAC_KEY)
    {   
        self::__validate($ciphertext, $encryptMethod, $hashKey);
           
        $mix = base64_decode($ciphertext);
            
        $iv_length = openssl_cipher_iv_length($encryptMethod);
        $iv = substr($mix, 0, $iv_length);

        $mac = substr($mix, $iv_length, 64);
        $first_encrypted = substr($mix, $iv_length+64);
                    
        $plaintext = openssl_decrypt($first_encrypted, $encryptMethod, base64_decode(self::KEY_1), OPENSSL_RAW_DATA, $iv);
        $mac_new = hash_hmac($hashKey, $first_encrypted, base64_decode(self::KEY_2), TRUE);

        if (!hash_equals($mac, $mac_new)) {
            throw new \Exception('Invalid Encrypted Value');
        }

        return $plaintext;
    }

    public static function supported_encryption_methods()
    {
        return openssl_get_cipher_methods();
    }

    public static function supported_hashing_algorithms()
    {
        return hash_hmac_algos();
    }

}
?>