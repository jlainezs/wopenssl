<?php
/**
 * User: jlainezs
 * Date: 12/11/2016
 * Time: 19:19
 */

namespace CloudConceptes\WOpenSSL;

/**
 *
 * @package CloudConceptes\WOpenSSL
 */
class Signature
{
    const WOSSL_ERROR_VERIFY = 30000;
    const WOSSL_ERROR_SIGN = 31000;

    /**
     * Validates the data signature with the public key contained in the given public key file
     *
     * @param   string  $data                Data signed
     * @param   string  $signature           Signature to validate
     * @param   string  $publicKeyFile       Public key used to validate the signature
     * @param   int     $signatureAlgorithm  Signature algorithm. Defaults to OPENSSL_ALGO_SHA256
     *
     * @return boolean
     *
     * @link http://php.net/manual/en/openssl.signature-algos.php
     */
    public function verify($data, $signature, $publicKeyFile, $signatureAlgorithm = OPENSSL_ALGO_SHA256)
    {
        $result = 0;

        if ($publicKey = openssl_pkey_get_public("file://" . $publicKeyFile)) {
            $result = openssl_verify($data, $signature, $publicKey, $signatureAlgorithm);
            openssl_free_key($publicKey);

        }

        return ($result == 1);
    }

    /**
     * Signs the given data
     *
     * @param   string  $data                Data to sign
     * @param   string  $privateKeyFile      Private key file used to sign the data
     * @param   string  $password            Private key password
     * @param   int     $signatureAlgorithm  Signature algorithm. Defaults to OPENSSL_ALGO_SHA256
     *
     * @return string
     *
     * @throws \Exception
     *
     * @link http://php.net/manual/en/openssl.signature-algos.php
     */
    public function sign($data, $privateKeyFile, $password, $signatureAlgorithm = OPENSSL_ALGO_SHA256)
    {
        $signature = '';
        $result = false;

        if ($privateKey = openssl_pkey_get_private("file://" . $privateKeyFile, $password)) {
            $result = openssl_sign($data, $signature, $privateKey, $signatureAlgorithm);
            openssl_free_key($privateKey);
        }

        if (!$result || ($signature == '')) {
            throw new \Exception('Signature fails', self::WOSSL_ERROR_SIGN);
        }

        return $signature;
    }
}
