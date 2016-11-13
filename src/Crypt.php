<?php
/**
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @autor      Pep Lainez <jlainezs@cloudconceptes.com>
 * @copyright  Copyright (C) 2016 CloudConceptes
 * @license    GNU/GPL https://www.gnu.org/licenses/gpl-3.0.html
 */

namespace CloudConceptes\WOpenSSL;

/**
 * Encrypt / Decrypt functions
 *
 * @package CloudConceptes\WOpenSSL
 */
class Crypt
{
    const WOPENSSL_ENCRYPT_ERROR = 20000;
    const WOPENSSL_DECRYPT_ERROR = 21000;

    /**
     * Encrypts data with a certificate public key, so it can only be decrypted
     * with the certificate private key
     *
     * @param   string  $data            Data to be encrypted
     * @param   string  $certWithPubKey  Certificate with public key
     *
     * @return  string
     *
     * @throws \Exception
     *
     * @see  Crypt::decryptWithPrivateKey
     */
    public function encryptWithPublicKey($data, $certWithPubKey)
    {
        $result = '';
        $encryptedData = '';
        $pwd = openssl_random_pseudo_bytes(32);

        if ($publicKey = openssl_pkey_get_public("file://" . $certWithPubKey)) {
            $result = openssl_public_encrypt($pwd, $encryptedPwd, $publicKey);
            openssl_free_key($publicKey);
            $randomBytes = openssl_random_pseudo_bytes(16);
            $encryptedPwd = bin2hex($encryptedPwd);
            $encryptedData = openssl_encrypt($data, 'AES-256-CBC', $pwd, null, $randomBytes);
            $encryptedData = $encryptedPwd . '|' . $encryptedData . '|' . bin2hex($randomBytes);
        }

        if ($result == '') {
            throw new \Exception('Invalid public key', self::WOPENSSL_ENCRYPT_ERROR);
        }

        return $encryptedData;
    }

    /**
     * Decrypts data encripted with a certificate public key.
     *
     * @param   string  $encryptedData   Data to decrypt
     * @param   string  $privateKeyFile  Filename with the private key
     * @param   string  $password        Password for the private key
     *
     * @return string
     *
     * @throws \Exception
     *
     * @see  Crypt::encryptWithPublicKey
     */
    public function decryptWithPrivateKey($encryptedData, $privateKeyFile, $password)
    {
        $aParts = explode('|', $encryptedData);
        $encryptedPwd = hex2bin($aParts[0]);
        $encryptedData = $aParts[1];
        $randomBytes = hex2bin($aParts[2]);

        if ($privateKey = openssl_pkey_get_private('file://' . $privateKeyFile, $password)) {
            $result = openssl_private_decrypt($encryptedPwd, $pwd, $privateKey);
            openssl_free_key($privateKey);
            $decryptedData = openssl_decrypt($encryptedData, 'AES-256-CBC', $pwd, null, $randomBytes);

            if ($result) {
                return $decryptedData;
            }
        }

        throw new \Exception('Invalid private key', self::WOPENSSL_DECRYPT_ERROR);
    }
}
