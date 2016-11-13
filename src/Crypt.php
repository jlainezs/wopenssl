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

        if ($publicKey = openssl_pkey_get_public("file://" . $certWithPubKey)) {
            $result = openssl_public_encrypt($data, $encryptedData, $publicKey);
            openssl_free_key($publicKey);
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
        if ($privateKey = openssl_pkey_get_private('file://' . $privateKeyFile, $password)) {
            $result = openssl_private_decrypt($encryptedData, $decryptedData, $privateKey);
            openssl_free_key($privateKey);

            if ($result) {
                return $decryptedData;
            }
        }

        throw new \Exception('Invalid private key', self::WOPENSSL_DECRYPT_ERROR);
    }
}
