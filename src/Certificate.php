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
 * Manages the generation of certificates
 *
 * @package CloudConceptes\WOpenSSL
 */
class Certificate
{
    const WOPENSSL_CREATE_CERTIFICATE_ERROR = 10000;
    const WOPENSSL_CERTIFICATENOTFOUND_ERROR = 11000;

    /**
     * Path to the openssl.cnf file
     * @var string
     */
    private $opensslconfig;

    /**
     * Certificate constructor.
     *
     * @param   string  $opensslcfgPath  Full path to the openssl.cnf file
     */
    public function __construct($opensslcfgPath)
    {
        $this->opensslconfig = $opensslcfgPath;
    }

    /**
     * Create a digital certificate with the public key embeded on it using OpenSSL functions.
     * If $cacert and $capem are null then the certificate created is a root certificate.
     *
     * @param   array        $dn                   Certificate data
     * @param   int          $duration             Number of days which the certificate is valid
     * @param   string       $password             Password of the private key
     * @param   string       $vaultPath            Where to store the certificate
     * @param   string       $fileNameNoExtension  File name without extension
     * @param   string|null  $cacert               CA root certificate file
     * @param   array        $capem                Private key and its password of the CA root certificate file
     * @param   array        $additionalConfig     Additional configuration parameters as stated on php reference
     *
     * @return array If there are any errors
     *
     * @throws \Exception If there are any errors
     *
     * @author  Pep Lainez <jlainezs@cloudconceptes.com>
     *
     * @see http://www.php.net/manual/en/function.openssl-csr-new.php
     */
    public function create(
        $dn,
        $duration,
        $password,
        $vaultPath,
        $fileNameNoExtension,
        $cacert = null,
        $capem = null,
        $additionalConfig = null
    ) {
        try {
            $configParams = array('config' => $this->opensslconfig);
            $result = null;

            if ($additionalConfig) {
                $configParams = array_merge($configParams, $additionalConfig);
            }

            // Generate a new private (and public) key pair
            if (($privateKey = openssl_pkey_new($configParams)) !== false) {
                // Generates a certificate signing request
                $csr = openssl_csr_new($dn, $privateKey, $configParams);

                // And signs it using the $cacert
                $usePemOrPrivKey = (is_null($capem) ? $privateKey : $capem);
                if (($sscert = openssl_csr_sign($csr, $cacert, $usePemOrPrivKey, $duration, $configParams)) !== false) {

                    // Export the certificate and the private key
                    openssl_x509_export($sscert, $certout);
                    openssl_pkey_export($privateKey, $pkout, $password, $configParams);

                    $file = $vaultPath . "/" . $fileNameNoExtension;

                    file_put_contents($file . ".cer", $certout);
                    file_put_contents($file . ".pem", $pkout);

                    $result = array('cer' => $certout, 'pem' => $pkout, 'file' => $fileNameNoExtension);
                }
            }
            // Gets any errors that occurred here
            self::getOpenSSLErrors();

        } catch (\Exception $e) {
            throw new \Exception($e->getMessage(), self::WOPENSSL_CREATE_CERTIFICATE_ERROR);
        }

        return $result;
    }

    /**
     * Gets data from a certificate file
     *
     * @param   string  $certificateFile  Certificate file name
     *
     * @return array
     *
     * @throws \Exception
     */
    public function getInformation($certificateFile)
    {
        if (file_exists($certificateFile)) {
            $certContent = file_get_contents($certificateFile);
            $cert = openssl_x509_read($certContent);

            return openssl_x509_parse($cert);
        }

        throw new \Exception('Certificate file not found', self::WOPENSSL_CERTIFICATENOTFOUND_ERROR);
    }

    /**
     * Logs OpenSSL errors and raises an exception if an error is found
     *
     * @return void
     *
     * @throws \Exception
     */
    protected function getOpenSSLErrors()
    {
        $allErrors = array();

        while (($e = openssl_error_string()) !== false) {
            $allErrors[] = $e;
        }

        if (count($allErrors)) {
            throw new \Exception(implode("\n", $allErrors), self::WOPENSSL_CREATE_CERTIFICATE_ERROR);
        }
    }
}
