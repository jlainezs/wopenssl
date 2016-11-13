<?php
/**
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @autor      Pep Lainez <jlainezs@cloudconceptes.com>
 * @copyright  Copyright (C) 2016 CloudConceptes
 * @license    GNU/GPL https://www.gnu.org/licenses/gpl-3.0.html
 */

namespace CloudConceptes\WOpenSSL\Test;

use CloudConceptes\WOpenSSL\Certificate;
use ReflectionClass;

/**
 * Basic class for testing extensions handling
 *
 * @package    Phing-tasks\Joomla
 * @subpackage Tests\JCopy
 * @author     Pep Lainez <contacte@econceptes.com>
 * @copyright  2016 Pep Lainez
 * @license    LGPL v3.0
 */
abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
    const CERT_NAME = 'acertificate';

    /**
     * Remove the given file if exists.
     *
     * @param   string  $file  File to remove.
     */
    public function removeFile($file)
    {
        if (file_exists($file)) {
            unlink($file);
        }
    }

    /**
     * Full path to .pem file
     *
     * @return string
     */
    public function tstPem($suffix = '')
    {
        return TST_VAULT_DIR . '/' . self::CERT_NAME . $suffix . '.pem';
    }

    /**
     * Full path to .cer file
     *
     * @return string
     */
    public function tstCer($suffix = '')
    {
        return TST_VAULT_DIR . '/' . self::CERT_NAME . $suffix . '.cer';
    }


    /**
     * Gets DN for the certificate A
     *
     * @return array
     */
    public function getDnA()
    {
        return array(
            "countryName" => "UK",
            "stateOrProvinceName" => "Somerset",
            "localityName" => "Glastonbury",
            "organizationName" => "The Brain Room Limited",
            "organizationalUnitName" => "PHP Documentation Team",
            "commonName" => "Wez Furlong",
            "emailAddress" => "wez@example.com"
        );
    }

    /**
     * Gets DN for the certificate B
     *
     * @return array
     */
    public function getDnB()
    {
        return array(
            "countryName" => "ES",
            "stateOrProvinceName" => "Barcelona",
            "localityName" => "Barcelona",
            "organizationName" => "XYZ",
            "organizationalUnitName" => "THAT",
            "commonName" => "Pep Lainez",
            "emailAddress" => "peplainez@example.com"
        );
    }

    public function password($suffix = '')
    {
        return 'tstpwd' . $suffix;
    }

    /**
     * Creates a new certificate
     *
     * @param   string  $suffix  Suffix to add to the generated file
     *
     * @return array
     */
    public function createACertificate($suffix = '')
    {
        $cert = new Certificate(TST_OPENSSL_CONFIG);
        $dn = $this->getDnA();
        $cert->create($dn, 100 * 365, $this->password(), TST_VAULT_DIR, self::CERT_NAME . $suffix);

        return array($cert, $dn);
    }

    /**
     * Gets a reference to a protected method
     *
     * @param   string  $className   Name of the class to get the method
     * @param   string  $methodName  Method name
     *
     * @return mixed
     *
     * @link http://stackoverflow.com/questions/249664/best-practices-to-test-protected-methods-with-phpunit
     */
    protected static function getMethod($className, $methodName)
    {
        $class = new ReflectionClass($className);
        $method = $class->getMethod($methodName);
        $method->setAccessible(true);

        return $method;
    }
}
