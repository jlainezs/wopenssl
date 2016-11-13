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

use CloudConceptes\WOpenSSL\Crypt;
use \Exception;

/**
 * Test the creation and handling of certificates
 *
 * @package CloudConceptes\WOpenSSL\Test
 *
 * @coversDefaultClass \CloudConceptes\WOpenSSL\Crypt
 */
class EncryptTest extends BaseTest
{
    /**
     * @covers ::encryptWithPublicKey
     * @covers ::decryptWithPrivateKey
     */
    public function testEncryptWithPublicKeyAndDecryptWithPrivateKey()
    {
        list($cert, $dn) = $this->createACertificate();
        $data = 'This is the data to encrypt';
        $encrypt = new Crypt();
        $encryptedData = $encrypt->encryptWithPublicKey($data, $this->tstCer());
        $this->assertTrue($encryptedData != '');
        $this->assertTrue($encryptedData != $data);

        $decriptedData = $encrypt->decryptWithPrivateKey($encryptedData, $this->tstPem(), $this->password());
        $this->assertEquals($data, $decriptedData);
    }

    /**
     * @covers ::encryptWithPublicKey
     * @expectedException \Exception
     */
    public function testEncryptWithPublicKeyFail()
    {
        list($cert, $dn) = $this->createACertificate();
        $data = 'This is the data to encrypt';
        $encrypt = new Crypt();
        $encrypt->encryptWithPublicKey($data, $this->tstCer('non-existent-file'));
    }

    /**
     * @covers ::encryptWithPublicKey
     * @covers ::decryptWithPrivateKey
     * @expectedException \Exception
     */
    public function testDecryptWithPublicKeyInvalidKey()
    {
        list($cert, $dn) = $this->createACertificate();
        $data = 'This is the data to encrypt';
        $encrypt = new Crypt();
        $encryptedData = $encrypt->encryptWithPublicKey($data, $this->tstCer());
        $this->assertTrue($encryptedData != '');
        $this->assertTrue($encryptedData != $data);

        $encrypt->decryptWithPrivateKey($encryptedData, 'non-existent-file', $this->password());
    }

    /**
     * @covers ::encryptWithPublicKey
     * @covers ::decryptWithPrivateKey
     * @expectedException \Exception
     */
    public function testDecryptWithPublicKeyUsingOtherKey()
    {
        list($cert, $dn) = $this->createACertificate();
        list($cert1, $dn1) = $this->createACertificate('1');
        $data = 'This is the data to encrypt';
        $encrypt = new Crypt();
        $encryptedData = $encrypt->encryptWithPublicKey($data, $this->tstCer());
        $this->assertTrue($encryptedData != '');
        $this->assertTrue($encryptedData != $data);

        $encrypt->decryptWithPrivateKey($encryptedData, $this->tstPem('1'), $this->password());
    }

    public function testEncryptDecryptLargeData()
    {
        list($cert, $dn) = $this->createACertificate();
        $data = bin2hex(openssl_random_pseudo_bytes(2048));
        $crypt = new Crypt;
        $encryptedData = $crypt->encryptWithPublicKey($data, $this->tstCer());
        $decryptedData = $crypt->decryptWithPrivateKey($encryptedData, $this->tstPem(), $this->password());

        $this->assertEquals($data, $decryptedData);
    }
}
