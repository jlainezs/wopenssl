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

use CloudConceptes\WOpenSSL\Signature;

/**
 * Test the creation and handling of certificates
 *
 * @package CloudConceptes\WOpenSSL\Test
 *
 * @coversDefaultClass \CloudConceptes\WOpenSSL\Signature
 */
class SignatureTest extends BaseTest
{
    /**
     * @covers ::sign
     * @covers ::verify
     */
    public function testSign()
    {
        list($cert, $dn) = $this->createACertificate();
        $this->assertTrue($cert !== null);
        $this->assertTrue($dn !== null);
        $signature = new Signature;
        $data = 'This is the data to sign';

        $sign = $signature->sign($data, $this->tstPem(), $this->password());
        $this->assertTrue($sign != '');

        $result = $signature->verify($data, $sign, $this->tstCer());
        $this->assertTrue($result);
    }

    /**
     * @covers ::sign
     * @expectedException \Exception
     */
    public function testSignFailNonExistentPrivateKeyFile()
    {
        $data = 'This is the data to sign';
        $signature = new Signature;
        $signature->sign($data, 'non-existent-file', $this->password());

    }
}
