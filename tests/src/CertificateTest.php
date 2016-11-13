<?php
/**
 * User: jlainezs
 * Date: 11/11/2016
 * Time: 18:30
 */

namespace CloudConceptes\WOpenSSL\Test;

use CloudConceptes\WOpenSSL\Certificate;
use \Exception;

/**
 * Test the creation and handling of certificates
 *
 * @package CloudConceptes\WOpenSSL\Test
 *
 * @coversDefaultClass  \CloudConceptes\WOpenSSL\Certificate
 */
class CertificateTest extends BaseTest
{
    /**
     * {@inheritdoc}
     */
    public function setUp()
    {
        parent::setUp();
        $this->removeFile($this->tstCer());
        $this->removeFile($this->tstPem());
        $this->removeFile($this->tstCer('b'));
        $this->removeFile($this->tstPem('b'));
    }

    /**
     * @covers ::__construct
     * @covers ::create
     * @use ::getInformation
     */
    public function testCreate()
    {
        list($cert, $dn) = $this->createACertificate();
        $this->assertFileExists($this->tstPem());
        $this->assertFileExists($this->tstCer());

        $certData = $cert->getInformation($this->tstCer());
        $this->assertEquals($dn['emailAddress'], $certData['subject']['emailAddress']);
    }

    /**
     * @covers ::__construct
     * @covers ::create
     * @expectedException Exception
     */
    public function testCreateExceptionExpected()
    {
        $cert = new Certificate(TST_OPENSSL_BADCONFIG);
        $dn = $this->getDnA();
        $cert->create($dn, 100 * 365, $this->password(), TST_VAULT_DIR, self::CERT_NAME);
    }

    /**
     * @covers ::__construct
     * @covers ::create
     * @expectedException Exception
     */
    public function testCreateNoConfigurationGiven()
    {
        $cert = new Certificate('');
        $dn = $this->getDnA();
        $cert->create($dn, 100 * 365, $this->password(), TST_VAULT_DIR, self::CERT_NAME);
    }

    /**
     * @covers ::__construct
     * @covers ::create
     * @expectedException Exception
     */
    public function testCreateExtraConfigurationOptions()
    {
        $cert = new Certificate('');
        $dn = $this->getDnA();
        $extraConfig = array('private_key_bits' => 1024);
        $cert->create($dn, 100 * 365, $this->password(), TST_VAULT_DIR, self::CERT_NAME, null, null, $extraConfig);
        $info = $cert->getInformation(TST_VAULT_DIR . '/' . self::CERT_NAME);
        $this->assertEquals($dn['emailAddress'], $info['subject']['emailAddress']);
    }

    /**
     * @covers ::__construct
     * @covers ::create
     * @expectedException Exception
     */
    public function testCreateNoDNGiven()
    {
        $cert = new Certificate(TST_OPENSSL_CONFIG);
        $dn = null;
        $cert->create($dn, 100 * 365, $this->password(), TST_VAULT_DIR, self::CERT_NAME);
    }

    /**
     * @covers ::create
     */
    public function testCreateWithParentCertificate()
    {
        $cert = new Certificate(TST_OPENSSL_CONFIG);
        $dna = $this->getDnA();
        $days = 100;
        $cert->create($dna, $duration, $this->password(), TST_VAULT_DIR, self::CERT_NAME);

        $cacert = "file://" . $this->tstCer();
        $capem = array("file://" . $this->tstPem(), $this->password());
        $certFName = self::CERT_NAME . 'b';

        $cert->create($this->getDnB(), $days, $this->password('b'), TST_VAULT_DIR, $certFName, $cacert, $capem);
        $this->assertFileExists($this->tstCer('b'));
        $this->assertFileExists($this->tstPem('b'));
    }

    /**
     * @covers ::create
     * @covers ::getInformation
     */
    public function testGetInformation()
    {
        list($cert, $dn) = $this->createACertificate();

        $certData = $cert->getInformation($this->tstCer());
        $this->assertTrue(isset($certData['subject']));

        foreach ($certData['subject'] as $key => $value) {
            switch ($key)
            {
                case 'C':
                    $keyalt = 'countryName';
                    break;
                case 'ST':
                    $keyalt = 'stateOrProvinceName';
                    break;
                case 'L':
                    $keyalt = 'localityName';
                    break;
                case 'O':
                    $keyalt = 'organizationName';
                    break;
                case 'OU':
                    $keyalt = 'organizationalUnitName';
                    break;
                case 'CN':
                    $keyalt = 'commonName';
                    break;
                default:
                    $keyalt = $key;
                    break;
            }
            $this->assertEquals($dn[$keyalt], $value);
        }
    }

    /**
     * @covers ::create
     * @covers ::getInformation
     * @expectedException \Exception
     */
    public function testGetInformationNonExistentCertificate()
    {
        list($cert, $dn) = $this->createACertificate();
        $certData = $cert->getInformation('nonexistentcertificate.cert');
    }

    /**
     * @covers ::getOpenSSLErrors
     */
    public function testGetOpenSSLErrorsNoError()
    {
        $openSSLErrorsMethod = self::getMethod('CloudConceptes\WOpenSSL\Certificate', 'getOpenSSLErrors');
        $obj = new Certificate(TST_OPENSSL_CONFIG);
        $openSSLErrorsMethod->invoke($obj);
    }

    /**
     * @covers ::getOpenSSLErrors
     */
    public function testGetOpenSSLErrors()
    {
        $openSSLErrorsMethod = self::getMethod('CloudConceptes\WOpenSSL\Certificate', 'getOpenSSLErrors');
        $obj = new Certificate(TST_OPENSSL_BADCONFIG);

        try {
            // Force an openssl error by parsing an empty certificate
            openssl_x509_parse('');
            $openSSLErrorsMethod->invoke($obj);
        } catch (Exception $e) {
            $this->assertTrue($e !== null);
            $this->assertTrue($e->getCode() === Certificate::WOPENSSL_CREATE_CERTIFICATE_ERROR);
            return;
        }

        $this->fail('No exception thrown');
    }
}
