<?php
/**
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @autor      Pep Lainez <jlainezs@cloudconceptes.com>
 * @copyright  Copyright (C) 2016 CloudConceptes
 * @license    GNU/GPL https://www.gnu.org/licenses/gpl-3.0.html
 */

require_once '../vendor/autoload.php';
require_once 'testClasses/BaseTest.php';

define('TST_HOME', dirname(realpath(__FILE__)));
define('TST_VAULT_DIR', TST_HOME . '/output');
define('TST_OPENSSL_CONFIG', TST_HOME . '/openssl.cnf');
define('TST_OPENSSL_BADCONFIG', TST_HOME . '/openssl-bad.cnf');
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_STRICT);
