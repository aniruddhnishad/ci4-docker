<?php

namespace App\Libraries;

use Carbon\Carbon;

class Utility
{

    protected $itoa64;
    protected $iteration_count_log2;
    protected $portable_hashes;
    protected $random_state;

    public function __construct($iteration_count_log2 = 9, $portable_hashes = false)

    {
        $this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31) {
            $iteration_count_log2 = 8;
        }
        $this->iteration_count_log2 = $iteration_count_log2;
        $this->portable_hashes = $portable_hashes;
        $this->random_state = microtime();
        if (function_exists('getmypid')) {
            $this->random_state .= getmypid();
        }
    }

    public function get_random_bytes($count)
    {
        $output = '';

        if (is_callable('random_bytes')) {
            return random_bytes($count);
        }

        if (
            @is_readable('/dev/urandom') &&
            ($fh = @fopen('/dev/urandom', 'rb'))
        ) {
            $output = fread($fh, $count);
            fclose($fh);
        }
        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->random_state =
                    md5(microtime() . $this->random_state);
                $output .=
                    pack('H*', md5($this->random_state));
            }
            $output = substr($output, 0, $count);
        }
        return $output;
    }


    public function encode64($input, $count)
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->itoa64[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }
            $output .= $this->itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }
            $output .= $this->itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $this->itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);
        return $output;
    }

    public function gensalt_private($input)
    {
        $output = '$P$';
        $output .= $this->itoa64[min($this->iteration_count_log2 +
            ((PHP_VERSION >= '5') ? 5 : 3), 30)];
        $output .= $this->encode64($input, 6);
        return $output;
    }
    /**
     * @param  String $password
     * @param  String $setting
     * @return String
     */
    public function crypt_private($password, $setting)
    {
        $output = '*0';
        if (substr($setting, 0, 2) == $output) {
            $output = '*1';
        }
        $id = substr($setting, 0, 3);
        # We use "$P$", phpBB3 uses "$H$" for the same thing
        if ($id != '$P$' && $id != '$H$') {
            return $output;
        }
        $count_log2 = strpos($this->itoa64, $setting[3]);
        if ($count_log2 < 7 || $count_log2 > 30) {
            return $output;
        }
        $count = 1 << $count_log2;
        $salt = substr($setting, 4, 8);
        if (strlen($salt) != 8) {
            return $output;
        }
        // We're kind of forced to use MD5 here since it's the only
        // cryptographic primitive available in all versions of PHP
        // currently in use.  To implement our own low-level crypto
        // in PHP would result in much worse performance and
        // consequently in lower iteration counts and hashes that are
        // quicker to crack (by non-PHP code).
        if (PHP_VERSION >= '5') {
            $hash = md5($salt . $password, TRUE);
            do {
                $hash = md5($hash . $password, TRUE);
            } while (--$count);
        } else {
            $hash = pack('H*', md5($salt . $password));
            do {
                $hash = pack('H*', md5($hash . $password));
            } while (--$count);
        }
        $output = substr($setting, 0, 12);
        $output .= $this->encode64($hash, 16);
        return $output;
    }
    /**
     * @param  String $input
     * @return String
     */
    public function gensalt_extended($input)
    {
        $count_log2 = min($this->iteration_count_log2 + 8, 24);
        // This should be odd to not reveal weak DES keys, and the
        // maximum valid value is (2**24 - 1) which is odd anyway.
        $count = (1 << $count_log2) - 1;
        $output = '_';
        $output .= $this->itoa64[$count & 0x3f];
        $output .= $this->itoa64[($count >> 6) & 0x3f];
        $output .= $this->itoa64[($count >> 12) & 0x3f];
        $output .= $this->itoa64[($count >> 18) & 0x3f];
        $output .= $this->encode64($input, 3);
        return $output;
    }
    /**
     * @param  String $input
     * @return String
     */
    public function gensalt_blowfish($input)
    {
        // This one needs to use a different order of characters and a
        // different encoding scheme from the one in encode64() above.
        // We care because the last character in our encoded string will
        // only represent 2 bits.  While two known implementations of
        // bcrypt will happily accept and correct a salt string which
        // has the 4 unused bits set to non-zero, we do not want to take
        // chances and we also do not want to waste an additional byte
        // of entropy.
        $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $output = '$2a$';
        $output .= chr(ord('0') + $this->iteration_count_log2 / 10);
        $output .= chr(ord('0') + $this->iteration_count_log2 % 10);
        $output .= '$';
        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
                $output .= $itoa64[$c1];
                break;
            }
            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;
            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $itoa64[$c1];
            $output .= $itoa64[$c2 & 0x3f];
        } while (1);
        return $output;
    }
    /**
     * @param String $password
     */
    public function HashPassword($password)
    {
        $random = '';
        if (CRYPT_BLOWFISH == 1 && !$this->portable_hashes) {
            $random = $this->get_random_bytes(16);
            $hash =
                crypt($password, $this->gensalt_blowfish($random));
            if (strlen($hash) == 60) {
                return $hash;
            }
        }
        if (CRYPT_EXT_DES == 1 && !$this->portable_hashes) {
            if (strlen($random) < 3) {
                $random = $this->get_random_bytes(3);
            }
            $hash =
                crypt($password, $this->gensalt_extended($random));
            if (strlen($hash) == 20) {
                return $hash;
            }
        }
        if (strlen($random) < 6) {
            $random = $this->get_random_bytes(6);
        }
        $hash =
            $this->crypt_private(
                $password,
                $this->gensalt_private($random)
            );
        if (strlen($hash) == 34) {
            return $hash;
        }
        // Returning '*' on error is safe here, but would _not_ be safe
        // in a crypt(3)-like function used _both_ for generating new
        // hashes and for validating passwords against existing hashes.
        return '*';
    }
    /**
     * @param String $password
     * @param String $stored_hash
     * @return boolean
     */
    public function CheckPassword($password, $stored_hash)
    {
        $hash = $this->crypt_private($password, $stored_hash);
        if ($hash[0] == '*') {
            $hash = crypt($password, $stored_hash);
        }
        return hash_equals($stored_hash, $hash);
    }

    public static function validateEmail($email)
    {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public static function getcountryCodeByIp($userIp)
    {
        $countryCode = 'US';
        $ip_data = json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip={$userIp}"));
        if ($ip_data && $ip_data->geoplugin_countryName != null) {
            $countryCode = $ip_data->geoplugin_countryCode;
        }
        return $countryCode;
    }

    public static function generatePassword($length = '5')
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $dt = Carbon::now();
        $dt1 = Carbon::now();
        return substr(str_shuffle($chars), 0, $length);
        //return $dt;
    }

    public static function getCurrencySign($countryCode)
    {
        $currency = self::getUserCurrency($countryCode);
        if ($currency == "USD") {
            $currencySign = "$";
        } elseif ($currency == "AUD") {
            $currencySign = "$";
        } else {
            $currencySign = "$";
        }
        return $currencySign;
    }

    public static function getUserCurrency($countryCode)
    {
        if ($countryCode == "US") {
            $currency = "USD";
        } elseif ($countryCode == "GB") {
            $currency = "GBP";
        } else {
            $currency = "USD";
        }
        return $currency;
    }

    public static function generateOrderId($userId)
    {
        $today = date("ymd");
        $rand = strtoupper(substr(uniqid(sha1(time())), 0, 4));
        return $unique = 'GAH' . $today . $userId . $rand;
    }

    public static function Encrypt($value)
    {
        $encrypt_method = "AES-256-CBC";
        $skey = '@reat@ss!gnmEnT$eRv!cEs@';
        $key = hash('sha256', $skey);
        $iv = substr(hash('sha256', $skey), 0, 16);
        if (!$value) {
            return false;
        }
        $data = openssl_encrypt($value, $encrypt_method, $key, 0, $iv);
        return base64_encode($data);
    }
    public static function Decrypt($value)
    {
        $encrypt_method = "AES-256-CBC";
        $skey = '@reat@ss!gnmEnT$eRv!cEs@';
        $key = hash('sha256', $skey);
        $iv = substr(hash('sha256', $skey), 0, 16);
        if (!$value) {
            return false;
        }
        $data = openssl_decrypt(base64_decode($value), $encrypt_method, $key, 0, $iv);
        return $data;
    }

    public static function setRights($menus, $menuRights, $topmenu)
    {
        $arrData = array();
        for ($i = 0, $c = count($menus); $i < $c; $i++) {

            $row = array();
            for ($j = 0, $c2 = count($menuRights); $j < $c2; $j++) {
                if ($menuRights[$j]["moduleCode"] == $menus[$i]["moduleCode"]) {
                    if (
                        self::authorize($menuRights[$j]["createRoleRights"]) || self::authorize($menuRights[$j]["editRoleRights"]) ||
                        self::authorize($menuRights[$j]["deleteRoleRights"]) || self::authorize($menuRights[$j]["viewRoleRights"])
                    ) {

                        $row["menu"] = $menus[$i]["moduleGroupCode"];
                        $row["menuName"] = $menus[$i]["moduleName"];
                        $row["menuIcons"] = $menus[$i]["moduleIcons"];
                        $row["pageName"] = $menus[$i]["modulePageName"];
                        $row["create"] = $menuRights[$j]["createRoleRights"];
                        $row["edit"] = $menuRights[$j]["editRoleRights"];
                        $row["delete"] = $menuRights[$j]["deleteRoleRights"];
                        $row["view"] = $menuRights[$j]["viewRoleRights"];

                        $arrData[$menus[$i]["moduleGroupCode"]][$menuRights[$j]["moduleCode"]] = $row;
                        $arrData[$menus[$i]["moduleGroupCode"]]["top_menu_name"] = $menus[$i]["moduleGroupName"];
                    }
                }
            }
        }

        return $arrData;
    }

    public static function authorize($module)
    {
        return $module == "yes" ? TRUE : FALSE;
    }

    public static function convertIndianTime($time, $fullTime = true)
    {
        $date = new \DateTimeImmutable($time, new \DateTimeZone('Europe/London'));
        $date->setTimezone(new \DateTimeZone('Asia/Kolkata'));
        if (!$fullTime) {
            return $date->format('Y-m-d');
        } else {
            return $date->format('Y-m-d H:i:s');
        }
    }

    public static function getPHPTimeZoneByIp($ip)
    {
        $ipInfo = file_get_contents('http://ip-api.com/json/' . $ip);
        $ipInfo = json_decode($ipInfo);
        $timezone = $ipInfo->timezone;
        return $timezone;
    }

    public static function getPHPTimeZone($timezone)
    {
        if ($timezone == 'EST') {
            $tzName = 'America/New_York';
        } elseif ($timezone == 'IST') {
            $tzName = 'Asia/Kolkata';
        } else {
            $tzName = 'Europe/London';
        }
        return $tzName;
    }

    public static function getTimezone($countryCode)
    {
        if ($countryCode == "US") {
            $timezone = "EST";
        } elseif ($countryCode == "AU") {
            $timezone = "AEST";
        } elseif ($countryCode == "IN") {
            $timezone = "IST";
        } else {
            $timezone = "GMT";
        }
        return $timezone;
    }

    public static function convertTimeAnyoneToIST($time, $tzName = 'Europe/London', $fullTime = true)
    {
        $date = new \DateTimeImmutable($time, new \DateTimeZone($tzName));
        $date->setTimezone(new \DateTimeZone('Asia/Kolkata'));
        if (!$fullTime) {
            return $date->format('Y-m-d');
        } else {
            return $date->format('Y-m-d H:i:s');
        }
    }

    public static function findTimeLeft($countryCode, $deadline)
    {
        $timezone = self::getTimezone($countryCode);
        $tzName = self::getPHPTimeZone($timezone);
        date_default_timezone_set($tzName);
        include_once(dirname(__FILE__) . '/../../plugins/vendor/autoload.php');
        $dt = Carbon::now();
        $dt1 = Carbon::now();
        $dt1->timestamp = strtotime($deadline);
        $d = $dt->diffInDays($dt1, false);
        $h = $dt->diffInHours($dt1, false) - ($d * 24);
        $m = $dt->diffInMinutes($dt1, false) - ($d * 24 * 60) - ($h * 60);
        $timeLeft = $d . " Days " . ceil($h) . " Hours " . ceil($m) . " Minutes";
        return $timeLeft;
    }

    public static function downloadZipFile($files = array(), $destination = '',  $overwrite = false)
    {
        // echo"<pre>";print_r($files);echo"</pre>"; die;	
        $validFiles = array();
        $destination = 'zip/' . $destination;
        $zip = new \ZipArchive();
        if ($zip->open($destination, $overwrite ? \ZIPARCHIVE::OVERWRITE : \ZIPARCHIVE::CREATE) == true) {
            foreach ($files as $file) {
                // echo"<pre>";print_r($file);echo"</pre>";die;
                $zip->addFile($file,  basename($file));
            }
            $zip->close();
            header('Content-Type: application/zip');
            header("Content-Disposition: attachment; filename=\"" . $destination . "\"");
            header("Content-Length: " . filesize($destination));
            readfile($destination);
            unlink($destination);
            exit;
        } else {
            return false;
        }
    }

    public static function downloadFile($filePath)
    {
        if (headers_sent())
            die('Headers Sent');
        if (ini_get('zlib.output_compression'))
            ini_set('zlib.output_compression', 'Off');
        if (file_exists($filePath)) {
            $fsize = filesize($filePath);
            $path_parts = pathinfo($filePath);
            $ext = strtolower($path_parts["extension"]);
            switch ($ext) {
                case "pdf":
                    $ctype = "application/pdf";
                    break;
                case "zip":
                    $ctype = "application/zip";
                    break;
                case "doc":
                    $ctype = "application/msword";
                    break;
                case "png":
                    $ctype = "image/png";
                    break;
                case "jpeg":
                case "jpg":
                    $ctype = "image/jpg";
                    break;
                default:
                    $ctype = "application/force-download";
            }
            header("Pragma: public");
            header("Expires: 0");
            header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
            header("Cache-Control: private", false);
            header("Content-Type: $ctype");
            header("Content-Disposition: attachment; filename=\"" . basename($filePath) . "\";");
            header("Content-Transfer-Encoding: binary");
            header("Content-Length: " . $fsize);
            ob_clean();
            flush();
            readfile($filePath);
        } else
            die('File Not Found');
    }

    public static function isTempMail($mail)
    {
        return false;
    }

    public static function getWriterDetails()
    {
        $arrExpertData = array();
        return $arrExpertData;
    }

    public static function getWriterDetailsById($id)
    {
        return $arrExpertData = self::getWriterDetails();
    }

    public static function getRelatedWriterData($subject, $tutorId)
    {
        return     $arrExpertData = self::getWriterDetails();
    }


    public static function getMagicShortUrl($longUrl)
    {
        return $longUrl;
    }

    public static function getShortPaymentUrl($longUrl)
    {
        return $longUrl;
    }
    public static function isMobile()
    {
        return preg_match("/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|mobi|palm|phone|pie|tablet|up\.browser|up\.link|webos|wos)/i", $_SERVER["HTTP_USER_AGENT"]);
    }
}
