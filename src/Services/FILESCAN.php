<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;

/**
 * Scan a file for malicious content.
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class FILESCAN implements PangeaInterface
{

    protected $travel;

    protected $version;

    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint)
    {
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    //Retrieve reputation for a domain from a provider, including an optional detailed report
    public function file_scanner(int $allowed_size = 2, array $allowed_file_types = array('jpg', 'png', 'jpeg', 'image/png', 'image/jpeg'))
    {
        if (!array_key_exists('file', $_FILES)) {
            throw new \Exception('Sorry! this file is bigger than the server requirements and has been rejected.');
        }
        // Retrieve the file details
        $filename = $this->sanitize_file_name($_FILES["file"]["name"]);
        $file_tmp = $this->strip($_FILES['file']['tmp_name']);
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        $finfo = new \finfo(FILEINFO_MIME);
        $mimetype = $finfo->file($file_tmp);
        $mimetypeParts = preg_split('/\s*[;,]\s*/', $mimetype);
        $mimeType = strtolower($mimetypeParts[0]);
        unset($finfo); //Safe some memory man
               
        if (!$extension || empty($extension) || !in_array($extension, $allowed_file_types) || !in_array($mimeType, $allowed_file_types)) {
            throw new \Exception('File type is not allowed.');
        }
        $s = $allowed_size * 1048576; //Measured in MB
        $size = $this->strip($_FILES['file']['size']);
        if ($size > $s) {
            throw new \Exception('File must not be greater than '.$allowed_size.' MB.');
        }
        // Get the file contents
        $fileContents = file_get_contents($file_tmp);
        $this->travel->transport->setHeader('Content-Type', 'multipart/form-data');
        $response = $this->travel->post($this->url . '/v1/scan', [
            'request' => json_encode(['transfer_method' => 'multipart']),
            'upload' => base64_encode($fileContents),
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    /**
     * Asynchronous call
     *
     * @param string $request_id
     */
    public function async_file_scanner_call(string $request_id)
    {
        $response = $this->travel->get($this->url . '/request/' . $request_id, []);
        return $response;
    }

    public function strip($value, $onlyTextAndWhiteSpace = true)
    {
        //I dont want to take any chance of attacks through this service. Remove anything suspicious.
        if (empty($value)) {
            return null;
        }
        $value = preg_replace('@<(script|style)[^>]*?>.*?</\\1>@si', '', $value);
        if ($onlyTextAndWhiteSpace) {
            $value = preg_replace('/[^A-Za-z0-9\- ]/', '', $value);
        }
        $data = $this->cleanString(strip_tags($value));
        $data = filter_var($data, FILTER_SANITIZE_SPECIAL_CHARS);
        return $data;
    }

    private function mbstring_binary_safe_encoding($reset = false)
    {
        static $encodings = array();
        static $overloaded = null;

        if (is_null($overloaded)) {
            $overloaded = function_exists('mb_internal_encoding') && (ini_get('mbstring.func_overload') & 2); // phpcs:ignore PHPCompatibility.IniDirectives.RemovedIniDirectives.mbstring_func_overloadDeprecated
        }

        if (false === $overloaded) {
            return;
        }

        if (!$reset) {
            $encoding = mb_internal_encoding();
            array_push($encodings, $encoding);
            mb_internal_encoding('ISO-8859-1');
        }

        if ($reset && $encodings) {
            $encoding = array_pop($encodings);
            mb_internal_encoding($encoding);
        }
    }

    private function reset_mbstring_encoding()
    {
        $this->mbstring_binary_safe_encoding(true);
    }

    /**
     * Checks to see if a string is utf8 encoded.
     * NOTE: This function checks for 5-Byte sequences, UTF8 has Bytes Sequences with a maximum length of 4.
     * @param string $str The string to be checked
     * @return bool True if $str fits a UTF-8 model, false otherwise.
     */
    private function seems_utf8($str)
    {
        $this->mbstring_binary_safe_encoding();
        $length = strlen($str);
        $this->reset_mbstring_encoding();
        for ($i = 0; $i < $length; $i++) {
            $c = ord($str[$i]);
            if ($c < 0x80) {
                $n = 0;
            } // 0bbbbbbb
            elseif (($c & 0xE0) == 0xC0) {
                $n = 1;
            } // 110bbbbb
            elseif (($c & 0xF0) == 0xE0) {
                $n = 2;
            } // 1110bbbb
            elseif (($c & 0xF8) == 0xF0) {
                $n = 3;
            } // 11110bbb
            elseif (($c & 0xFC) == 0xF8) {
                $n = 4;
            } // 111110bb
            elseif (($c & 0xFE) == 0xFC) {
                $n = 5;
            } // 1111110b
            else {
                return false;
            } // Does not match any model
            for ($j = 0; $j < $n; $j++) { // n bytes matching 10bbbbbb follow ?
                if ((++$i == $length) || ((ord($str[$i]) & 0xC0) != 0x80)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Function to clean a string so all characters with accents are turned into ASCII characters. EG: ‡ = a
     *
     * @param string $string
     * @return string
     */
    private function cleanString(string $string)
    {
        if (!preg_match('/[\x80-\xff]/', $string)) {
            return $string;
        }

        if ($this->seems_utf8($string)) {
            $chars = array(
                // Decompositions for Latin-1 Supplement.
                'ª' => 'a',
                'º' => 'o',
                'À' => 'A',
                'Á' => 'A',
                'Â' => 'A',
                'Ã' => 'A',
                'Ä' => 'A',
                'Å' => 'A',
                'Æ' => 'AE',
                'Ç' => 'C',
                'È' => 'E',
                'É' => 'E',
                'Ê' => 'E',
                'Ë' => 'E',
                'Ì' => 'I',
                'Í' => 'I',
                'Î' => 'I',
                'Ï' => 'I',
                'Ð' => 'D',
                'Ñ' => 'N',
                'Ò' => 'O',
                'Ó' => 'O',
                'Ô' => 'O',
                'Õ' => 'O',
                'Ö' => 'O',
                'Ù' => 'U',
                'Ú' => 'U',
                'Û' => 'U',
                'Ü' => 'U',
                'Ý' => 'Y',
                'Þ' => 'TH',
                'ß' => 's',
                'à' => 'a',
                'á' => 'a',
                'â' => 'a',
                'ã' => 'a',
                'ä' => 'a',
                'å' => 'a',
                'æ' => 'ae',
                'ç' => 'c',
                'è' => 'e',
                'é' => 'e',
                'ê' => 'e',
                'ë' => 'e',
                'ì' => 'i',
                'í' => 'i',
                'î' => 'i',
                'ï' => 'i',
                'ð' => 'd',
                'ñ' => 'n',
                'ò' => 'o',
                'ó' => 'o',
                'ô' => 'o',
                'õ' => 'o',
                'ö' => 'o',
                'ø' => 'o',
                'ù' => 'u',
                'ú' => 'u',
                'û' => 'u',
                'ü' => 'u',
                'ý' => 'y',
                'þ' => 'th',
                'ÿ' => 'y',
                'Ø' => 'O',
                // Decompositions for Latin Extended-A.
                'Ā' => 'A',
                'ā' => 'a',
                'Ă' => 'A',
                'ă' => 'a',
                'Ą' => 'A',
                'ą' => 'a',
                'Ć' => 'C',
                'ć' => 'c',
                'Ĉ' => 'C',
                'ĉ' => 'c',
                'Ċ' => 'C',
                'ċ' => 'c',
                'Č' => 'C',
                'č' => 'c',
                'Ď' => 'D',
                'ď' => 'd',
                'Đ' => 'D',
                'đ' => 'd',
                'Ē' => 'E',
                'ē' => 'e',
                'Ĕ' => 'E',
                'ĕ' => 'e',
                'Ė' => 'E',
                'ė' => 'e',
                'Ę' => 'E',
                'ę' => 'e',
                'Ě' => 'E',
                'ě' => 'e',
                'Ĝ' => 'G',
                'ĝ' => 'g',
                'Ğ' => 'G',
                'ğ' => 'g',
                'Ġ' => 'G',
                'ġ' => 'g',
                'Ģ' => 'G',
                'ģ' => 'g',
                'Ĥ' => 'H',
                'ĥ' => 'h',
                'Ħ' => 'H',
                'ħ' => 'h',
                'Ĩ' => 'I',
                'ĩ' => 'i',
                'Ī' => 'I',
                'ī' => 'i',
                'Ĭ' => 'I',
                'ĭ' => 'i',
                'Į' => 'I',
                'į' => 'i',
                'İ' => 'I',
                'ı' => 'i',
                'Ĳ' => 'IJ',
                'ĳ' => 'ij',
                'Ĵ' => 'J',
                'ĵ' => 'j',
                'Ķ' => 'K',
                'ķ' => 'k',
                'ĸ' => 'k',
                'Ĺ' => 'L',
                'ĺ' => 'l',
                'Ļ' => 'L',
                'ļ' => 'l',
                'Ľ' => 'L',
                'ľ' => 'l',
                'Ŀ' => 'L',
                'ŀ' => 'l',
                'Ł' => 'L',
                'ł' => 'l',
                'Ń' => 'N',
                'ń' => 'n',
                'Ņ' => 'N',
                'ņ' => 'n',
                'Ň' => 'N',
                'ň' => 'n',
                'ŉ' => 'n',
                'Ŋ' => 'N',
                'ŋ' => 'n',
                'Ō' => 'O',
                'ō' => 'o',
                'Ŏ' => 'O',
                'ŏ' => 'o',
                'Ő' => 'O',
                'ő' => 'o',
                'Œ' => 'OE',
                'œ' => 'oe',
                'Ŕ' => 'R',
                'ŕ' => 'r',
                'Ŗ' => 'R',
                'ŗ' => 'r',
                'Ř' => 'R',
                'ř' => 'r',
                'Ś' => 'S',
                'ś' => 's',
                'Ŝ' => 'S',
                'ŝ' => 's',
                'Ş' => 'S',
                'ş' => 's',
                'Š' => 'S',
                'š' => 's',
                'Ţ' => 'T',
                'ţ' => 't',
                'Ť' => 'T',
                'ť' => 't',
                'Ŧ' => 'T',
                'ŧ' => 't',
                'Ũ' => 'U',
                'ũ' => 'u',
                'Ū' => 'U',
                'ū' => 'u',
                'Ŭ' => 'U',
                'ŭ' => 'u',
                'Ů' => 'U',
                'ů' => 'u',
                'Ű' => 'U',
                'ű' => 'u',
                'Ų' => 'U',
                'ų' => 'u',
                'Ŵ' => 'W',
                'ŵ' => 'w',
                'Ŷ' => 'Y',
                'ŷ' => 'y',
                'Ÿ' => 'Y',
                'Ź' => 'Z',
                'ź' => 'z',
                'Ż' => 'Z',
                'ż' => 'z',
                'Ž' => 'Z',
                'ž' => 'z',
                'ſ' => 's',
                // Decompositions for Latin Extended-B.
                'Ș' => 'S',
                'ș' => 's',
                'Ț' => 'T',
                'ț' => 't',
                // Euro sign.
                '€' => 'E',
                // GBP (Pound) sign.
                '£' => '',
                // Vowels with diacritic (Vietnamese).
                // Unmarked.
                'Ơ' => 'O',
                'ơ' => 'o',
                'Ư' => 'U',
                'ư' => 'u',
                // Grave accent.
                'Ầ' => 'A',
                'ầ' => 'a',
                'Ằ' => 'A',
                'ằ' => 'a',
                'Ề' => 'E',
                'ề' => 'e',
                'Ồ' => 'O',
                'ồ' => 'o',
                'Ờ' => 'O',
                'ờ' => 'o',
                'Ừ' => 'U',
                'ừ' => 'u',
                'Ỳ' => 'Y',
                'ỳ' => 'y',
                // Hook.
                'Ả' => 'A',
                'ả' => 'a',
                'Ẩ' => 'A',
                'ẩ' => 'a',
                'Ẳ' => 'A',
                'ẳ' => 'a',
                'Ẻ' => 'E',
                'ẻ' => 'e',
                'Ể' => 'E',
                'ể' => 'e',
                'Ỉ' => 'I',
                'ỉ' => 'i',
                'Ỏ' => 'O',
                'ỏ' => 'o',
                'Ổ' => 'O',
                'ổ' => 'o',
                'Ở' => 'O',
                'ở' => 'o',
                'Ủ' => 'U',
                'ủ' => 'u',
                'Ử' => 'U',
                'ử' => 'u',
                'Ỷ' => 'Y',
                'ỷ' => 'y',
                // Tilde.
                'Ẫ' => 'A',
                'ẫ' => 'a',
                'Ẵ' => 'A',
                'ẵ' => 'a',
                'Ẽ' => 'E',
                'ẽ' => 'e',
                'Ễ' => 'E',
                'ễ' => 'e',
                'Ỗ' => 'O',
                'ỗ' => 'o',
                'Ỡ' => 'O',
                'ỡ' => 'o',
                'Ữ' => 'U',
                'ữ' => 'u',
                'Ỹ' => 'Y',
                'ỹ' => 'y',
                // Acute accent.
                'Ấ' => 'A',
                'ấ' => 'a',
                'Ắ' => 'A',
                'ắ' => 'a',
                'Ế' => 'E',
                'ế' => 'e',
                'Ố' => 'O',
                'ố' => 'o',
                'Ớ' => 'O',
                'ớ' => 'o',
                'Ứ' => 'U',
                'ứ' => 'u',
                // Dot below.
                'Ạ' => 'A',
                'ạ' => 'a',
                'Ậ' => 'A',
                'ậ' => 'a',
                'Ặ' => 'A',
                'ặ' => 'a',
                'Ẹ' => 'E',
                'ẹ' => 'e',
                'Ệ' => 'E',
                'ệ' => 'e',
                'Ị' => 'I',
                'ị' => 'i',
                'Ọ' => 'O',
                'ọ' => 'o',
                'Ộ' => 'O',
                'ộ' => 'o',
                'Ợ' => 'O',
                'ợ' => 'o',
                'Ụ' => 'U',
                'ụ' => 'u',
                'Ự' => 'U',
                'ự' => 'u',
                'Ỵ' => 'Y',
                'ỵ' => 'y',
                // Vowels with diacritic (Chinese, Hanyu Pinyin).
                'ɑ' => 'a',
                // Macron.
                'Ǖ' => 'U',
                'ǖ' => 'u',
                // Acute accent.
                'Ǘ' => 'U',
                'ǘ' => 'u',
                // Caron.
                'Ǎ' => 'A',
                'ǎ' => 'a',
                'Ǐ' => 'I',
                'ǐ' => 'i',
                'Ǒ' => 'O',
                'ǒ' => 'o',
                'Ǔ' => 'U',
                'ǔ' => 'u',
                'Ǚ' => 'U',
                'ǚ' => 'u',
                // Grave accent.
                'Ǜ' => 'U',
                'ǜ' => 'u',
            );

            $string = strtr($string, $chars);
        } else {
            $chars = array();
            // Assume ISO-8859-1 if not UTF-8.
            $chars['in'] = "\x80\x83\x8a\x8e\x9a\x9e"
                . "\x9f\xa2\xa5\xb5\xc0\xc1\xc2"
                . "\xc3\xc4\xc5\xc7\xc8\xc9\xca"
                . "\xcb\xcc\xcd\xce\xcf\xd1\xd2"
                . "\xd3\xd4\xd5\xd6\xd8\xd9\xda"
                . "\xdb\xdc\xdd\xe0\xe1\xe2\xe3"
                . "\xe4\xe5\xe7\xe8\xe9\xea\xeb"
                . "\xec\xed\xee\xef\xf1\xf2\xf3"
                . "\xf4\xf5\xf6\xf8\xf9\xfa\xfb"
                . "\xfc\xfd\xff";

            $chars['out'] = 'EfSZszYcYuAAAAAACEEEEIIIINOOOOOOUUUUYaaaaaaceeeeiiiinoooooouuuuyy';

            $string = strtr($string, $chars['in'], $chars['out']);
            $double_chars = array();
            $double_chars['in'] = array("\x8c", "\x9c", "\xc6", "\xd0", "\xde", "\xdf", "\xe6", "\xf0", "\xfe");
            $double_chars['out'] = array('OE', 'oe', 'AE', 'DH', 'TH', 'ss', 'ae', 'dh', 'th');
            $string = str_replace($double_chars['in'], $double_chars['out'], $string);
        }
        //Additional cleaner
        return $string;
    }

    /**
     * Sanitizes a file name, replacing whitespace and a few other characters with dashes.
     *
     * Limits the output to alphanumeric characters, underscore (_) and dash (-).
     * Whitespace becomes a dash.
     *
     *
     * @param string $file     The title to be sanitized.
     * @param string $raw_title Optional. Not used. Default empty.
     * @param string $context   Optional. The operation for which the string is sanitized.
     *                          Default 'display'.
     * @return string The sanitized title.
     */
    public function sanitize_file_with_dashes(string $file, $raw_title = '', $context = 'display')
    {
        // Preserve escaped octets.
        $file = preg_replace('|%([a-fA-F0-9][a-fA-F0-9])|', '---$1---', $file);
        // Remove percent signs that are not part of an octet.
        $file = str_replace('%', '', $file);
        // Restore octets.
        $file = preg_replace('|---([a-fA-F0-9][a-fA-F0-9])---|', '%$1', $file);

        if ($this->seems_utf8($file)) {
            if (function_exists('mb_strtolower')) {
                $file = mb_strtolower($file, 'UTF-8');
            }
            $file = $this->utf8_uri_encode($file, 200);
        }

        $file = strtolower($file);

        if ('save' === $context) {
            // Convert &nbsp, &ndash, and &mdash to hyphens.
            $file = str_replace(array('%c2%a0', '%e2%80%93', '%e2%80%94'), '-', $file);
            // Convert &nbsp, &ndash, and &mdash HTML entities to hyphens.
            $file = str_replace(array('&nbsp;', '&#160;', '&ndash;', '&#8211;', '&mdash;', '&#8212;'), '-', $file);
            // Convert forward slash to hyphen.
            $file = str_replace('/', '-', $file);

            // Strip these characters entirely.
            $file = str_replace(
                array(
                    // Soft hyphens.
                    '%c2%ad',
                    // &iexcl and &iquest.
                    '%c2%a1',
                    '%c2%bf',
                    // Angle quotes.
                    '%c2%ab',
                    '%c2%bb',
                    '%e2%80%b9',
                    '%e2%80%ba',
                    // Curly quotes.
                    '%e2%80%98',
                    '%e2%80%99',
                    '%e2%80%9c',
                    '%e2%80%9d',
                    '%e2%80%9a',
                    '%e2%80%9b',
                    '%e2%80%9e',
                    '%e2%80%9f',
                    // Bullet.
                    '%e2%80%a2',
                    // &copy, &reg, &deg, &hellip, and &trade.
                    '%c2%a9',
                    '%c2%ae',
                    '%c2%b0',
                    '%e2%80%a6',
                    '%e2%84%a2',
                    // Acute accents.
                    '%c2%b4',
                    '%cb%8a',
                    '%cc%81',
                    '%cd%81',
                    // Grave accent, macron, caron.
                    '%cc%80',
                    '%cc%84',
                    '%cc%8c',
                ),
                '',
                $file
            );

            // Convert &times to 'x'.
            $file = str_replace('%c3%97', 'x', $file);
        }

        // Kill entities.
        $file = preg_replace('/&.+?;/', '', $file);
        $file = str_replace('.', '-', $file);

        $file = preg_replace('/[^%a-z0-9 _-]/', '', $file);
        $file = preg_replace('/\s+/', '-', $file);
        $file = preg_replace('|-+|', '-', $file);
        $file = trim($file, '-');

        return $file;
    }


    /**
     * Sanitizes a filename, replacing whitespace with dashes.
     *
     * Removes special characters that are illegal in filenames on certain
     * operating systems and special characters requiring special escaping
     * to manipulate at the command line. Replaces spaces and consecutive
     * dashes with a single dash. Trims period, dash and underscore from beginning
     * and end of filename. It is not guaranteed that this function will return a
     * filename that is allowed to be uploaded.
     *
     *
     * @param string $filename The filename to be sanitized.
     * @return string The sanitized filename.
     */
    public function sanitize_file_name(string $filename)
    {
        $filename = $this->strip($filename);

        $special_chars = array('?', '[', ']', '/', '\\', '=', '<', '>', ':', ';', ',', "'", '"', '&', '$', '#', '*', '(', ')', '|', '~', '`', '!', '{', '}', '%', '+', '’', '«', '»', '”', '“', chr(0));

        if (!$this->seems_utf8($filename)) {
            $_ext = pathinfo($filename, PATHINFO_EXTENSION);
            $_name = pathinfo($filename, PATHINFO_FILENAME);
            $filename = $this->sanitize_file_with_dashes($_name) . '.' . $_ext;
        }

        $filename = str_replace($special_chars, '', $filename);
        $filename = str_replace(array('%20', '+'), '-', $filename);
        $filename = preg_replace('/[\r\n\t -]+/', '-', $filename);
        $filename = preg_replace('/_+/', '_', $filename);
        $filename = preg_replace(array('/ +/', '/-+/'), '-', $filename);
        $filename = preg_replace(array('/-*\.-*/', '/\.{2,}/'), '.', $filename);
        // cut to 255 characters
        $length = 255;
        $filename = extension_loaded('mbstring') ? mb_strcut($filename, 0, $length, mb_detect_encoding($filename)) : substr($filename, 0, $length);
        $filename = trim($filename, '.-_');

        return $filename;
    }

    private function utf8_uri_encode($utf8_string, $length = 0)
    {
        $unicode = '';
        $values = array();
        $num_octets = 1;
        $unicode_length = 0;

        $this->mbstring_binary_safe_encoding();
        $string_length = strlen($utf8_string);
        $this->reset_mbstring_encoding();

        for ($i = 0; $i < $string_length; $i++) {

            $value = ord($utf8_string[$i]);

            if ($value < 128) {
                if ($length && ($unicode_length >= $length)) {
                    break;
                }
                $unicode .= chr($value);
                $unicode_length++;
            } else {
                if (count($values) == 0) {
                    if ($value < 224) {
                        $num_octets = 2;
                    } elseif ($value < 240) {
                        $num_octets = 3;
                    } else {
                        $num_octets = 4;
                    }
                }

                $values[] = $value;

                if ($length && ($unicode_length + ($num_octets * 3)) > $length) {
                    break;
                }
                if (count($values) == $num_octets) {
                    for ($j = 0; $j < $num_octets; $j++) {
                        $unicode .= '%' . dechex($values[$j]);
                    }

                    $unicode_length += $num_octets * 3;

                    $values = array();
                    $num_octets = 1;
                }
            }
        }

        return $unicode;
    }
}