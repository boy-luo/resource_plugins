<?php

/**
 */
class zbj_lib_BaseUtils
{

    /**
     * static error
     *
     * @var string
     */
    public static $error = '';

    /**
     * 请勿删除$s_field及$s_sc变量 二维数组排序用
     *
     * @var string
     */
    static $s_field;

    /**
     * @var string
     */
    static $s_sc;

    /**
     * @var string
     */
    private static $clientIP;

    /**
     * IP格式字符串
     */
    const IP_FORMAT_STRING = 0;

    /**
     * IP格式非负数
     */
    const IP_FORMAT_INT = 1;

    /**
     * 安全过滤数据
     *
     * @param string|array $str     需要处理的字符或数组
     * @param string       $type    返回的字符类型，支持，string,int,float,html
     * @param mixed        $default 当出现错误或无数据时默认返回值
     *
     * @return string|array|mixed 当出现错误或无数据时默认返回值
     */
    public static function getStr($str, $type = 'string', $default = '')
    {
        //如果为空则为默认值
        if ($str === '') {r
            return $default;
        }

        if (is_array($str)) {
            $_str = array();
            foreach ($str as $key => $val) {
                $_str[$key] = self::getStr($val, $type, $default);
            }

            return $_str;
        }

        //转义
        if (!get_magic_quotes_gpc()) {
            $str = addslashes($str);
        }

        switch ($type) {
            case 'string':    //字符处理
                $_str = strip_tags($str);
                $_str = str_replace("'", '&#39;', $_str);
                $_str = str_replace("\"", '&quot;', $_str);
                $_str = str_replace("\\", '', $_str);
                $_str = str_replace("\/", '', $_str);
                $_str = str_replace("+/v", '', $_str);
                break;
            case 'int':    //获取整形数据
                $_str = intval($str);
                break;
            case 'float':    //获浮点形数据
                $_str = floatval($str);
                break;
            case 'html':    //获取HTML，防止XSS攻击
                $_str = self::reMoveXss($str);
                break;

            default:    //默认当做字符处理
                $_str = strip_tags($str);
        }

//        var_dump($_str);
        return $_str;
    }

    /**
     * 防注入处理(为变量加入斜杠)函数
     *
     * @param string|array $string
     *
     * @return string|array $string
     */
    public static function saddslashes($string)
    {
        if (is_array($string)) {
            foreach ($string as $key => $val) {
                $string[$key] = self::saddslashes($val);
            }
        } else {
            $string = self::straddslashes($string);
        }

        return $string;
    }

    /**
     * add slashes
     *
     * @param string $string
     *
     * @return string
     */
    public static function straddslashes($string)
    {
        if (!get_magic_quotes_gpc()) {
            return addslashes($string);
        } else {
            return $string;
        }
    }

    /**
     * 去掉变量斜杠函数
     *
     * @param string|array $string
     *
     * @return string|array $string
     */
    public static function sstripslashes($string)
    {
        if (is_array($string)) {
            foreach ($string as $key => $val) {
                $string[$key] = self::sstripslashes($val);
            }
        } else {
            $string = stripslashes($string);
        }

        return $string;
    }

    /**
     * 取消HTML特殊字符 防止XSS
     *
     * @param string|array $string
     *
     * @return string|array $string
     */
    public static function shtmlspecialchars($string)
    {
        if (is_array($string)) {
            foreach ($string as $key => $val) {
                $string[$key] = self::shtmlspecialchars($val);
            }
        } else {
            $string = preg_replace('/&amp;((#(\d{3,5}|x[a-fA-F0-9]{4})|[a-zA-Z][a-z0-9]{2,5});)/', '&\\1',
                str_replace(array('&', '"', '<', '>', '\''), array('&amp;', '&quot;', '&lt;', '&gt;', '&#039;'),
                    $string));
        }

        return $string;
    }

    /**
     * 取消HTML特殊字符 防止XSS
     *
     * @param string|array $array
     *
     * @return string|array $array
     */
    public static function specialhtml($array)
    {
        if (is_array($array)) {
            foreach ($array as $key => $value) {
                if (is_array($value) === false) {
                    $array[$key] = htmlspecialchars($value);
                } else {
                    $array[$key] = self::specialhtml($value);
                }
            }
            return $array;
        } else {
            return htmlspecialchars($array);
        }
    }

    /**
     * 是否是回环ip地址
     * @return bool
     */
    public static function isLoopBackIPClient()
    {
        $ip_int = self::getClientIP(self::IP_FORMAT_INT);
        return $ip_int >= sprintf('%u', ip2long('127.0.0.1')) &&
            $ip_int <= sprintf('%u', ip2long('127.255.255.254'));
    }

    /**
     * 是否是局域网ip客户端
     * @return bool
     */
    public static function isIntranetIPClient()
    {
        $ip_int = self::getClientIP(self::IP_FORMAT_INT);
        $intranet_ip_range = array(
            '10.0.0.0'    => '10.255.255.255',
            '172.16.0.0'  => '172.31.255.255',
            '192.168.0.0' => '192.168.255.255',
        );
        foreach ($intranet_ip_range as $ip_start => $ip_end) {
            $ip_start_int = sprintf('%u', ip2long($ip_start));
            $ip_end_int = sprintf('%u', ip2long($ip_end));
            if ($ip_int >= $ip_start_int && $ip_int <= $ip_end_int) {
                return true;
            }
        }
        return false;
    }

    /**
     * 是否为公司公网IP访问
     * @return bool
     */
    public static function isCompanyPublicIPClient()
    {
        return in_array(self::getClientIP(self::IP_FORMAT_STRING), self::getCompanyPublicIps());
    }

    /**
     * @param int $format
     *
     * @return int|string
     */
    public static function getClientIP($format = self::IP_FORMAT_STRING)
    {
        return self::getIp($format);
    }

    /**
     * 公司公网IP列表
     * @return array
     */
    public static function getCompanyPublicIps()
    {
        return array(
            //'218.70.9.10', //总部电信 已换
            '218.70.85.138', //总部电信
            '113.204.227.146', //总部联通
            '113.204.227.170', //总部联通
            '113.204.227.186', //总部联通
            '222.180.195.202',
            '222.180.173.114',
            '113.204.225.86',
            '183.230.8.134',
            '222.180.148.46',
            '222.180.148.42',
            '222.180.195.198',
            '183.230.8.160',
            '222.180.195.206',
            '222.180.195.210',
            '183.230.8.165',
            '222.180.195.194',
            '183.230.8.166',
            '183.230.169.40', //以上ip为公司老楼知识产权
        );
    }

    /**
     * 获取当前在线IP地址
     *
     * @param int $format $format = 0 返回IP地址：127.0.0.1  $format = 1 返回IP长整形：2130706433
     *
     * @return string|int
     */
    public static function getIp($format = self::IP_FORMAT_STRING)
    {
        if (self::$clientIP === null) {
            if ($_SERVER['HTTP_REMOTE_HOST'] && $_SERVER['HTTP_X_REAL_IP'] && $_SERVER['HTTP_REMOTE_HOST'] == $_SERVER['HTTP_X_REAL_IP']) {
                $client_ip = $_SERVER['HTTP_X_REAL_IP'];
            } elseif (getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
                $client_ip = getenv('HTTP_CLIENT_IP');
            } elseif (getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
                $client_ip = getenv('HTTP_X_FORWARDED_FOR');
            } elseif (getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
                $client_ip = getenv('REMOTE_ADDR');
            } elseif (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'],
                    'unknown')
            ) {
                $client_ip = $_SERVER['REMOTE_ADDR'];
            } else {
                $client_ip = '';
            }
            preg_match("/[\d\.]{7,15}/", $client_ip, $ip_matches);
            self::$clientIP = $ip_matches[0] ? $ip_matches[0] : 'unknown';
        }
        if (!$format) {
            return self::$clientIP;
        } else {
            return sprintf('%u', ip2long(self::$clientIP));
        }
    }

    /**
     * 格式化大小函数
     *
     * @param int $size 为文件大小
     *
     * @return string 文件大家加单位
     */
    public static function formatsize($size)
    {
        $prec = 3;
        $size = round(abs($size));
        $units = array(0 => " B ", 1 => " KB", 2 => " MB", 3 => " GB", 4 => " TB");
        if ($size == 0) {
            return str_repeat(" ", $prec) . "0$units[0]";
        }
        $unit = min(4, floor(log($size) / log(2) / 10));
        $size = $size * pow(2, -10 * $unit);
        $digi = $prec - 1 - floor(log($size) / log(10));
        $size = round($size * pow(10, $digi)) * pow(10, -$digi);

        return $size . $units[$unit];
    }

    /**
     * 验证目录名是否有效 (只允许输入数字和字母)
     *
     * @param string $dirname 目录名
     *
     * @return bool
     */
    public static function isdir($dirname)
    {
        $patn = '/^[a-zA-Z]+[a-zA-Z0-9]+$/';

        return preg_match($patn, $dirname);
    }

    /**
     * 创建目录
     *
     * @param string $path 目录路径 如：e:/work/yii/test
     *
     * @return bool
     */
    public static function makePath($path)
    {
        return is_dir($path) or (self::makePath(dirname($path)) and mkdir($path, 0755));
    }

    /**
     * 删除目录
     *
     * @param string $path 目录路径 如：e:/work/yii/test
     *
     * @return bool
     */
    public static function rmDir($path)
    {
        return @rmdir($path);
    }

    /**
     * 获取文件内容
     *
     * @param string $filename 目录路径 如：e:/work/yii/test.html
     *
     * @return string
     */
    public static function sreadfile($filename)
    {
        $content = '';
        if (function_exists('file_get_contents')) {
            @$content = file_get_contents($filename);
        } else {
            if (@$fp = fopen($filename, 'r')) {
                @$content = fread($fp, filesize($filename));
                @fclose($fp);
            }
        }

        return $content;
    }

    /**
     * 写入文件内容
     *
     * @param string $filename  目录路径 如：e:/work/yii/test.html
     * @param string $writetext 写入文件内容
     * @param string $openmod   打开文件类型 默认为'w'表示写入
     *
     * @return bool
     */
    public static function swritefile($filename, $writetext, $openmod = 'w')
    {
        if (@$fp = fopen($filename, $openmod)) {
            flock($fp, 2);
            fwrite($fp, $writetext);
            fclose($fp);

            return true;
        } else {
            //runlog('error', "File: $filename write error.");
            return false;
        }
    }

    /**
     * 产生随机数
     *
     * @param int    $length 产生随机数长度
     * @param int    $type   返回字符串类型 随机字符串 $type = 0：数字+字母 $type = 1：数字 $type = 2：字符
     * @param string $hash   是否由前缀，默认为空. 如:$hash = 'zz-'  结果zz-823klis
     *
     * @return string
     *
     */
    public static function random($length, $type = 0, $hash = '')
    {
        $chars = '';
        if ($type == 0) {
            $chars = '0123456789abcdefghijklmnopqrstuvwxyz';
        } else {
            if ($type == 1) {
                $chars = '0123456789';
            } else {
                if ($type == 2) {
                    $chars = 'abcdefghijklmnopqrstuvwxyz';
                }
            }
        }
        $max = strlen($chars) - 1;
        mt_srand((double)microtime() * 1000000);
        for ($i = 0; $i < $length; $i++) {
            $hash .= $chars[mt_rand(0, $max)];
        }

        return $hash;
    }


    /**
     * 判断字符串是否存在
     *
     * @param string $haystack 被查找的字符串
     * @param string $needle   需要查找的字符串
     *
     * @return bool
     */
    public static function strexists($haystack, $needle)
    {
        return !(strpos($haystack, $needle) === false);
    }

    /**
     * 获取文件后缀名
     *
     * @param string $filename 文件名
     *
     * @return string
     */
    public static function fileext($filename)
    {
        return strtolower(trim(substr(strrchr($filename, '.'), 1)));
    }

    /**
     * 编码转换
     *
     * @param string $str         需要转换的字符
     * @param string $out_charset 转换的编码格式
     * @param string $in_charset  默认的编码格式
     *
     * @return string
     */
    public static function siconv($str, $out_charset, $in_charset = '')
    {
        global $_SC;

        $in_charset = empty($in_charset) ? strtoupper($_SC['charset']) : strtoupper($in_charset);
        $out_charset = strtoupper($out_charset);
        if ($in_charset != $out_charset) {
            if (function_exists('iconv') && (@$outstr = iconv("$in_charset//IGNORE", "$out_charset//IGNORE", $str))) {
                return $outstr;
            } elseif (function_exists('mb_convert_encoding') && (@$outstr = mb_convert_encoding($str, $out_charset,
                    $in_charset))
            ) {
                return $outstr;
            }
        }

        return $str;// 转换失败
    }

    /**
     * 获取日期时间格式
     *
     * @param int $time 时间 整型格式
     * @param int $type 获取类型 $type=1获取时间 $type=2获取日期 $type=3获取日期及时间
     *
     * @return string
     */
    public static function getDate($time, $type = 3)
    {
        if ($time == 0 || $time == null) {
            return '';
        } else {
            $format[] = $type & 2 ? (!empty($settings['dateformat']) ? $settings['dateformat'] : 'Y-n-j') : '';
            $format[] = $type & 1 ? (!empty($settings['timeformat']) ? $settings['timeformat'] : 'H:i') : '';
            $format[] = $type & 4 ? (!empty($settings['dateformat']) ? $settings['dateformat'] : 'Y/n/j') : '';

            return gmdate(implode(' ', $format), $time + 28800);
        }
    }

    /**
     * 获取时间差
     *
     * @param int $begin_time 开始时间
     * @param int $end_time   结束时间
     *
     * @return array|string
     */
    public static function timediff($begin_time, $end_time)
    {
        if ($begin_time > $end_time) {
            return '-1'; //time is wrong
        } else {
            $timediff = $end_time - $begin_time;
            $days = intval($timediff / 86400);
            $remain = $timediff % 86400;
            $hours = intval($remain / 3600);
            $remain = $remain % 3600;
            $mins = intval($remain / 60);
            $secs = $remain % 60;
            $res = array("day" => $days, "hour" => $hours, "min" => $mins, "sec" => $secs);

            return $res;
        }
    }

    /**
     * 格式化数字，以标准MONEY格式输出
     *
     * @param string $num 整型数字
     *
     * @return string 888,888,88
     */
    public static function formatnumber($num)
    {
        return number_format($num, 2, ".", ",");
    }

    /**
     * 检测时间的正确性
     *
     * @param string $date 时间格式如:2010-04-05
     *
     * @return bool
     */
    public static function chkdate($date)
    {
        if ((strpos($date, '-'))) {
            $d = explode("-", $date);
            if (checkdate($d[1], $d[2], $d[0])) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * cookie设置
     *
     * @param array  $array  设置的cookie键值对
     * @param int    $life   设置的过期时间：为整型，单位秒 如60表示60秒后过期
     * @param string $path   设置的cookie作用路径
     * @param string $domain 设置的cookie作用域名
     */
    public static function ssetcookie($array, $life = 0, $path = '/', $domain = '')
    {
        global $_SERVER;
        $_cookName_ary = array_keys($array);
        for ($i = 0; $i < count($array); $i++) {
            //echo $_cookName_ary[$i].'='.$array[$_cookName_ary[$i]].'<br>';
            $httpOnly = false;
            if ($_cookName_ary[$i] == 'userkey') {
                $httpOnly = true;
            }
            setcookie($_cookName_ary[$i], $array[$_cookName_ary[$i]], $life ? (time() + $life) : 0, $path, $domain, '',
                $httpOnly);
        }
    }

    /**
     * 冒泡排序（数组排序）
     *
     * @param array $array 需要排序的数组
     *
     * @return array|bool 排序后数组
     */
    public static function bubble_sort($array)
    {
        $count = count($array);
        if ($count <= 0) {
            return false;
        } else {
            for ($i = 0; $i < $count; $i++) {
                for ($j = $count - 1; $j > $i; $j--) {
                    if ($array[$j] < $array[$j - 1]) {
                        $temp = $array[$j];
                        $array[$j] = $array[$j - 1];
                        $array[$j - 1] = $temp;
                    }
                }
            }

            return $array;
        }
    }

    /**
     * 截取字符函数
     *
     * @param string $string 要截取的字符串
     * @param int    $len    截取长度
     * @param string $code   字符编码
     * @param string $prefix 新截取字符的前缀
     * @param string $add    处理后字符串加的后缀,如'...'
     *
     * @return string
     */
    public static function cutstr($string, $len, $code = 'utf-8', $prefix = '', $add = '')
    {
        if (is_array($string)) {
            foreach ($string as $key => $val) {
                if (mb_strlen($val, $code) > $len) {
                    $key = $prefix . $key;
                    $string[$key] = mb_substr($val, 0, $len, $code);
                    $string[$key] .= $add;
                } else {
                    $key = $prefix . $key;
                    $string[$key] = $val;
                }
            }
        } else {
            if (mb_strlen($string, $code) > $len) {
                $string = mb_substr($string, 0, $len, $code);
                $string .= $add;
            }
        }

        return $string;
    }

    /**
     * 过滤XSS攻击
     *
     * @param string $val
     *
     * @return string
     */
    public static function reMoveXss($val)
    {
        // remove all non-printable characters. CR(0a) and LF(0b) and TAB(9) are allowed
        // this prevents some character re-spacing such as <java\0script>
        // note that you have to handle splits with \n, \r, and \t later since they *are* allowed in some inputs
        //$val = preg_replace('/([\x00-\x08|\x0b-\x0c|\x0e-\x19])/', '', $val);
        $val = preg_replace('/([\x00-\x08])/', '', $val);
        $val = preg_replace('/([\x0b-\x0c])/', '', $val);
        $val = preg_replace('/([\x0e-\x19])/', '', $val);

        // straight replacements, the user should never need these since they're normal characters
        // this prevents like <IMG SRC=@avascript:alert('XSS')>
        $search = 'abcdefghijklmnopqrstuvwxyz';
        $search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $search .= '1234567890!@#$%^&*()';
        $search .= '~`";:?+/={}[]-_|\'\\';
        for ($i = 0; $i < strlen($search); $i++) {
            // ;? matches the ;, which is optional
            // 0{0,7} matches any padded zeros, which are optional and go up to 8 chars

            // @ @ search for the hex values
            $val = preg_replace('/(&#[xX]0{0,8}' . dechex(ord($search[$i])) . ';?)/i', $search[$i], $val); // with a ;
            // @ @ 0{0,7} matches '0' zero to seven times
            $val = preg_replace('/(&#0{0,8}' . ord($search[$i]) . ';?)/', $search[$i], $val); // with a ;
        }

        // now the only remaining whitespace attacks are \t, \n, and \r
        $ra1 = Array(
            'javascript',
            'vbscript',
            'expression',
            'applet',
            'meta',
            'xml',
            'blink',
            'link',
            'script',
            'embed',
            'object',
            'iframe',
            'frame',
            'frameset',
            'ilayer',
            'layer',
            'bgsound',
            'base',
        );
        $ra2 = Array(
            'onabort',
            'onactivate',
            'onafterprint',
            'onafterupdate',
            'onbeforeactivate',
            'onbeforecopy',
            'onbeforecut',
            'onbeforedeactivate',
            'onbeforeeditfocus',
            'onbeforepaste',
            'onbeforeprint',
            'onbeforeunload',
            'onbeforeupdate',
            'onblur',
            'onbounce',
            'oncellchange',
            'onchange',
            'onclick',
            'oncontextmenu',
            'oncontrolselect',
            'oncopy',
            'oncut',
            'ondataavailable',
            'ondatasetchanged',
            'ondatasetcomplete',
            'ondblclick',
            'ondeactivate',
            'ondrag',
            'ondragend',
            'ondragenter',
            'ondragleave',
            'ondragover',
            'ondragstart',
            'ondrop',
            'onerror',
            'onerrorupdate',
            'onfilterchange',
            'onfinish',
            'onfocus',
            'onfocusin',
            'onfocusout',
            'onhelp',
            'onkeydown',
            'onkeypress',
            'onkeyup',
            'onlayoutcomplete',
            'onload',
            'onlosecapture',
            'onmousedown',
            'onmouseenter',
            'onmouseleave',
            'onmousemove',
            'onmouseout',
            'onmouseover',
            'onmouseup',
            'onmousewheel',
            'onmove',
            'onmoveend',
            'onmovestart',
            'onpaste',
            'onpropertychange',
            'onreadystatechange',
            'onreset',
            'onresize',
            'onresizeend',
            'onresizestart',
            'onrowenter',
            'onrowexit',
            'onrowsdelete',
            'onrowsinserted',
            'onscroll',
            'onselect',
            'onselectionchange',
            'onselectstart',
            'onstart',
            'onstop',
            'onsubmit',
            'onunload',
        );
        $ra = array_merge($ra1, $ra2);
        $found = true; // keep replacing as long as the previous round replaced something
        while ($found == true) {
            $val_before = $val;
            for ($i = 0; $i < sizeof($ra); $i++) {
                $pattern = '/';
                for ($j = 0; $j < strlen($ra[$i]); $j++) {
                    if ($j > 0) {
                        $pattern .= '(';
                        $pattern .= '(&#[xX]0{0,8}([9ab]);)';
                        $pattern .= '|';
                        $pattern .= '|(&#0{0,8}([9|10|13]);)';
                        $pattern .= ')*';
                    }
                    $pattern .= $ra[$i][$j];
                }
                $pattern .= '/i';
                $replacement = substr($ra[$i], 0, 2) . '<x>' . substr($ra[$i], 2); // add in <> to nerf the tag
                $val = preg_replace($pattern, $replacement, $val); // filter out the hex tags
                if ($val_before == $val) {
                    // no replacements were made, so exit the loop
                    $found = false;
                }
            }
        }

        return $val;
    }

    /**
     * get url content
     *
     * @param string $url_query
     *
     * @return null|string
     */
    public static function gethttpurl($url_query)
    {
        $url_host = $url_query;
        $url_hostall = preg_replace("/(http|https|ftp|news):\/\//", "", $url_host);
        $url_host = preg_replace("/\/.*/", "", $url_hostall);
        $url_get = preg_replace("/$url_host/", "", $url_hostall);
        $fp = fsockopen("$url_host", 80);
        $content = null;
        if ($fp) {
            $req = "GET $url_get HTTP/1.0\r\n"
                . "Host: $url_host\r\n"
                . "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.2; zh-CN; rv:1.8.1.1) Gecko/20061204 Fire
                fox/2.0.0.6\r\n\r\n";
            //$req="GET $url_get HTTP/1.1\r\nHost: $url_host\r\nAccept: */*\r\nReferer:$url_get\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\nConnection: Close\r\n\r\n";
            fwrite($fp, $req);
            while (!feof($fp)) {
                $content .= fgets($fp, 256);
            }
            fclose($fp);
            $content = end(explode("\n", $content));

            return $content;
        } else {
            //return file_get_contents($url_query);
            return null;
        }
    }

    /**
     * 是否符合用户名格式
     *
     * @param string $Argv
     *
     * @return bool
     */
    public static function IsUsername($Argv)
    {
        $RegExp = '/^[a-z0-9_]{4,16}$/'; //由大小写字母跟数字下划线组成并且长度在4-16字符直接
        //return preg_match($RegExp,$Argv)?$Argv:false;
        $stara = substr($Argv, 0, 1);
        $sRegExp = '/^\d*$/'; //判断首字符是否为字母
        return preg_match($RegExp, $Argv) && !preg_match($sRegExp, $stara) ? true : false;
    }

    /**
     * 是否为正确的邮件格式
     *
     * @param string $Argv
     *
     * @return int
     */
    public static function IsMail($Argv)
    {
        //$RegExp='/^[a-z0-9][a-z\.0-9-_]+@[a-z0-9_-]+(?:\.[a-z]{0,3}\.[a-z]{0,2}|\.[a-z]{0,3}|\.[a-z]{0,2})$/i';
        $RegExp = '/^[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)+$/';
        if (preg_match($RegExp, $Argv)) {
            if (strlen($Argv) >= 50) {
                return 2; //长度操作50
            }
            if (strlen($Argv) > 4) {
                $root_domain = strtolower(end(explode('.', $Argv)));
                if (in_array($root_domain,
                    array('com', 'net', 'org', 'mobi', 'cn', 'asia', 'edu', 'info', 'name', 'cc', 'me'))) {
                    return 0;
                } else {
                    return 3; //后缀不正确
                }
            } else {
                return 4; //不允许的邮件格式
            }
        } else {
            return 1;// 格式不正确
        }
    }

    /**
     * 是否符合QQ号码的格式
     *
     * @param string $Argv
     *
     * @return bool
     */
    public static function IsQQ($Argv)
    {
        $RegExp = '/^[1-9][0-9]{4,11}$/';

        return preg_match($RegExp, $Argv) ? $Argv : false;
    }

    /**
     * 检测是否为正确的中国手机号码格式
     *
     * @param string $Argv
     *
     * @return bool
     */
    public static function IsMobile($Argv)
    {
        if (!ctype_digit((string)$Argv)) {
            return false;
        }
        $RegExp = '/^(?:13|15|17|18|14)[0-9]\d{8}$/';
        //return preg_match($RegExp,$Argv)?$Argv:false;
        if (preg_match($RegExp, $Argv)) {
            return true;
        }
        if (self::isHongKongMobile($Argv)) {
            return true;
        }
        if (self::isMacauMobile($Argv)) {
            return true;
        }

        return false;
    }

    /**
     * 验证是否是香港地区手机号
     *
     * @param string $num
     *
     * @return bool
     */
    public static function isHongKongMobile($num)
    {
        if (!ctype_digit((string)$num) || strlen($num) != 11) {
            return false;
        }

        return preg_match("/^852\d{8}$/", $num) ? true : false;
    }

    /**
     * 验证是否是澳门地区手机号
     *
     * @param string $num
     *
     * @return bool
     */
    public static function isMacauMobile($num)
    {
        if (!ctype_digit((string)$num) || strlen($num) != 11) {
            return false;
        }

        return preg_match("/^853\d{8}$/", $num) ? true : false;
    }

    /**
     * 验证银行卡号
     *
     * @param string $str
     *
     * @return bool
     */
    public static function checkBank($str)
    {
        $pattern = "/^\d{12,}$/";
        if (preg_match($pattern, $str)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 验证身份证
     *
     * @param string $id_card
     *
     * @return bool
     */
    public static function validation_filter_id_card($id_card)
    {
        if (strlen($id_card) == 18) {
            return self::idcard_checksum18($id_card);
        } elseif ((strlen($id_card) == 15)) {
            $id_card = self::idcard_15to18($id_card);

            return self::idcard_checksum18($id_card);
            /**
             * 用户交接源文件身份证号
             */
        } elseif ($id_card == 'S7935588G') {//台湾
            return true;
        } elseif ((strlen($id_card)) == 10) {
            return self::hkidcard($id_card);
        } elseif ($id_card == '0442268402(B)') {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 计算身份证校验码，根据国家标准GB 11643-1999
     *
     * @param string $idcard_base
     *
     * @return bool
     */
    public static function idcard_verify_number($idcard_base)
    {
        if (strlen($idcard_base) != 17) {
            return false;
        }
        //加权因子
        $factor = array(7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2);
        //校验码对应值
        $verify_number_list = array('1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2');
        $checksum = 0;
        for ($i = 0; $i < strlen($idcard_base); $i++) {
            $checksum += intval(substr($idcard_base, $i, 1)) * $factor[$i];
        }
        $mod = $checksum % 11;
        $verify_number = $verify_number_list[$mod];

        return $verify_number;
    }

    /**
     * 将15位身份证升级到18位
     *
     * @param string $idcard
     *
     * @return bool|string
     */
    public static function idcard_15to18($idcard)
    {
        if (strlen($idcard) != 15) {
            return false;
        } else {
            // 如果身份证顺序码是996 997 998 999，这些是为百岁以上老人的特殊编码
            if (array_search(substr($idcard, 12, 3), array('996', '997', '998', '999')) !== false) {
                $idcard = substr($idcard, 0, 6) . '18' . substr($idcard, 6, 9);
            } else {
                $idcard = substr($idcard, 0, 6) . '19' . substr($idcard, 6, 9);
            }
        }
        $idcard = $idcard . self::idcard_verify_number($idcard);

        return $idcard;
    }

    /**
     * 18位身份证校验码有效性检查
     *
     * @param string $idcard
     *
     * @return bool
     */
    public static function idcard_checksum18($idcard)
    {
        if (strlen($idcard) != 18) {
            return false;
        }
        $idcard_base = substr($idcard, 0, 17);
        if (self::idcard_verify_number($idcard_base) != strtoupper(substr($idcard, 17, 1))) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * 香港身份证号
     *
     * @param string $idcard
     *
     * @return bool
     */
    public static function hkidcard($idcard)
    {
        $firstStr = substr($idcard, 0, 1);
        $middleStr = substr($idcard, 1, -3);
        $length = strlen($middleStr);

        $rightSecondStr = substr($idcard, -2, 1);
        $left = substr($idcard, -3, 1);
        $right = substr($idcard, -1, 1);
        $ord_firstStr = ord($firstStr);
        $ord_rightSecondStr = ord($rightSecondStr);
        $ord_left = ord($left);
        $ord_right = ord($right);
        if (($ord_firstStr > 90) || ($ord_firstStr < 65)) {
            return false;
        } else {
            if (($ord_left != 40) or ($ord_right != 41)) {
                return false;
            } else {
                if ($ord_rightSecondStr < 48 || $ord_rightSecondStr > 57) {
                    return false;
                } else {
                    if (!is_numeric($middleStr)) {
                        return false;
                    } else {
                        if ($length != 6) {
                            return false;
                        } else {
                            return true;
                        }
                    }
                }
            }
        }
    }

    /**
     * 验证组织机构代码证
     *
     * @param string $str
     *
     * @return bool
     */
    public static function checkOrgCode($str)
    {
        $pattern = "/^[A-Za-z0-9]{8}-[A-Za-z0-9]{1}/";//组织机构代码，8位数字或字母加上一个"-"再加一位数字或字母
        if (preg_match($pattern, $str)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * php模拟POST数据
     *
     * @param string $url       访问页面
     * @param array  $post_data 提交数据，类型array
     *
     * @return array
     */
    public static function apiPostExcute($url, $post_data)
    {
        $URL = $url; //需要提交到的页面
        $referrer = "";
        // parsing the given URL
        $URL_Info = parse_url($URL);
        // Building referrer
        if ($referrer == "") // if not given use this script as referrer
        {
            $referrer = $_SERVER["SCRIPT_URI"];
        }

        // making string from $data
        $values = array();
        foreach ($post_data as $key => $value) {
            $values[] = "$key=" . urlencode($value);
        }
        //$values[]="$key=".$value;

        $data_string = implode("&", $values);
        // Find out which port is needed - if not given use standard (=80)
        if (!isset($URL_Info["port"])) {
            $URL_Info["port"] = 80;
        }
        // building POST-request:
        $request = "POST " . $URL_Info["path"] . " HTTP/1.1\n";
        $request .= "Host: " . $URL_Info["host"] . "\n";
        $request .= "Referer: $referrer\n";
        $request .= "Content-type: application/x-www-form-urlencoded\n";
        $request .= "User-Agent:$_SERVER[HTTP_USER_AGENT]\r\n";
        $request .= "Content-length: " . strlen($data_string) . "\n";
        $request .= "Connection: close\n";
        $request .= "\n";
        $request .= $data_string . "\n";
        $fp = fsockopen($URL_Info["host"], $URL_Info["port"]);
        $content = null;
        fputs($fp, $request);
        while (!feof($fp)) {
            $content .= fgets($fp, 256);
        }
        fclose($fp);

        $result = explode("\n", $content);
        $content = end($result);

        return $content;
    }

    /**
     * 获取关键字标签
     *
     * @param string $contents
     *
     * @return string
     */
    public static function getTag($contents)
    {
        $rows = strip_tags($contents);
        $arr = array(' ', ' ', "\s", "\r\n", "\n", "\r", "\t", ">", "“", "”", "<br />");
        $qc_rows = str_replace($arr, '', $rows);
        if (strlen($qc_rows) > 2400) {
            $qc_rows = substr($qc_rows, 0, 2400);
        }
        $url = "http://keyword.discuz.com/related_kw.html?title=$qc_rows&ics=utf-8&ocs=utf-8";
        $data = self::file_get_contents_safe($url, array(), "GET", 20);
        preg_match_all("/<kw>(.*)A\[(.*)\]\](.*)><\/kw>/", $data, $out, PREG_SET_ORDER);
        //$_file = Yii::app()->basePath . '/extensions/smarty/plugins/modifier.filter.php';
        //require($_file);
        $smarty_dir = implode(DIRECTORY_SEPARATOR, array(
            dirname(dirname(__DIR__)),
            "plugins",
            "smarty3",
            "plugins_slightphp",
        ));
        $filter_file = $smarty_dir . DIRECTORY_SEPARATOR . "modifier.filter.php";
        if (file_exists($filter_file) === false) {
            return "";
        }
        require_once($filter_file);
        $key = "";
        for ($i = 0; $i < 5; $i++) {
            if (smarty_modifier_filter($out[$i][2]) == '**') {
                continue;
            }
            $key = $key . $out[$i][2];
            if ($out[$i][2]) {
                $key = $key . ",";
            }
        }

        return $key;
    }

    /**
     * 时间差转为X天X小时X分X秒等形式
     *
     * @param int    $intervalTime
     * @param string $accuracy day精确到天 hour精确到小时 minute精确到分 second精确到秒,max精确在最大一个有数据的值
     *
     * @return string
     */
    public static function intervalTime2str($intervalTime, $accuracy = "hour")
    {
        $intervalTime = $intervalTime > 0 ? $intervalTime : 0;

        $day = floor($intervalTime / 86400);
        $hour = floor(($intervalTime - 86400 * $day) / 3600);
        $minute = floor((($intervalTime - 86400 * $day) - 3600 * $hour) / 60);
        $second = floor((($intervalTime - 86400 * $day) - 3600 * $hour) - 60 * $minute);
        $s_day = ($day > 0) ? $day . "天" : "";
        $s_hour = ($hour > 0) ? $hour . "小时" : "";
        $s_minute = ($minute > 0) ? $minute . "分钟" : "";
        $s_second = ($second > 0) ? $second . "秒" : "";
        if ($accuracy == "day") {
            return $s_day;
        }
        if ($accuracy == "hour") {
            return $s_day . $s_hour;
        }
        if ($accuracy == "minute") {
            return $s_day . $s_hour . $s_minute;
        }
        if ($accuracy == "second") {
            return $s_day . $s_hour . $s_minute . $s_second;
        }
        if ($accuracy == "max") {
            if ($s_day != "") {
                return $s_day;
            }
            if ($s_hour != "") {
                return $s_hour;
            }
            if ($s_minute != "") {
                return $s_minute;
            }
            if ($s_second != "") {
                return $s_second;
            }
        }
        return '';
    }

    /**
     * 计算多维数组总指定下标的和
     *
     * @param array    $arr
     * @param int|null $index
     *
     * @return int
     */
    public static function array_sum_key($arr, $index = null)
    {
        if (!is_array($arr) || sizeof($arr) < 1) {
            return 0;
        }
        $ret = 0;
        foreach ($arr as $id => $data) {
            if (isset($index)) {
                $ret += (isset($data[$index])) ? $data[$index] : 0;
            } else {
                $ret += $data;
            }
        }

        return $ret;
    }

    /**
     * 检查一个（英文）域名是否合法
     *
     * @param string $Domain
     *
     * @return bool
     */
    public static function isDomain($Domain)
    {
        if (!preg_match("/^[0-9a-z]+[0-9a-z\.-]+[0-9a-z]+$/", $Domain)) {
            return false;
        }
        if (!preg_match("/\./", $Domain)) {
            return false;
        }

        if (preg_match("/\-\./", $Domain) or preg_match("/\-\-/", $Domain) or preg_match("/\.\./",
                $Domain) or preg_match("/\.\-/", $Domain)
        ) {
            return false;
        }

        $aDomain = explode(".", $Domain);
        if (!preg_match("/[a-zA-Z]/", $aDomain[count($aDomain) - 1])) {
            return false;
        }

        if (strlen($aDomain[0]) > 63 || strlen($aDomain[0]) < 1) {
            return false;
        }

        return true;
    }

    /**
     * 检查输入的是否为数字
     *
     * @param string $val
     *
     * @return bool
     */
    public static function isNumber($val)
    {
        if (preg_match("/^[0-9]+$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 检查输入的是否为电话
     *
     * @param string $val
     *
     * @return bool
     */
    public static function isPhone($val)
    {
        //eg: xxx-xxxxxxxx-xxx | xxxx-xxxxxxx-xxx ...
        if (preg_match("/^((0\d{2,3})-)(\d{7,8})(-(\d{3,}))?$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 是否为邮编
     *
     * @param string $val
     *
     * @return bool
     */
    public static function isPostcode($val)
    {
        if (preg_match("/^[0-9]{4,6}$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 检查字符串长度是否符合要求
     *
     * @param string $val
     * @param int    $min
     * @param int    $max
     *
     * @return bool
     */
    public static function isNumLength($val, $min, $max)
    {
        //$theelement = trim($val);
        if (preg_match("/^[0-9]{" . $min . "," . $max . "}$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 检查字符串长度是否符合要求
     *
     * @param string $val
     * @param int    $min
     * @param int    $max
     *
     * @return bool
     */
    public static function isEngLength($val, $min, $max)
    {
        //$theelement = trim($val);
        if (preg_match("/^[a-zA-Z]{" . $min . "," . $max . "}$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 检查输入是否为英文
     *
     * @param string $theelement
     *
     * @return bool
     */
    public static function isEnglish($theelement)
    {
        if (preg_match("/[\x80-\xff]./", $theelement)) {
            return false;
        }

        return true;
    }

    /**
     * 检查是否输入为汉字
     *
     * @param string $sInBuf
     *
     * @return bool
     */
    public static function isChinese($sInBuf)
    {
        $iLen = strlen($sInBuf);
        for ($i = 0; $i < $iLen; $i++) {
            if (ord($sInBuf{$i}) >= 0x80) {
                if ((ord($sInBuf{$i}) >= 0x81 && ord($sInBuf{$i}) <= 0xFE) && ((ord($sInBuf{$i + 1}) >= 0x40 && ord($sInBuf{$i + 1}) < 0x7E) || (ord($sInBuf{$i + 1}) > 0x7E && ord($sInBuf{$i + 1}) <= 0xFE))) {
                    if (ord($sInBuf{$i}) > 0xA0 && ord($sInBuf{$i}) < 0xAA) {
                        //有中文标点
                        return false;
                    }
                } else {
                    //有日文或其它文字
                    return false;
                }
                $i++;
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * 检测时间的正确性
     *
     * @param string $date 时间格式如:2010-04-05
     * @return bool
     */
    public static function isDate($date)
    {
        if (is_scalar($date) && ctype_digit(str_replace("-", '', $date)) === true) {
            $d = explode("-", $date);
            return count($d) === 3 && checkdate($d[1], $d[2], $d[0]);
        } else {
            return false;
        }
    }

    /**
     * 检查日期是否符合0000-00-00 00:00:00
     *
     * @param string $sTime
     *
     * @return bool
     */
    public static function isTime($sTime)
    {
        if (preg_match('/^[0-9]{4}\-[][0-9]{2}\-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/', $sTime)) {
            return strtotime($sTime) !== false;
        } else {
            return false;
        }
    }

    /**
     * 检查输入值是否为合法人民币格式
     *
     * @param string $val
     *
     * @return bool
     */
    public static function isMoney($val)
    {
        if (preg_match("/^[0-9]{1,}$/", $val)) {
            return true;
        }
        if (preg_match("/^[0-9]{1,}\.[0-9]{1,2}$/", $val)) {
            return true;
        }

        return false;
    }

    /**
     * 检查输入IP是否符合要求
     *
     * @param string $val
     *
     * @return bool
     */
    public static function isIp($val)
    {
        return (bool)ip2long($val);
    }

    /**
     * 去掉UBB标签,返回指定长度字符
     *
     * @param string   $string
     * @param int      $strlen
     * @param bool|int $br 是否保留换行
     *
     * @return string
     */
    public static function getUbbStr($string, $strlen, $br = 0)
    {
        //过滤UBB
        if ($br == 0) {
            $string = str_replace("\n", "", $string);
            $string = str_replace("\r", "", $string);
        }
        if ($br == 1) {
            $string = preg_replace("/[\r\n]+/", "\r\n", $string);//多个回车换行只保留1个
        }
        $string = preg_replace("/\[.*?\](.*?)\[.*?\]/i", "$1", $string);

        return zbj_lib_BaseUtils::cutstr($string, $strlen) . '...';
    }

    /**
     * 获取根域名
     *
     * @param string $url
     *
     * @return mixed
     */
    public static function getUrlDomain($url)
    {
        $url = $url . "/";
        preg_match("/((\w*):\/\/)?\w*\.?([\w|-]*\.(com.cn|net.cn|gov.cn|org.cn|com|net|cn|org|asia|tel|mobi|me|tv|biz|cc|name|info|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cd|cf|cg|ch|ci|ck|cl|cm|co|cr|cs|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw))\//",
            $url, $ohurl);
        if ($ohurl[3] == '') {
            preg_match("/((\d+\.){3}\d+)\//", $url, $ohip);

            return $ohip[1];
        }

        return $ohurl[3];
    }

    /**
     * 检查是否本域名下请求,防止机器提交
     *
     * @param string      $url 指定URL参数,如果不指定，默认读取发起请求的链接(HTTP_REFERER)
     * @param null|string $domain
     *
     * @return bool
     */
    public static function isRefererMyDomain($url = '', $domain = null)
    {
        if ($domain === null) {
            $domain = zbj_lib_Constant::DOMAIN;
        }

        $referer = empty($url) ? $_SERVER['HTTP_REFERER'] : $url;

        if (empty($referer)) {
            return false;
        }
        $urldata = parse_url($referer);

        if (strpos(strtolower($urldata['host']), zbj_lib_Constant::ZHUBAJIE_DOMAIN)) {
            return true;
        }

        if (strpos(strtolower($urldata['host']), $domain) === false) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * 验证验证码
     *
     * @param string $seed
     * @param string $catcha
     *
     * @return bool
     */
    public static function checkCatcha($seed, $catcha)
    {
        //session_start();
        //$oSC = new SCaptcha();
        //return $oSC->check($s);
        $c = new SCaptchalu();

        return $c->verify($seed, $catcha);
    }

    /**
     * 双向加密
     *
     * @param string $string
     * @param string $operation
     * @param string $key
     * @param int    $expire
     *
     * @return string
     */
    public static function authcode($string, $operation = 'DECODE', $key = '', $expire = 0)
    {
        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        $ckey_length = 4;

        // 密匙
        $key = md5($key ? $key : 'zhubajie');

        // 密匙a会参与加解密
        $keya = md5(substr($key, 0, 16));
        // 密匙b会用来做数据完整性验证
        $keyb = md5(substr($key, 16, 16));
        // 密匙c用于变化生成的密文
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()),
            -$ckey_length)) : '';
        // 参与运算的密匙
        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d',
                $expire ? $expire + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        // 产生密匙簿
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度
        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        // 核心加解密部分
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            // 从密匙簿得出密匙进行异或，再转成字符
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 'DECODE') {
            // substr($result, 0, 10) == 0 验证数据有效性
            // substr($result, 0, 10) - time() > 0 验证数据有效性
            // substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16) 验证数据完整性
            // 验证数据有效性，请看未加密明文的格式
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10,
                    16) == substr(md5(substr($result, 26) . $keyb), 0, 16)
            ) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
            return $keyc . str_replace('=', '', base64_encode($result));
        }
    }

    /**
     * php 二维数组按键值排序 此方法效率极低，请使用array_sort_new
     *
     * @param array  $a    需要排序的数组
     * @param string $sort 排序的键值
     * @param string $d    默认是降序排序，带上参后是升序
     *
     * @return array
     */
    public static function array_sort($a, $sort, $d = '')
    {
        //no change $a
        $b = $a;

        self::array_sort_new($b, $sort, $d);

        return $b;
    }

    /**
     * php 二维数组按键值排序
     *
     * @param array  $a    需要排序的数组
     * @param string $sort 排序的键值
     * @param string $d    默认ASC，带上参后为DESC
     *
     * @covers zbj_lib_BaseUtils::_cmp
     * @author 5+ <wujia@zhubajie.com>
     * @return boolean
     */
    public static function array_sort_new(&$a, $sort, $d = '')
    {
        self::$s_field = $sort;
        self::$s_sc = $d;

        return usort($a, array("zbj_lib_BaseUtils", "_cmp"));
    }

    /**
     * 排序回调方法 请勿删除
     *
     * @param string $a
     * @param string $b
     *
     * @return int
     */
    public static function _cmp($a, $b)
    {
        $s_a = self::$s_sc ? $b : $a;
        $s_b = self::$s_sc ? $a : $b;
        $field = self::$s_field;

        return strcmp($s_a[$field], $s_b[$field]);
    }

    /**
     * PHP 二维数组去重
     *
     * @param array  $arr 需要去重的数组
     * @param string $key 键值
     *
     * @return array
     */
    public static function assoc_unique($arr, $key)
    {
        $tmp_arr = array();
        foreach ($arr as $k => $v) {
            if (in_array($v[$key], $tmp_arr)) {
                unset($arr[$k]);
            } else {
                $tmp_arr[] = $v[$key];
            }
        }
        sort($arr);

        return $arr;
    }

    /**
     * 通过登记获取当前所需最对技能值
     *
     * @param int $level 等级
     *
     * @return int
     */
    public static function getLevelToAbility($level = 0)
    {
        if ($level <= 0) {
            $s = 0;
        } elseif ($level == 1) {
            $s = 1;
        } elseif ($level == 2) {
            $s = 50;
        } elseif ($level == 3) {
            $s = 1000;
        } elseif ($level == 4) {
            $s = 5000;
        } elseif ($level == 5) {
            $s = 20000;
        } elseif ($level == 6) {
            $s = 60000;
        } elseif ($level == 7) {
            $s = 150000;
        } elseif ($level == 8) {
            $s = 300000;
        } elseif ($level == 9) {
            $s = 600000;
        } else {
            $s = 0;
        }

        return $s;
    }

    /**
     * 雇主发任务，返点活动  输入金额返回返点金额
     *
     * @param float $amount 金额
     *
     * @return float
     */
    public static function getRebateAmount($amount)
    {
        $time = time();
        if ($time >= 1322539200 && $time < 1325347200) {
            //活动期间
        } else {
            return 0;
        }

        /** @noinspection PhpUnusedLocalVariableInspection */
        $sale = 0.01;
        $amount = (float)$amount;
        if (0 >= $amount) {
            $sale = 0;
        } else {
            if (500 >= $amount) {
                $sale = 0.01;
            } else {
                if (1001 > $amount) {
                    $sale = 0.02;
                } else {
                    if (5001 > $amount) {
                        $sale = 0.03;
                    } else {
                        if (10001 > $amount) {
                            $sale = 0.04;
                        } else {
                            $sale = 0.05;
                        }
                    }
                }
            }
        }

        return round($amount * $sale, 2);
    }

    /**
     * 雇主发任务，返点活动  输入返点金额，返回返点比例
     *
     * @param float $rebate_amount 金额
     *
     * @return float
     */
    public static function getRebateProportion($rebate_amount)
    {
        /** @noinspection PhpUnusedLocalVariableInspection */
        $proportion = 0.01;
        $rebate_amount = (float)$rebate_amount;
        if (0 >= $rebate_amount) {
            $proportion = 0;
        } else {
            if (5 >= $rebate_amount) {
                $proportion = 0.01;
            } else {
                if (20.02 > $rebate_amount) {
                    $proportion = 0.02;
                } else {
                    if (150.03 > $rebate_amount) {
                        $proportion = 0.03;
                    } else {
                        if (400.04 > $rebate_amount) {
                            $proportion = 0.04;
                        } else {
                            $proportion = 0.05;
                        }
                    }
                }
            }
        }

        return $proportion;
    }

    /**
     * 检测comet频道状态
     *
     * @param int $uid
     *
     * @return bool
     * @deprecated
     */
    public static function Comet_ChannelStat($uid)
    {
        unset($uid);
        return false;//弃用
        /*
        if (extension_loaded('curl')) {
            if ($uid % 2 == 1) {
                $url = zbj_lib_Constant::PUSH_HOST_1;
            } else {
                $url = zbj_lib_Constant::PUSH_HOST_2;
            }
            $curl = $url . '?id=' . self::getChannel($uid);
            $ch = curl_init($curl);
            curl_setopt($ch, CURLOPT_HTTPHEADER, Array("Content-Type: text/plain"));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $status = curl_exec($ch);
            curl_close($ch);
            if ($status) {
                $status = json_decode($status);

                return ((int)$status->subscribers > 0) ? true : false;
            } else {
                return false;
            }
        } else {
            return false;
        }
        */
    }

    /**
     * 检测用户IM在线状态  (需与聊天服务器共用memcache 后台不可直接调用)
     *
     * @param array $aUserid array('id1','id2','id3')
     *
     * @return array|bool
     */
    public static function Comet_CheckOnline($aUserid)
    {
        return self::webIm_online($aUserid);//使用新版
        /*
        $oCache = new zbj_lib_cache('memcache');
        $time = time();
        if (is_array($aUserid) && !empty($aUserid)) {
            $return = array();
            foreach ($aUserid as $v) {
                $info = $oCache->get('zbjim.controller.chat.user.' . $v);
                if ($info['online'] == 1) {
                    if (intval($time - $info['lastrequest']) < 1800) {
                        $return[$v] = 1;
                    } else {
                        if (self::Comet_ChannelStat($v)) {
                            $info['lastrequest'] = $time;
                            $return[$v] = 1;
                        } else {
                            $info['online'] = 0;
                            $return[$v] = 0;
                        }
                    }
                } else {
                    $info['online'] = 0;
                    $return[$v] = 0;
                }
                $oCache->set('zbjim.controller.chat.user.' . $v, $info, 3600);
            }

            return $return;
        } else {
            return false;
        }
        */
    }

    /**
     * 获取用户频道ID
     *
     * @param int $userid
     *
     * @return string
     * @deprecated
     */
    public static function getChannel($userid)
    {
        unset($userid);
        return false;//弃用
        //return md5('zbj_im_channelid_' . $userid . '_key_' . zbj_lib_Constant::ZBJ_SYSUSERKEY);
    }


    /**
     * 去除除中文，字符，数字以外的字符
     *
     * @param string $string
     *
     * @return string
     */
    public static function getSafeString($string)
    {
        return preg_replace("[^\x80-\xffa-zA-Z0-9]", '', (string)$string);
    }

    /**
     * 文件上传方法
     *
     * @param array       $_file       文件流
     * @param string      $filename    文件名 不含扩展名
     * @param string      $productname 产名名 如：task
     * @param string      $path        上传路径
     * @param string      $key         与产品关联的ID号，如task_id
     * @param array       $_size       生成缩略图的大小尺寸,如：array('size[0]'=>'80x80','size[1]'=>'640x1000') 仅为图片是有效
     * @param boolean|int $mark        是否在缩略图上加水印 1为是0为否，默认为是
     * @param array       $params      其他参数 例如：水印的文字（nomask），水印位置（lc）,servers_url指定上传服务器(zbj_lib_Constant::UPFILEAPI),
     *
     * @return array  状态数组 如：array('state'=>1,'msg'='sdf')，当state为1时为成功，msg为上传成功的路径 含域名；当state为非1时，msg表示错误信息
     */
    public static function getUploadFilePath(
        $_file,
        $filename,
        $productname = "task",
        $path = "",
        $key = "",
        $_size = array(),
        $mark = 1,
        $params = array()
    ) {

        if ($_file) {
            $query = $params;
            //$nowtime = time();
            $_file_type = 0;
            $type_img = array('jpg', 'gif', 'jpeg', 'png', 'bmp');

            //2012-8-8过滤文件名称
            $_file['name'] = self::filterFilename($_file['name']);
            if (!$_file['name']) {
                return array('state' => 0, 'msg' => '文件不能没有扩展名');
            }
            $ext = strtolower(end(explode(".", $_file['name'])));
            if (in_array($ext, $type_img)) {
                $_file_type = 1;
                if ($ext == 'gif') {
                    $_file_type = 3;
                }
            }
            $allow_extensions = array(
                'bmp',
                'gif',
                'jpg',
                'jpeg',
                'png',
                'zip',
                'rar',
                '7z',
                'pdf',
                'ppt',
                'fla',
                'dwg',
                'max',
                'pptx',
                'psd',
                'swf',
                'doc',
                'ezp',
                'docx',
                'xls',
                'xlsx',
                'mpg',
                'ttc',
                'ttf',
                'otf',
                'numbers',
                'page',
                'key',
                'ai',
                'cdr',
                'tif',
                'abr',
                'eip',
                'indd',
                'max',
                'fla',
                'eps',
                'obj',
                'mp3',
                'mp4',
                'm4a',
                'wma',
                'txt',
                'mht',
            );
            if (!in_array($ext, $allow_extensions)) {
                return array('state' => 0, 'msg' => '不可以上传此格式文件，请压缩后上传！');
            }

            //图片尺寸
            if (count($_size) > 0) {
                foreach ($_size as $vkey => $value) {
                    $query[$vkey] = $value;
                }
            }
            $query['path'] = $productname . ($path ? $path : date("/Y-m/d/", time())) . ($key ? $key . "/" : "pub/");
            $query['type'] = $_file_type;  //为图片时填1,非图片文件填
            //唯一文件名由自己构造,不能使用上传文件的名字，有可能重复,可以使用自增id、时间截或随机等为文件名,后缀要准确0
            $query['name'] = ($filename ? $filename : uniqid()) . '.' . $ext;  // $_suffix  =  '.jpg'
            $query['key'] = $key;   //任务为tid(纯数字),其它业务图片或文件自定但不能为纯数字
            if (!$mark) {
                $query['nomask'] = 1;
            }
            $result = zbj_lib_Uploadfilesv::postfile($query, $_file['name'], $_file['tmp_name'], $_file['type'],
                $params['servers_url']);
            if ($result['state'] === 1) {
                $result['msg'] = zbj_lib_Uploadfilesv::getfileurl($query['path'], $query['name']);

                //2012-8-8返回过滤过后的原始文件名称
                $result['ofilename'] = $_file['name'];
                $size = explode('x', trim($result['info'][1]['real']));
                $result['width'] = $size[0];
                $result['height'] = $size[1];
                $sizef = explode('x', trim($result['info']['size']));
                $result['widthf'] = $sizef[0];
                $result['heightf'] = $sizef[1];
                unset($result['info']);
            } else {
                switch ($result['state']) {
                    case 2:
                        $result['msg'] = '部分缩略图未生成';
                        break;
                    case 11:
                        $result['msg'] = '保存文件失败';
                        break;
                    case 14:
                        $result['msg'] = '水印文字超长';
                        break;
                    case 17:
                        $result['msg'] = '上传图片非法';
                        break;
                    case 19:
                        $result['msg'] = '上传文件非法';
                        break;
                    case 20:
                        $result['msg'] = '上传路径非法';
                        break;
                    default:
                        //$result['msg'] = '未知错误';
                        break;
                }
                $result['state'] = 0;
            }

            return $result;
        }

        return array('state' => 0, 'msg' => '文件为空');
    }

    /**
     * 从远程服务器上传方法 * 目前只支持HTTP
     *
     * @param array       $_file       文件流
     * @param string      $filename    文件名 不含扩展名
     * @param string      $productname 产名名 如：task
     * @param string      $path        上传路径
     * @param string      $key         与产品关联的ID号，如task_id
     * @param array       $_size       生成缩略图的大小尺寸,如：array('size[0]'=>'80x80','size[1]'=>'640x1000') 仅为图片是有效
     * @param boolean|int $mark        是否在缩略图上加水印 1为是0为否，默认为是
     * @param array       $params      其他参数 例如：水印的文字（nomask），水印位置（lc）,servers_url指定上传服务器(zbj_lib_Constant::UPFILEAPI),
     *
     * @return array  状态数组 如：array('state'=>1,'msg'='sdf')，当state为1时为成功，msg为上传成功的路径 含域名；当state为非1时，msg表示错误信息
     */
    public static function getUploadFileFromRemote(
        $_file,
        $filename,
        $productname = "task",
        $path = "",
        $key = "",
        $_size = array(),
        $mark = 1,
        $params = array()
    ) {

        if ($_file) {
            $query = $params;
            //$nowtime = time();
            $_file_type = 0;
            $type_img = array('jpg', 'gif', 'jpeg', 'png', 'bmp');

            //2012-8-8过滤文件名称
            $_file['name'] = self::filterFilename($_file['name']);
            if (!$_file['name']) {
                return array('state' => 0, 'msg' => '文件不能没有扩展名');
            }
            $ext = strtolower(end(explode(".", $_file['name'])));
            if (in_array($ext, $type_img)) {
                $_file_type = 1;
                if ($ext == 'gif') {
                    $_file_type = 3;
                }
            } elseif (in_array($ext, array('php', 'phps', 'php5', 'php4'))) {
                return array('state' => 0, 'msg' => '非法扩展名');
            }

            //图片尺寸
            if (count($_size) > 0) {
                foreach ($_size as $vkey => $value) {
                    $query[$vkey] = $value;
                }
            }
            $query['path'] = $productname . ($path ? $path : date("/Y-m/d/", time())) . ($key ? $key . "/" : "pub/");
            $query['type'] = $_file_type;  //为图片时填1,非图片文件填
            //唯一文件名由自己构造,不能使用上传文件的名字，有可能重复,可以使用自增id、时间截或随机等为文件名,后缀要准确0
            $query['name'] = ($filename ? $filename : uniqid()) . '.' . $ext;  // $_suffix  =  '.jpg'
            $query['key'] = $key;   //任务为tid(纯数字),其它业务图片或文件自定但不能为纯数字
            if (!$mark) {
                $query['nomask'] = 1;
            }
            $result = zbj_lib_Uploadfilesv::postfile($query, $_file['name'], $_file['tmp_name'], $_file['type'],
                $params['servers_url']);
            if ($result['state'] === 1) {
                $result['msg'] = zbj_lib_Uploadfilesv::getfileurl($query['path'], $query['name']);

                //2012-8-8返回过滤过后的原始文件名称
                $result['ofilename'] = $_file['name'];
                $size = explode('x', trim($result['info'][1]['real']));
                $result['width'] = $size[0];
                $result['height'] = $size[1];
                unset($result['info']);
            } else {
                switch ($result['state']) {
                    case 2:
                        $result['msg'] = '部分缩略图未生成';
                        break;
                    case 11:
                        $result['msg'] = '保存文件失败';
                        break;
                    case 14:
                        $result['msg'] = '水印文字超长';
                        break;
                    case 17:
                        $result['msg'] = '上传图片非法';
                        break;
                    case 19:
                        $result['msg'] = '上传文件非法';
                        break;
                    case 20:
                        $result['msg'] = '上传路径非法';
                        break;
                    default:
                        //$result['msg'] = '未知错误';
                        break;
                }
                $result['state'] = 0;
            }

            return $result;
        }

        return array('state' => 0, 'msg' => '文件为空');
    }

    /**
     * 上传网络图片
     *
     * @param string      $url    需要上传的url
     * @param string      $productname
     * @param string      $path   上传路径
     * @param string      $key    与产品关联的ID号，如task_id
     * @param array       $_size  生成缩略图的大小尺寸,如：array('size[0]'=>'80x80','size[1]'=>'640x1000') 仅为图片是有效
     * @param boolean|int $mark   是否在缩略图上加水印 1为是0为否，默认为是
     * @param array       $params 其他参数 例如：水印的文字（nomask），水印位置（lc）,servers_url指定上传服务器(zbj_lib_Constant::UPFILEAPI),
     *
     * @return array  状态数组 如：array('state'=>1,'msg'='sdf')，当state为1时为成功，msg为上传成功的路径 含域名；当state为非1时，msg表示错误信息
     */
    public static function getUploadFileUrl(
        $url,
        $productname = "task",
        $path = "",
        $key = "",
        $_size = array(),
        $mark = 1,
        $params = array()
    ) {
        $query = array();
        $urlinfo = parse_url($url);
        if ($urlinfo['scheme'] && !in_array($urlinfo['scheme'], array('http'))) {
            return array('state' => 0, 'msg' => '目前只支持http格式');
        }
        $path_parts = pathinfo($url);
        $ext = $path_parts['extension'] ? $path_parts['extension'] : 'jpg';
        $filename = $path_parts['filename'];
        $type_img = array('jpg', 'gif', 'jpeg', 'png', 'bmp');
        if (in_array($ext, $type_img)) {
            $_file_type = 1;
        } elseif (in_array($ext, array('php', 'phps', 'php5', 'php4'))) {
            return array('state' => 0, 'msg' => '非法扩展名');
        } else {
            return array('state' => 0, 'msg' => '非法扩展名');
        }
        //图片尺寸
        if (count($_size) > 0) {
            foreach ($_size as $vkey => $value) {
                $query[$vkey] = $value;
            }
        }

        $localfile = self::getRemoteFile($url, $ext);

        $query['path'] = $productname . ($path ? $path : date("/Y-m/d/", time())) . ($key ? $key . "/" : "pub/");
        $query['type'] = $_file_type;  //为图片时填1,非图片文件填
        //唯一文件名由自己构造,不能使用上传文件的名字，有可能重复,可以使用自增id、时间截或随机等为文件名,后缀要准确0
        $query['name'] = ($filename ? md5($filename . uniqid()) : uniqid()) . '.' . $ext;  // $_suffix  =  '.jpg'
        if (!$mark) {
            $query['nomask'] = 1;
        }
        $query['scale'] = 1;   //不足裁剪尺寸则放大
        $result = zbj_lib_Uploadfilesv::postfile($query, $query['name'], $localfile, "", $params['servers_url']);
        if ($result['state'] === 1) {
            $result['msg'] = zbj_lib_Uploadfilesv::getfileurl($query['path'], $query['name']);
            //2012-8-8返回过滤过后的原始文件名称
            $result['ofilename'] = $filename;
            $size = explode('x', trim($result['info'][1]['real']));
            $result['width'] = $size[0];
            $result['height'] = $size[1];
            $result['filename'] = $query['name'];
            $result['ext'] = $ext;
            $sizef = explode('x', trim($result['info']['size']));
            $result['widthf'] = $sizef[0];
            $result['heightf'] = $sizef[1];
            unset($result['info']);
        } else {
            switch ($result['state']) {
                case 2:
                    $result['msg'] = '部分缩略图未生成';
                    break;
                case 11:
                    $result['msg'] = '保存文件失败';
                    break;
                case 14:
                    $result['msg'] = '水印文字超长';
                    break;
                case 17:
                    $result['msg'] = '上传图片非法';
                    break;
                case 19:
                    $result['msg'] = '上传文件非法';
                    break;
                case 20:
                    $result['msg'] = '上传路径非法';
                    break;
                default:
                    //$result['msg'] = '未知错误';
                    break;
            }
            $result['state'] = 0;
        }
        @unlink($localfile);

        return $result;
    }

    /**
     * 加密上传附件信息
     *
     * @param array $file
     *
     * @return string
     */
    public static function encodeFile($file)
    {
        return substr(md5(serialize($file) . zbj_lib_Constant::ZBJ_SYSUSERKEY), 0, 30);
    }

    /**
     * 检查加密的附件附件信息是否合法
     *
     * @param array $file
     *
     * @return bool
     */
    public static function checkEncodeFile($file)
    {
        $filecode = $file['filecode'];
        $file['filecode'] = substr($file['filecode'], 0, 32);
        if ($filecode == $file['filecode'] . substr(md5(serialize($file) . zbj_lib_Constant::ZBJ_SYSUSERKEY), 0, 30)) {
            return true;
        }

        return false;
    }


    /**
     * 页面不存在，执行404操作 +echo +exit
     *
     * @param string $tpl    自定义模板地址
     * @param array  $params 自定义模板变量
     *
     * @return null exit&echo
     */
    public static function run404($tpl = '', $params = array())
    {
        header('HTTP/1.1 404 Not Found');
        header('Status: 404 Not Found');

        if (SGui::isRakeZbjProjectRender() || defined('IS_RAKE_ZBJ_PROJECT')) {
            $is_rake_project = true;
            $srvBasePage = new zbj_components_basepage($is_rake_project);
            $srvBasePage->setTplDir("common");
            $tpl = '404.tpl';
            $render_parameters = array_merge((array)$srvBasePage->rakeTplVar, (array)$params);
            echo $srvBasePage->rakeZbjRender($tpl, $render_parameters);
        } else {
            $srvGui = new SGui();
            $tpl = $tpl ? $tpl : dirname(__FILE__) . '/../templates/common/404.html';
            echo $srvGui->render($tpl, $params);
        }
        exit;
    }

    /**
     * 301永久跳转 +exit
     *
     * @param string $url 跳转地址
     *
     * @return null
     * @exit
     */
    public static function run301($url)
    {
        $url = self::isRefererMyDomain($url) ? $url : zbj_lib_Constant::MAIN_URL;
        header('HTTP/1.1 301 Moved Permanently');
        header('Location:' . $url, true, 301);
        exit();
    }

    /**
     *302临时跳转 +exit
     *
     * @param string $url 跳转地址
     *
     * @return null
     * @exit
     */
    public static function run302($url)
    {
        $url = self::isRefererMyDomain($url) ? $url : zbj_lib_Constant::MAIN_URL;
        header('HTTP/1.1 302 Moved Temporarily');
        header('Location:' . $url, true, 302);
        exit();
    }

    /**
     * 通过curl获取文件内容
     *
     * @param string $url
     *
     * @return mixed|string
     */
    public static function curl_get_file($url)
    {
        $c = curl_init();
        curl_setopt($c, CURLOPT_URL, $url);
        curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($c, CURLOPT_ENCODING, "UTF-8");
        $content = curl_exec($c);
        curl_close($c);

        return $content;
    }

    /**
     * 用curl重写file_get_contents,规避file_get_contents的堵塞问题
     *
     * @param string       $url     请求的url
     * @param array|string $data    请求的参数
     * @param string       $method  请求的方法
     * @param int          $timeout 请求超时的时间
     * @param bool|true    $sync    同步还是异步
     *
     * @return mixed|string
     */
    public static function file_get_contents_safe($url, $data = array(), $method = 'GET', $timeout = 5, $sync = true)
    {
        $ch = curl_init();

        if (is_array($data)) {
            $data = http_build_query($data);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, $sync);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_NOBODY, !$sync);

        if (strtoupper($method) == 'POST') {
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            if (strtoupper($method) == 'GET') {
                curl_setopt($ch, CURLOPT_URL, empty($data) ? $url : $url . '?' . $data);
            } else { //PUT方法支持
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            }
        }
        $return = curl_exec($ch);
        curl_close($ch);
        
        return $return;     
    }

    /**
     * 判断后缀名，过滤文件名的特殊字符
     *
     * @param string $filename
     *
     * @return false|string 如果没有后缀名返回false，如果有返回过滤后的文件名
     */
    public static function filterFilename($filename)
    {
        $filename = preg_replace(array('/\(/', '/\+/', '/\)/', '/\[/', '/\]/', '/\{/', '/\}/', '/\~/'), array(),
            self::getStr($filename));
        $nameArr = explode(".", $filename);
        if (count($nameArr) < 2 || !end($nameArr)) {
            return false;
        }
        $tmp_name = substr($filename, 0, -1 - strlen(end($nameArr)));
        if (!$tmp_name) {
            $tmp_name = 'undefined';
        }

        return $tmp_name . '.' . end($nameArr);
    }

    /**
     * 判断一个字符串是否为数组，包括整数和浮点数
     *
     * @param string $val
     *
     * @return boolean
     */
    public static function isNumberNew($val)
    {
        if (preg_match('/^[0-9]+[\.]{0,1}[0-9]*$/', $val)) {
            return true;
        }

        return false;
    }

    /**
     * 是否是ajax提交
     *
     * @return bool
     * @author glzaboy<glzaboy@163.com>
     */
    public static function isAjax()
    {
        return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
            && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
    }

    /**
     * 渲染评论，即：加上@链接
     *
     * @param string $str     评论
     * @param array  $pattern @的人
     * @param array  $uidArr  @的人对应的user_id
     *
     * @return string
     */
    public static function renderCommnet($str = '', $pattern = array(), $uidArr = array())
    {
        if (!($pattern && $uidArr)) {
            return $str;
        }
        $replacement = array();
        foreach ($pattern as $k => $p) {
            $replacement[] = '<a href="' . zbj_lib_Constant::HOME_URL . '/' . $uidArr[$k] . '">' . substr($p, 1,
                    -1) . '</a>';
        }

        return preg_replace($pattern, $replacement, $str);
    }

    /**
     * 判断一个字符串中是否只包含了 数字和逗号
     *
     * @param string $string
     *
     * @return bool
     */
    public static function onlyNumAndComma($string)
    {
        if (preg_match('/[^\d,]+/', $string)) {
            return false;
        }

        return true;
    }

    /**
     * 计算中英文混合字符串的长度
     *
     * @param string $str
     *
     * @return int
     */
    public static function ccstrlen($str)
    {
        $cclen = 0;
        $asclen = strlen($str);
        //$ind = 0;
        $hascc = preg_match("[xa1-xfe]", $str); #判断是否有汉字
        $hasasc = preg_match("[x01-xa0]", $str); #判断是否有ascii字符
        if ($hascc && !$hasasc) #只有汉字的情况
        {
            return strlen($str) / 2;
        }
        if (!$hascc && $hasasc) #只有ascii字符的情况
        {
            return strlen($str);
        }
        for ($ind = 0; $ind < $asclen; $ind++) {
            if (ord(substr($str, $ind, 1)) > 0xa0) {
                $cclen++;
                $ind++;
            } else {
                $cclen++;
            }
        }

        return $cclen;
    }

    /**
     * 从左边截取中英文混合字符串
     *
     * @param string $str
     * @param int    $len
     *
     * @return string
     */
    public static function ccstrleft($str, $len)
    {
        $asclen = strlen($str);
        if ($asclen <= $len) {
            return $str;
        }
        $hascc = preg_match("[xa1-xfe]", $str); #同上
        $hasasc = preg_match("[x01-xa0]", $str);
        if (!$hascc) {
            return substr($str, 0, $len);
        }
        if (!$hasasc) {
            if ($len & 0x01) #如果长度是奇数
            {
                return substr($str, 0, $len + $len - 2);
            } else {
                return substr($str, 0, $len + $len);
            }
        }
        $cind = 0;
        $flag = 0;
        while ($cind < $asclen) {
            if (ord(substr($str, $cind, 1)) < 0xa1) {
                $flag++;
            }
            $cind++;
        }
        if ($flag & 0x01) {
            return substr($str, 0, $len);
        } else {
            return substr($str, 0, $len - 1);
        }
    }

    /**
     * 获取当前的url地址
     *
     * @param bool $ignore_port
     *
     * @return string $url
     */
    public static function getCurrentUrl($ignore_port = false)
    {
        $url = 'http';
        if (self::isHttpsConnection() === true) {  //check for https
            $url .= "s";
        }
        $domain = $_SERVER['HTTP_HOST'];
        $url .= '://' . $domain;
        $port = $_SERVER["SERVER_PORT"];
        if (!$ignore_port && !in_array(intval($port), array(80, 443))) {
            $url .= ':' . $port;
        }
        $url .= $_SERVER['REQUEST_URI'];

        return $url;
    }

    /**
     *当前连接是否是https连接
     * @return bool
     */
    public static function isHttpsConnection()
    {
        return ($_SERVER['HTTPS'] && $_SERVER['HTTPS'] !== 'off' && $_SERVER['SERVER_PORT'] == 443)
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on');
    }

    public static function changeNum($num)
    {
        switch ($num) {
            case 1:
                return '一';
            case 2:
                return '二';
            case 3:
                return '三';
            case 4:
                return '四';
            case 5:
                return '五';
            case 6:
                return '六';
            case 7:
                return '七';
            case 8:
                return '八';
            case 9:
                return '九';
            case 10:
                return '十';
            default:
                return $num;
        }
    }

    /**
     * API调用
     *
     * @param string $catalog    类型
     * @param string $apiname    名称
     * @param array  $data       数据只支持数组方式
     * @param string $returnType 返回数据形式支持Array,class,object
     *
     * @return mixed|boolean
     */
    public static function apicall($catalog, $apiname, $data = array(), $returnType = 'Array')
    {
        $data ['TIME'] = time();
        $token = array(
            'TOKEN' => zbj_lib_Constant::API_TOKEN,
            'TIME'  => $data ['TIME'],
        );
        sort($token, SORT_STRING);
        $data ['signature'] = sha1(implode($token));
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_URL, zbj_lib_Constant::API_URL . "/api" . $catalog . '/' . $apiname);
        $content = curl_exec($ch);
        if (curl_getinfo($ch, CURLINFO_HTTP_CODE) == 200) {
            curl_close($ch);
            switch (strtolower($returnType)) {
                case 'array' :
                    return json_decode($content, true);
                    break;
                case 'object' :
                case 'class' :
                default :
                    return json_decode($content, false);
                    break;
            }
        } else {
            curl_close($ch);

            return false;
        }
    }

    /**
     * 调用ZBJAPI
     *
     * @param string       $api    要调用的API接口名
     * @param array|string $param  请求此API接口要提交的参数
     * @param string       $method 指定发起请求的方式，支持GET|POST
     *
     * @return mixed|array|boolean
     */
    public static function zbjapicall($api, $param = array(), $method = 'GET')
    {
        if (!defined('lib_Constant::ZBJAPI_APPID') || !defined('lib_Constant::ZBJAPI_APPSECRET')) {
            return self::setStaticError('系统配置为空');
        }
        if (!defined('zbj_lib_Constant::ZBJAPI_URL')) {
            return self::setStaticError('请求地址为空');
        }

        if (!is_array($param)) {
            $param = (array)$param;
        }
        /** @noinspection PhpUndefinedClassInspection */
        $param['appid'] = lib_Constant::ZBJAPI_APPID;
        $param['timestamp'] = time();
        $param['sign'] = self::zbjapimksign($param);
        $query = array();
        foreach ($param as $qk => $qv) {
            $query[] = "{$qk}=" . rawurlencode($qv);
        }
        $query = join('&', $query);
        if ($method == 'POST') {
            $zbjapi_url = sprintf('%s/%s', zbj_lib_Constant::ZBJAPI_URL, $api);
            $result = self::file_get_contents_safe($zbjapi_url, $query, 'POST');
        } else {
            $zbjapi_url = sprintf('%s/%s?%s', zbj_lib_Constant::ZBJAPI_URL, $api, $query);
            $result = self::file_get_contents_safe($zbjapi_url);
        }
        if (empty($result)) {
            return self::setStaticError('返回数据为空');
        }
        $result = @json_decode($result, true);
        if ($result === null) {
            return self::setStaticError('解析返回的数据失败1');
        }
        if (!is_array($result)) {
            return self::setStaticError('解析返回的数据失败2');
        }

        return $result;
    }

    /**
     * set static error
     *
     * @param string $msg
     *
     * @return bool
     */
    private static function setStaticError($msg)
    {
        self::$error = $msg;

        return false;
    }

    /**
     * get static error
     *
     * @return string
     */
    public static function getStaticError()
    {
        return self::$error;
    }

    /**
     * 生成ZBJAPI验证用的sign
     *
     * @param array $param
     *
     * @return string
     */
    private static function zbjapimksign($param)
    {
        /** @noinspection PhpUndefinedClassInspection */
        $param['appsecret'] = lib_Constant::ZBJAPI_APPSECRET;
        $sign = array();
        foreach ($param as $key => $_param) {
            $sign[] = sprintf("%s=%s", $key, str_replace(array('+', ' '), array('%7E', '~'), rawurlencode($_param)));
        }
        $sign = join('|', $sign);
        $sign = hash('sha1', $sign);

        return $sign;
    }

    /**
     * API调用
     *
     * @param string $catalog    类型
     * @param string $apiname    名称
     * @param array  $data       数据只支持数组方式
     * @param string $returnType 返回数据形式支持Array,class,object
     *
     * @return mixed|boolean
     */
    public static function oaapicall($catalog, $apiname, $data = array(), $returnType = 'Array')
    {
        $data['ZBJ_URL'] = $_SERVER['REQUEST_URI'];
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_URL,
            zbj_lib_Constant::OA_URL . "/general/zbj-new/api/" . $catalog . '/' . $apiname . '.php');
        $content = curl_exec($ch);
        if (curl_getinfo($ch, CURLINFO_HTTP_CODE) == 200) {
            curl_close($ch);
            switch (strtolower($returnType)) {
                case 'array' :
                    return json_decode($content, true);
                    break;
                case 'object' :
                case 'class' :
                default :
                    return json_decode($content, false);
                    break;
            }
        } else {
            curl_close($ch);

            return false;
        }
    }

    /**
     * 往队列里面放数据
     *
     * @param int $type  1:交稿：mk_works,2:评论：mk_task_comment,3点评（稿件的评论）mk_works_comment,4:头像,5:昵称,6:个人介绍,7:服务,8:身份
     * @param int $pk_id 事务主键
     *
     * @return bool
     * @deprecated
     */
    public static function pushLgCheckQueue($type, $pk_id)
    {
        unset($type, $pk_id);
        return true;
        /*
        $queue = 'lg_check_queue';
        $q = new SQueue ($queue);
        $q->push($type . ',' . $pk_id);
        */
    }

    /**
     * ubb to html
     *
     * @param string $sUBB
     *
     * @return string
     */
    public static function ubb2html($sUBB)
    {
        $sHtml = $sUBB;
        global $emotPath, $cnum, $arrcode, $bUbb2htmlFunctionInit;
        $cnum = 0;
        $arrcode = array();
        $emotPath = 'http://s.zbjimg.com/ubb/xheditor_emot/default/'; //表情根路径

        if (!$bUbb2htmlFunctionInit) {

            function saveCodeArea($match)
            {
                global $cnum, $arrcode;
                $cnum++;
                $arrcode[$cnum] = $match[0];

                return "[\tubbcodeplace_" . $cnum . "\t]";
            }

        }
        $sHtml = preg_replace_callback('/\[code\s*(?:=\s*((?:(?!")[\s\S])+?)(?:"[\s\S]*?)?)?\]([\s\S]*?)\[\/code\]/i',
            'saveCodeArea', $sHtml);

        $sHtml = preg_replace("/&/", '&amp;', $sHtml);
        $sHtml = preg_replace("/</", '&lt;', $sHtml);
        $sHtml = preg_replace("/>/", '&gt;', $sHtml);
        $sHtml = preg_replace("/\r?\n/", '<br />', $sHtml);

        $sHtml = preg_replace("/\[(\/?)(b|u|i|s|sup|sub)\]/i", '<$1$2>', $sHtml);
        $sHtml = preg_replace('/\[color\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\]/i', '<span style="color:$1;">', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getSizeName($match)
            {
                $arrSize = array('8pt', '10pt', '12pt', '14pt', '18pt', '24pt', '36pt');

                return '<span style="font-size:' . $arrSize[$match[1] - 1] . ';">';
            }

        }
        $sHtml = preg_replace_callback("/\[size\s*=\s*(\d+?)\s*\]/i", 'getSizeName', $sHtml);
        $sHtml = preg_replace('/\[font\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\]/i', '<span style="font-family:$1;">', $sHtml);
        $sHtml = preg_replace('/\[back\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\]/i', '<span style="background-color:$1;">',
            $sHtml);
        $sHtml = preg_replace("/\[\/(color|size|font|back)\]/i", '</span>', $sHtml);

        for ($i = 0; $i < 3; $i++
        ) {
            $sHtml = preg_replace('/\[align\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\](((?!\[align(?:\s+[^\]]+)?\])[\s\S])*?)\[\/align\]/',
                '<p align="$1">$2</p>', $sHtml);
        }
        $sHtml = preg_replace('/\[img\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*?)?\s*\[\/img\]/i', '<img src="$1" alt="" />',
            $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getImg($match)
            {
                $alt = $match[1];
                $p1 = $match[2];
                $p2 = $match[3];
                $p3 = $match[4];
                $src = $match[5];
                $a = $p3 ? $p3 : (!is_numeric($p1) ? $p1 : '');

                return '<img src="' . $src . '" alt="' . $alt . '"' . (is_numeric($p1) ? ' width="' . $p1 . '"' : '') . (is_numeric($p2) ? ' height="' . $p2 . '"' : '') . ($a ? ' align="' . $a . '"' : '') . ' />';
            }

        }
        $sHtml = preg_replace_callback('/\[img\s*=([^,\]]*)(?:\s*,\s*(\d*%?)\s*,\s*(\d*%?)\s*)?(?:,?\s*(\w+))?\s*\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*)?\s*\[\/img\]/i',
            'getImg', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getEmot($match)
            {
                global $emotPath;
                $arr = explode(',', $match[1]);
                if (!isset($arr[1])) {
                    $arr[1] = $arr[0];
                    $arr[0] = 'default';
                }
                $path = $emotPath . $arr[0] . '/' . $arr[1] . '.gif';

                return '<img src="' . $path . '" alt="' . $arr[1] . '" />';
            }

        }
        $sHtml = preg_replace_callback('/\[emot\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\/\]/i', 'getEmot', $sHtml);
        //人性化表情UBB标签处理
        $sHtml = strtr($sHtml, array(
            '[生气]'     => "<img src='" . $emotPath . '1.gif' . "'>",
            '[吃饭]'     => "<img src='" . $emotPath . '2.gif' . "'>",
            '[疑问(微笑)]' => "<img src='" . $emotPath . '3.gif' . "'>",
            '[打针]'     => "<img src='" . $emotPath . '4.gif' . "'>",
            '[大哭]'     => "<img src='" . $emotPath . '5.gif' . "'>",
            '[拳击]'     => "<img src='" . $emotPath . '6.gif' . "'>",
            '[投降]'     => "<img src='" . $emotPath . '7.gif' . "'>",
            '[俯卧撑]'    => "<img src='" . $emotPath . '8.gif' . "'>",
            '[疑问(不解)]' => "<img src='" . $emotPath . '9.gif' . "'>",
            '[发财]'     => "<img src='" . $emotPath . '10.gif' . "'>",
            '[瞌睡]'     => "<img src='" . $emotPath . '11.gif' . "'>",
            '[打酱油]'    => "<img src='" . $emotPath . '12.gif' . "'>",
            '[憨笑]'     => "<img src='" . $emotPath . '13.gif' . "'>",
            '[吃西瓜]'    => "<img src='" . $emotPath . '14.gif' . "'>",
            '[汗]'      => "<img src='" . $emotPath . '15.gif' . "'>",
            '[惊恐]'     => "<img src='" . $emotPath . '16.gif' . "'>",
            '[中标]'     => "<img src='" . $emotPath . '17.gif' . "'>",
            '[翻墙]'     => "<img src='" . $emotPath . '18.gif' . "'>",
            '[摇头]'     => "<img src='" . $emotPath . '19.gif' . "'>",
            '[念经]'     => "<img src='" . $emotPath . '20.gif' . "'>",
            '[害羞]'     => "<img src='" . $emotPath . '21.gif' . "'>",
            '[睡觉]'     => "<img src='" . $emotPath . '22.gif' . "'>",
            '[勤奋]'     => "<img src='" . $emotPath . '23.gif' . "'>",
            '[真棒]'     => "<img src='" . $emotPath . '24.gif' . "'>",
            '[偷笑]'     => "<img src='" . $emotPath . '25.gif' . "'>",
            '[听音乐]'    => "<img src='" . $emotPath . '26.gif' . "'>",
            '[晕]'      => "<img src='" . $emotPath . '27.gif' . "'>",
        ));
        if (!$bUbb2htmlFunctionInit) {

            function getUrl($match)
            {
                $url = $match[1];
                if (preg_match('/' . zbj_lib_Constant::DOMAIN . '/i', $url)) {
                    return '<a target="_blank" href="' . $url . '">' . $url . '</a>';
                } else {
                    return '<a target="_blank" href="' . zbj_lib_Constant::MAIN_URL . '/direct?' . $url . '">' . $url . '</a>';
                }
            }

        }
        if (!$bUbb2htmlFunctionInit) {

            function getLink($match)
            {
                $url = $match[1];
                $str = $match[2];
                if (preg_match('/' . zbj_lib_Constant::DOMAIN . '/i', $url)) {
                    return '<a target="_blank" href="' . $url . '">' . $str . '</a>';
                } else {
                    return '<a target="_blank" href="' . zbj_lib_Constant::MAIN_URL . '/direct?' . $url . '">' . $str . '</a>';
                }
            }

        }
        $sHtml = preg_replace_callback('/\[url\]\s*(((?!")[\s\S])*?)(?:"[\s\S]*?)?\s*\[\/url\]/i', 'getUrl', $sHtml);
        $sHtml = preg_replace_callback('/\[url\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\]\s*([\s\S]*?)\s*\[\/url\]/i',
            'getLink', $sHtml);
        $sHtml = preg_replace('/\[email\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*?)?\s*\[\/email\]/i',
            '<a href="mailto:$1">$1</a>', $sHtml);
        $sHtml = preg_replace('/\[email\s*=\s*([^\]"]+?)(?:"[^\]]*?)?\s*\]\s*([\s\S]+?)\s*\[\/email\]/i',
            '<a href="mailto:$1">$2</a>', $sHtml);
        $sHtml = preg_replace("/\[quote\]([\s\S]*?)\[\/quote\]/i", '<blockquote>$1</blockquote>', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getFlash($match)
            {
                $w = $match[1];
                $h = $match[2];
                $url = $match[3];
                if (!$w
                ) {
                    $w = 480;
                }
                if (!$h
                ) {
                    $h = 400;
                }

                return '<embed type="application/x-shockwave-flash" src="' . $url . '" wmode="opaque" quality="high" bgcolor="#ffffff" menu="false" play="true" loop="true" width="' . $w . '" height="' . $h . '" />';
            }

        }
        $sHtml = preg_replace_callback('/\[flash\s*(?:=\s*(\d+)\s*,\s*(\d+)\s*)?\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*?)?\s*\[\/flash\]/i',
            'getFlash', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getMedia($match)
            {
                $w = $match[1];
                $h = $match[2];
                $play = $match[3];
                $url = $match[4];
                if (!$w
                ) {
                    $w = 480;
                }
                if (!$h
                ) {
                    $h = 400;
                }

                return '<embed type="application/x-mplayer2" src="' . $url . '" enablecontextmenu="false" autostart="' . ($play == '1' ? 'true' : 'false') . '" width="' . $w . '" height="' . $h . '" />';
            }

        }
        $sHtml = preg_replace_callback('/\[media\s*(?:=\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*(\d+)\s*)?)?\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*?)?\s*\[\/media\]/i',
            'getMedia', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getTable($match)
            {
                return '<table' . (isset($match[1]) ? ' width="' . $match[1] . '"' : '') . (isset($match[2]) ? ' bgcolor="' . $match[2] . '"' : '') . '>';
            }

        }
        $sHtml = preg_replace_callback('/\[table\s*(?:=(\d{1,4}%?)\s*(?:,\s*([^\]"]+)(?:"[^\]]*?)?)?)?\s*\]/i',
            'getTable', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getTR($match)
            {
                return '<tr' . (isset($match[1]) ? ' bgcolor="' . $match[1] . '"' : '') . '>';
            }

        }
        $sHtml = preg_replace_callback('/\[tr\s*(?:=(\s*[^\]"]+))?(?:"[^\]]*?)?\s*\]/i', 'getTR', $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getTD($match)
            {
                $col = isset($match[1]) ? $match[1] : 0;
                $row = isset($match[2]) ? $match[2] : 0;
                $w = isset($match[3]) ? $match[3] : null;

                return '<td' . ($col > 1 ? ' colspan="' . $col . '"' : '') . ($row > 1 ? ' rowspan="' . $row . '"' : '') . ($w ? ' width="' . $w . '"' : '') . '>';
            }

        }
        $sHtml = preg_replace_callback("/\[td\s*(?:=\s*(\d{1,2})\s*,\s*(\d{1,2})\s*(?:,\s*(\d{1,4}%?))?)?\s*\]/i",
            'getTD', $sHtml);
        $sHtml = preg_replace("/\[\/(table|tr|td)\]/i", '</$1>', $sHtml);
        $sHtml = preg_replace("/\[\*\]((?:(?!\[\*\]|\[\/list\]|\[list\s*(?:=[^\]]+)?\])[\s\S])+)/i", '<li>$1</li>',
            $sHtml);
        if (!$bUbb2htmlFunctionInit) {

            function getUL($match)
            {
                $str = '<ul';
                if (isset($match[1])
                ) {
                    $str .= ' type="' . $match[1] . '"';
                }

                return $str . '>';
            }

        }
        $sHtml = preg_replace_callback('/\[list\s*(?:=\s*([^\]"]+))?(?:"[^\]]*?)?\s*\]/i', 'getUL', $sHtml);
        $sHtml = preg_replace("/\[\/list\]/i", '</ul>', $sHtml);

        for ($i = 1; $i <= $cnum; $i++
        ) {
            $sHtml = str_replace("[\tubbcodeplace_" . $i . "\t]", $arrcode[$i], $sHtml);
        }

        if (!$bUbb2htmlFunctionInit) {

            function fixText($match)
            {
                $text = $match[2];
                $text = preg_replace("/\t/", '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;', $text);
                $text = preg_replace("/ /", '&nbsp;', $text);

                return $match[1] . $text;
            }

        }
        $sHtml = preg_replace_callback('/(^|<\/?\w+(?:\s+[^>]*?)?>)([^<$]+)/i', 'fixText', $sHtml);
        //显示源代码
        if (!$bUbb2htmlFunctionInit) {

            function showCode($match)
            {
                $match[1] = strtolower($match[1]);
                if (!$match[1]
                ) {
                    $match[1] = 'plain';
                }
                $match[2] = preg_replace("/</", '&lt;', $match[2]);
                $match[2] = preg_replace("/>/", '&gt;', $match[2]);

                return '<pre name="code" class="' . $match[1] . '">' . $match[2] . '</pre>';
            }

        }
        $sHtml = preg_replace_callback('/\[code\s*(?:=\s*((?:(?!")[\s\S])+?)(?:"[\s\S]*?)?)?\]([\s\S]*?)\[\/code\]/i',
            'showCode', $sHtml);
        //flv播放
        if (!$bUbb2htmlFunctionInit) {

            function showFlv($match)
            {
                $w = $match[1];
                $h = $match[2];
                $url = $match[3];
                if (!$w
                ) {
                    $w = 480;
                }
                if (!$h
                ) {
                    $h = 400;
                }

                return '<embed type="application/x-shockwave-flash" src="mediaplayer/player.swf" wmode="transparent" allowscriptaccess="always" allowfullscreen="true" quality="high" bgcolor="#ffffff" width="' . $w . '" height="' . $h . '" flashvars="file=' . $url . '" />';
            }

        }
        $sHtml = preg_replace_callback('/\[flv\s*(?:=\s*(\d+)\s*,\s*(\d+)\s*)?\]\s*(((?!")[\s\S])+?)(?:"[\s\S]*?)?\s*\[\/flv\]/i',
            'showFlv', $sHtml);
        $bUbb2htmlFunctionInit = true;

        return $sHtml;
    }

    /**
     * 判断是否为搜索引擎访问
     *
     * @return boolean
     */
    public static function is_spider()
    {
        $searchengine_bot = array(
            'googlebot',
            'mediapartners-google',
            'baiduspider',
            'msnbot',
            'yodaobot',
            'yahoo! slurp;',
            'yahoo! slurp china;',
            'iaskspider',
            'sogou web spider',
            'sogou push spider',
        );
        $spider = strtolower($_SERVER['HTTP_USER_AGENT']);
        if (!$spider) {
            return false;
        }
        foreach ($searchengine_bot as $v) {
            if (strpos($spider, $v) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * 将16进制颜色转化为rgb值
     *
     * @param string $color
     *
     * @return array|bool
     */
    public static function hex2rgb($color)
    {
        if ($color[0] == '#') {
            $color = substr($color, 1);
        }
        if (strlen($color) == 6) {
            list($r, $g, $b) = array($color[0] . $color[1], $color[2] . $color[3], $color[4] . $color[5]);
        } elseif (strlen($color) == 3) {
            list($r, $g, $b) = array($color[0] . $color[0], $color[1] . $color[1], $color[2] . $color[2]);
        } else {
            return false;
        }
        $r = hexdec($r);
        $g = hexdec($g);
        $b = hexdec($b);

        return array($r, $g, $b);
    }


    /***
     *用新key重新索引数组
     *
     * @param array  $array
     * @param string $key
     * @param string $value
     *
     * @return array
     */
    public static function indexArray($array, $key, $value = '*')
    {
        if (is_array($array) && $array) {
            $arr = array();
            if ($value == '*') {
                foreach ($array as $k => $v) {
                    $arr[$v[$key]] = $v;
                }
            } else {
                foreach ($array as $k => $v) {
                    $arr[$v[$key]] = $v[$value];
                }
            }

            return $arr;
        } else {
            return $array;
        }
    }


    /**
     *调用smarty插件的modifier方法 (string $modifier_name, mixed $input, ...)
     *
     * @return string
     */
    public static function call_smarty_plugin_modifier()
    {
        $args = func_get_args();
        $func_name = array_shift($args);
        $smarty_slightphp_dir = SMARTY_DIR . 'plugins_slightphp' . DIRECTORY_SEPARATOR;
        $file_name = 'modifier.' . $func_name . '.php';
        $path = $smarty_slightphp_dir . $file_name;
        if (!file_exists($path)) {
            self::$error = 'smarty插件不存在';

            return false;
        }
        require_once($path);
        $smarty_func_name = 'smarty_modifier_' . $func_name;
        if (!function_exists($smarty_func_name)) {
            self::$error = $smarty_func_name . '方法不存在';

            return false;
        }

        return call_user_func_array($smarty_func_name, $args);
    }

    /**
     * notice servie stop
     *
     * @return bool
     */
    public static function noticeServcieStop()
    {
        $cache = new zbj_lib_cache('memcache');
        $begin = $cache->get('zhubajie_noticeservciestop_begin');
        $end = $cache->get('zhubajie_noticeservciestop_end');

        if (is_numeric($begin) && is_numeric($end) && time() >= $begin && time() <= $end) {
            if ($_COOKIE['_tu'] == 'jksdfhoawrl3ysdhf8a7df2jh') {
                return false;
            }
            if ($cache->get('zhubajie_noticeservciestop_sdfwf') == 1) {
                $model = new zbj_model_mk_task();
                $error = array();
                $error['s'] = $_SERVER;
                $error['c'] = $_COOKIE;
                $items = array(
                    'id'       => intval($_COOKIE['userid']),
                    'dateline' => time(),
                    'error'    => serialize($error),
                    'type'     => 121,
                );
                $model->_db->insert('mk_conv_log', $items);

                return true;
            }

            return false;
        }

        return false;
    }

    /**
     * 跳转到英文站 +?exit
     *
     * @deprecated
     *
     * @param string $url
     *
     * @return null
     */
    public static function redirectToWitmart($url = '')
    {
        unset($url);
        return null;
    }

    /**
     * 判断是否是GA统计站内分析热点图验证的UA Mozilla/5.0 (compatible; Google-Proxy; build=0e0)
     *
     * @return bool
     */
    public static function is_google_analytics_ua()
    {
        $spider = strtolower($_SERVER['HTTP_USER_AGENT']);
        if (!$spider) {
            return false;
        }
        $ga_ua = 'google-proxy';

        return strpos($spider, $ga_ua) !== false;
    }

    /**
     * 创建快速登录token
     *
     * @param int    $user_id 用户ID
     * @param int    $type    1后台快速登录 2交易顾问发布需求登录 3移动端登录
     * @param string $log     需要记录的登录日志内容
     *
     * @return string
     */
    public static function createquickLoginToken($user_id, $type, $log = '')
    {
        $str = "{$user_id}[zbj]{$type}[zbj]" . time();
        $str .= $log ? "[zbj]{$log}" : "";

        return base64_encode(self::authcode($str, 'ENCODE', zbj_lib_Constant::ZBJ_SYSUSERKEY));
    }

    /**
     * 是否为重复请求
     *
     * @param int $time 请求间隔
     * @param int $refe 是否检查来路
     *
     * @return boolean true表示为非正常请求（这时候就不能响应数据）
     */
    public static function isRepeatRequest($time = 3, $refe = 0)
    {
        $return = false;
        if ($refe == 1 && self::isRefererMyDomain($_SERVER["HTTP_REFERER"]) === false) {
            return true;
        }
        $cacheName = "prevent_repeat_request_" . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'] . $_SERVER['REQUEST_METHOD'] . self::getIp(1);
        $cache = new zbj_lib_cache('memcache');
        $cacheRs = $cache->get($cacheName);
        if ($cacheRs) {
            if (time() - $cacheRs['lasttime'] < $time) {
                $return = true;
            }
            $cacheRs = array(
                'times'    => intval($cacheRs['times'] + 1),
                'lasttime' => time(),
            );
            /**
             * if ($cacheRs['times'] >= 10) {
             * $iptable = $cache->get('repeat_request_iptable');
             * $iptable[$_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']][] = self::getIp();
             * $cache->set('repeat_request_iptable', $iptable, 864000);
             * }
             **/
        } else {
            $cacheRs = array(
                'times'    => 1,
                'lasttime' => time(),
            );
        }
        $cache->set($cacheName, $cacheRs, $time * 5);

        return $return;
    }


    /**
     * 检查csrf的token是否合法
     *
     * @param bool $del 检查合法后是否删除l
     *
     * @return bool
     */
    public static function checkCsrfToken($del = false)
    {
        $csrf_token = $_GET['zbj_csrf_token'] ? $_GET['zbj_csrf_token'] : $_POST['zbj_csrf_token'];
        if (strlen($csrf_token) != 32) {
            return false;
        }
        $cache = new zbj_lib_cache('memcache');
        if ($cache) {
            $cacheRs = $cache->get("zbj_csrf_token_key_" . $csrf_token);
            if ($del) {
                $cache->del("zbj_csrf_token_key_" . $csrf_token);
            }
            $value = (int)$_COOKIE['userid'] > 0 ? md5($_COOKIE['userid'] . $csrf_token) : $csrf_token;
            $value = md5($value . zbj_lib_Constant::ZBJ_SYSUSERKEY);
            if ($cacheRs == $value) {
                return true;
            }

            return false;
        } else {
            return true;
        }
    }

    /**
     * 手动删除csrf的token
     *
     */
    public static function delCsrfToken()
    {
        $del_token = true;
        self::checkCsrfToken($del_token);
    }

    /**
     * 获取和设置登录用户的状态到cache  ====暂未使用====
     *
     * @param int          $userId
     * @param int          $type 1get 2set
     * @param array|string $data empty=>del
     *
     * @return mixed
     */
    public static function userLoginCache($userId, $type = 1, $data = '')
    {
        $cache = new zbj_lib_cache('memcache');
        $cacheName = "zbj_user_safelogininfo_id_{$userId}";
        if ($type == 1) {
            return $cache->get($cacheName);
        }
        if (is_array($data)) {
            return $cache->set($cacheName, $data, 604800);
        } else {
            return $cache->del($cacheName);
        }
    }

    /**
     * 清除登录状态  ====暂未使用====
     *
     * @param int $userId 清理cache
     */
    public static function clearLoginCookie($userId = 0)
    {
        $userId = $userId == 0 ? intval($_COOKIE['userid']) : $userId;
        $cookie['isquick'] = '';
        $cookie['userid'] = '';
        $cookie['nickname'] = '';
        $cookie['brandname'] = '';
        $cookie['unstatus'] = '';
        $cookie['needmobile'] = '';
        $cookie['activekey'] = '';
        $cookie['userkey'] = '';
        $cookie['safe'] = '';
        $cookie['sp'] = '';
        $cookie['skey'] = '';
        zbj_lib_BaseUtils::ssetcookie($cookie, -1, '/', zbj_lib_Constant::COOKIE_DOMAIN);
        if ($userId > 0) {
            self::userLoginCache($userId, 2, '');
        }
    }

    /**
     * 获取字符串的编码
     *
     * @param string $str
     *
     * @return string|bool
     */
    public static function getStrEncoding($str)
    {
        $encodings = array('UTF-8', 'ASCII', 'GB2312', 'GBK', 'CP936', 'HZ', 'EUC-CN', 'BIG-5', 'EUC-TW');
        foreach ($encodings as $enc) {
            if (mb_check_encoding($str, $enc)) {
                return $enc;
            }
        }

        return false;
    }

    /***
     *按比例从数组中减去一个数 比如 从array('key1'=>43.5, 'key2'=>22.5) 中减去41.5 得数组array(
     *     'key1'=>array('orig'=>43.5, 'sub'=>27.35, 'new'=>16.15),
     *     'key2'=>array('orig'=>22.5, 'sub'=>14.15, 'new'=>8.35),
     *    );
     *
     * @param array      $arr        array('key1'=> 2.55, 'key2'=> $float_val); 注意数组值总和不能为0
     * @param float      $subtrahend 减数
     * @param bool|mixed $precise    控制返回数值的精度
     * @param bool       $just_return_new
     *
     * @return array|false $arr_new
     *
     */
    public static function arrayRatioSubtraction($arr, $subtrahend, $precise = 2, $just_return_new = false)
    {
        $subtrahend = floatval($subtrahend);
        if ($subtrahend <= 0) {
            return $arr;
        }
        if (!is_array($arr)) {
            return false;
        }
        $sum = floatval(array_sum($arr));
        if ($sum == 0) {
            return false;
        }
        $ratio = floatval(floatval($subtrahend) / $sum);
        $arr_new = array();
        $sub_total = 0.00;
        foreach ($arr as $k => $v) {
            $sub_this = round(floatval($ratio * $v), $precise);
            $arr_new[$k] = array(
                'orig' => floatval($v),
                'sub'  => $sub_this,
                'new'  => round(floatval($v) - $sub_this, $precise),
            );
            $sub_total += round($arr_new[$k]['sub'], $precise);
        }
        $diff = round($subtrahend - $sub_total, $precise);
        $diff_done = null; //just fix warning
        if (!in_array($diff, array(0, -0))) {
            foreach ($arr_new as $k => $v) {
                if ($diff_done === false && $v['new'] > $diff) {
                    $arr_new[$k]['sub'] = round($arr_new[$k]['sub'] + $diff, $precise);
                    $arr_new[$k]['new'] = round($arr_new[$k]['new'] - $diff, $precise);
                    break;
                }
            }
        }
        if ($just_return_new) {
            foreach ($arr_new as $k => $v) {
                $arr_new[$k] = $v['new'];
            }
        }

        return $arr_new;
    }

    /**
     * socket模拟http post请求
     *
     * @param string $url  ex: "http://www.remote.com:80/post"
     * @param string $data ex: "name=mike&age=18"
     *
     * @return string|false
     * @author 5+
     */
    public static function postOverSocket($url, $data)
    {
        $url_info = parse_url($url);
        $httpheader = "POST " . $url_info['path'] . " HTTP/1.0\r\n";
        $httpheader .= "Host:" . $url_info['host'] . "\r\n";
        $httpheader .= "Content-Type:application/x-www-form-urlencoded\r\n";
        $httpheader .= "Content-Length:" . strlen($data) . "\r\n";
        $httpheader .= "Connection:close\r\n\r\n";
        $httpheader .= $data;
        $timeOut = 30;
        $fd = @fsockopen($url_info['host'], $url_info["port"] ? $url_info['port'] : 80, $iErrno, $sErrStr, $timeOut);
        if (!$fd) {
            return self::setStaticError($sErrStr);
        }
        //set blocking & timeout
        stream_set_blocking($fd, true);
        stream_set_timeout($fd, $timeOut);
        @fwrite($fd, $httpheader);
        //get status -- if not timeout then get res
        $status = stream_get_meta_data($fd);
        $gets = "";
        $limit = null;
        //format header & get response
        if (!$status['timed_out']) {
            while (!feof($fd)) {
                if (($header = @fgets($fd)) && ($header == "\r\n" || $header == "\n")) {
                    break;
                }
            }
            $stop = false;
            while (!feof($fd) && !$stop) {
                $data = fread($fd, ($limit == 0 || $limit > 8192 ? 8192 : $limit));
                $gets .= $data;
                if ($limit) {
                    $limit -= strlen($data);
                    $stop = $limit <= 0;
                }
            }
        }
        //close socket connection
        @fclose($fd);
        if (empty($gets) || $gets == "") {
            return self::setStaticError('empty return data');
        }

        return $gets;
    }

    /**
     * 检查两个用户之间是否能进行WEBIM的会话
     *
     * @param int $seller_id
     * @param int $buyer_id
     *
     * @return bool
     */
    public static function webIm_contactable($seller_id, $buyer_id)
    {
        $tid = $fid = null;
        if (empty($seller_id) || empty($buyer_id)) {
            self::setStaticError('双方ID不能为空');

            return false;
        }
        if ($seller_id === $buyer_id) {
            self::setStaticError('双方ID不能相同');

            return false;
        }


        $isTargetFWS = self::webim_is_target_fws($seller_id, $buyer_id);

        if ($isTargetFWS) {
            return true;
        }


        $cache = new zbj_lib_cache("memcache");

        $cacheTime = 2592000;
        $cacheName = "webim_fid_{$seller_id}_tid_{$buyer_id}";
        $rs = $cache->get($cacheName);
        if (!$rs) {
            //检查是否有反向联系权限，如果有的话就开放权沟通权限
            $rCacheName = "webim_fid_{$buyer_id}_tid_{$seller_id}";
            $rs = $cache->get($rCacheName);

            if (!$rs) {
                $sellerPac = new zbj_service_sellerpac($buyer_id);
                $node = $sellerPac->checkLimits(11);
                if (!$node) {
                    $sellerPac = new zbj_service_sellerpac($seller_id);
                    $node = $sellerPac->checkLimits(11);
                    if (!$node) {
                        self::setStaticError('暂时无法联系');

                        return false;
                    }
                }
                $cacheTime = 86400;
                $rs = time();
            }
        }
        if ($rs + $cacheTime < time()) {
            $cache->del($cacheName);
            self::setStaticError('超过一个月不能再联系');

            return false;
        } else {
            $cache->set($cacheName, time(), $cacheTime);
            //使用接口后反向建立联系
            $cacheName = "webim_fid_{$tid}_tid_{$fid}";
            if (!$cache->get($cacheName)) {
                $cache->set($cacheName, time(), 246400);
            }

            return true;
        }
    }

    /**
     * 如果接受方是 服务商，可以直接聊天
     *
     * @param int $sender
     * @param int $recipient
     *
     * @return bool
     */
    public static function webim_is_target_fws($sender, $recipient)
    {
        $webimMemKeyPrefix = 'webim_fws_';
        $recipient = intval($recipient);
        $cache = new zbj_lib_cache("memcache");

        $webimMemKeyPrefixFix = 'webim_fws_fixed_';

        $expTime = 1800; // 开店状态缓存 半个小时
        $contactedHistoryExpTime = 2592000; // 聊过天的一个月

        $recipientCacheName = $webimMemKeyPrefix . $recipient;
        $contactedHistoryCacheName = $webimMemKeyPrefix . $sender . '-' . $recipient;

        $cache->del($recipientCacheName);
        $cache->del($contactedHistoryCacheName);


        $newRecipientCacheName = $webimMemKeyPrefixFix . $recipient;
        $newContactedHistoryCacheName = $webimMemKeyPrefixFix . $sender . '-' . $recipient;
        $newContactedHistoryRevertCacheName = $webimMemKeyPrefixFix . $recipient . '-' . $sender;

        $isFws = $cache->get($newRecipientCacheName);

        if (!$isFws) {
            $mdl = new zbj_model_mb_info();
            $condition = "`user_id` = {$recipient}";
            $fields = 'user_id,isfws';
            $recipientInfo = $mdl->selectOne($condition, $fields);

            $isFws = $recipientInfo['isfws'];

            if ($isFws) {
                $cache->set($newRecipientCacheName, 'open', $expTime);
            }
        }
        if ($isFws) {
            $cache->set($newContactedHistoryCacheName, 'contacted', $contactedHistoryExpTime);

            return true;
        }

        // 否则，查看是否曾经联系过
        return $cache->get($newContactedHistoryRevertCacheName) || $cache->get($newContactedHistoryCacheName);
    }

    /**
     * 检测webIm是否在线
     *
     * @param int|array $user_id
     *
     * @return false|array ex: array(uid1 => true, uid2 => false)
     * @author 5+
     */
    public static function webIm_online($user_id)
    {
        if (is_array($user_id)) {
            $uid = implode(",", $user_id);
        } else {
            $uid = $user_id;
        }
        $url = zbj_lib_Constant::WEBIM_CHK_URL;
        $data = "idlist=$uid";
        $rs = self::postOverSocket($url, $data);
        $return = null;
        if ($rs) {
            $response = @json_decode($rs);
            if (!is_array($response)) {
                return false;
            }
            if (is_array($user_id)) {
                foreach ($user_id as $v) {
                    $return[$v] = in_array($v, $response) ? true : false;
                }
            } else {
                $return = in_array($uid, $response) ? true : false;
            }

            return $return;
        } else {
            return false;
        }
    }

    /**
     * 检测字符串是否utf-8编码
     *
     * @param string $str
     *
     * @return bool
     */
    public static function check_utf8($str)
    {
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($str[$i]);
            if ($c > 128) {
                if (($c > 247)) {
                    return false;
                } elseif ($c > 239) {
                    $bytes = 4;
                } elseif ($c > 223) {
                    $bytes = 3;
                } elseif ($c > 191) {
                    $bytes = 2;
                } else {
                    return false;
                }
                if (($i + $bytes) > $len) {
                    return false;
                }
                while ($bytes > 1) {
                    $i++;
                    $b = ord($str[$i]);
                    if ($b < 128 || $b > 191) {
                        return false;
                    }
                    $bytes--;
                }
            }
        }

        return true;
    }

    /**
     * send http status header
     *
     * @param int $code
     */
    public static function httpStatus($code)
    {
        $http = array(
            100 => "HTTP/1.1 100 Continue",
            101 => "HTTP/1.1 101 Switching Protocols",
            200 => "HTTP/1.1 200 OK",
            201 => "HTTP/1.1 201 Created",
            202 => "HTTP/1.1 202 Accepted",
            203 => "HTTP/1.1 203 Non-Authoritative Information",
            204 => "HTTP/1.1 204 No Content",
            205 => "HTTP/1.1 205 Reset Content",
            206 => "HTTP/1.1 206 Partial Content",
            300 => "HTTP/1.1 300 Multiple Choices",
            301 => "HTTP/1.1 301 Moved Permanently",
            302 => "HTTP/1.1 302 Found",
            303 => "HTTP/1.1 303 See Other",
            304 => "HTTP/1.1 304 Not Modified",
            305 => "HTTP/1.1 305 Use Proxy",
            307 => "HTTP/1.1 307 Temporary Redirect",
            400 => "HTTP/1.1 400 Bad Request",
            401 => "HTTP/1.1 401 Unauthorized",
            402 => "HTTP/1.1 402 Payment Required",
            403 => "HTTP/1.1 403 Forbidden",
            404 => "HTTP/1.1 404 Not Found",
            405 => "HTTP/1.1 405 Method Not Allowed",
            406 => "HTTP/1.1 406 Not Acceptable",
            407 => "HTTP/1.1 407 Proxy Authentication Required",
            408 => "HTTP/1.1 408 Request Time-out",
            409 => "HTTP/1.1 409 Conflict",
            410 => "HTTP/1.1 410 Gone",
            411 => "HTTP/1.1 411 Length Required",
            412 => "HTTP/1.1 412 Precondition Failed",
            413 => "HTTP/1.1 413 Request Entity Too Large",
            414 => "HTTP/1.1 414 Request-URI Too Large",
            415 => "HTTP/1.1 415 Unsupported Media Type",
            416 => "HTTP/1.1 416 Requested range not satisfiable",
            417 => "HTTP/1.1 417 Expectation Failed",
            500 => "HTTP/1.1 500 Internal Server Error",
            501 => "HTTP/1.1 501 Not Implemented",
            502 => "HTTP/1.1 502 Bad Gateway",
            503 => "HTTP/1.1 503 Service Unavailable",
            504 => "HTTP/1.1 504 Gateway Time-out",
        );
        if ($http[$code]) {
            header($http[$code]);
        }
    }

    /**
     * 判断当前请求是否是post请求
     *
     * @return bool
     */
    public static function isPostRequest()
    {
        return strtolower($_SERVER['REQUEST_METHOD']) == 'post';
    }

    /**
     * 获取注册纳税人接口的开启状态
     *
     * @return bool
     */
    public static function getRegTPOpenState()
    {
        $cache = new zbj_lib_cache('memcache');
        $opentime = $cache->get('zhubajie.taxplayer.regbegin.time');
        if (time() < strtotime('2014-03-20 00:00:00') || time() < $opentime) {
            if ($_COOKIE['_tpr'] == 'KwcD29doKwjkPO_56d54sEfe') {
                return true;
            }

            return false;
        }

        return true;
    }

    /**
     * 保存易极付接口日志
     *
     * @param object $api
     * @param int    $errcode 0: 正常，1：超时
     * @param string $msg     描述
     * @param string $data    扩展数据
     *
     * @return array|bool
     */
    public static function getApiLogData($api, $errcode = 0, $msg = '', $data = '')
    {
        if (empty($api)) {
            return false;
        }

        $orderdata = (array)$api;
        $service = $api->service;

        unset($orderdata['orderNo'], $orderdata['service'], $orderdata['partner_id'], $orderdata['debug'], $orderdata['key'], $orderdata['token']);
        unset($orderdata['gateway'], $orderdata['signType'], $orderdata['services'], $orderdata['_error'], $orderdata['execapi'], $orderdata['return_url'], $orderdata['notify_url']);

        $data = $data . (!empty($data) ? '  ||  ' : '') . json_encode($orderdata);

        $log = array(
            'unique_no'  => $api->orderNo,
            'request_no' => $api->request_no,
            'service'    => $service,
            'amount'     => round($api->amount, 2),
            'datetime'   => time(),
            'dateymd'    => date('Y-m-d'),
            'msg'        => $msg,
            'option'     => $data,
            'errcode'    => $errcode,
        );
        $logs = array();
        $order = $api->orders[0];
        if (!empty($order)) {
            if ($service == 'bounty_secured_pay' || $service == 'bounty_secured_refund') { // 托管 | 退款
                $log['trade_no'] = $order['c_order_id'];
                $log['task_id'] = intval($order['c_task_id']);
                $log['memo'] = $order['subject'];
                $log['yuser_id'] = $api->payer;

                $logs[] = $log;
            } else {
                if ($service == 'direct_pay') { // 转帐
                    $log['trade_no'] = $order['c_order_id'];
                    $log['task_id'] = intval($order['c_task_id']);
                    $log['memo'] = $order['subject'];
                    $log['yuser_id'] = $api->payer;

                    $logs[] = $log;
                } else {
                    if ($service == 'bounty_secured_transfer') { //交易打款
                        $log['trade_no'] = $order['c_order_id'];
                        $log['task_id'] = intval($order['c_task_id']);

                        if (!empty($order['payee'])) {
                            foreach ($order['payee'] as $payee) {
                                $log['memo'] = $payee['subject'] . ' | ' . $order['detail_url'];
                                $log['yuser_id'] = $payee['id'];

                                $logs[] = $log;
                            }
                        }
                    } else {
                        $log['trade_no'] = $order['c_order_id'];
                        $log['task_id'] = intval($order['c_task_id']);
                        $log['memo'] = $order['subject'];
                        $log['yuser_id'] = $api->payer;

                        $logs[] = $log;
                    }
                }
            }
        }

        if (empty($logs)) {
            $logs[] = $log;
        }

        return $logs;
    }

    /**
     *
     * 此方法可用于字符串的sql完全匹配查询
     *
     * field_hash字段需索引长度为5位 最大值为16256 sql: where `field`=$str and `field_hash`=str2int($str)
     *
     * @param string $str
     *
     * @return int
     */
    public static function str2int($str)
    {
        $str = strtoupper(hash('sha512', (string)$str));
        $len = strlen($str);
        $sum = 0;
        for ($i = 0; $i < $len; $i++) {
            $num = ord($str[$i]);
            if (($i + 1) % 4 == 0 && $num >= 65 && $num <= 90) {
                $num += 32;
            } //转小写
            $sum += $num;
        }

        return $sum;
    }

    /**
     * 此方法用于生成保单号
     *
     * @param int $sno
     *
     * @return bool|string
     */
    public static function getsecurityNumber($sno = 0)
    {
        if ($sno < 0 || $sno > 999999) {
            return false;
        }
        $sno = sprintf("%06d", $sno);

        return "91072248544" . date('y') . $sno;
    }

    /**
     * 此方法用于生成保单包号
     *
     * @param int $userid
     *
     * @return int
     */
    public static function getsecurityPackageNumber($userid = 0)
    {
        unset($userid);
        return time();
    }

    /**
     * 取url地址中的搜索关键词
     *
     * @param string $url
     *
     * @return mixed
     */
    public static function getUrlSearchKeyword($url)
    {
        if (!$url) {
            return '';
        }
        $domain = (string)parse_url($url, PHP_URL_HOST);
        if (!$domain) {
            return '';
        }
        if (ctype_digit(str_replace('.', '', $domain))) {
            return '';
        } // ex: 127.0.0.1
        //处理中文被截断的情况 //ex.: %E6%B7%98='淘' %E6B7转码结果为?
        $entities = array(
            '21',
            '2A',
            '27',
            '28',
            '29',
            '3B',
            '3A',
            '40',
            '26',
            '3D',
            '2B',
            '24',
            '2C',
            '2F',
            '3F',
            '25',
            '23',
            '5B',
            '5D',
            '20',
            '3C',
            '3E',
        ); //"%val" map to array('!', '*', "'", "(", ")", ";", ":", "@", "&", "=", "+", "$", ",", "/", "?", "%", "#", "[", "]", ' ', '<', '>');
        if (substr_count(substr($url, -3), '%') && preg_match_all('/(?:%[0-9A-F]{2})+/i', $url, $matches)) {
            foreach ($matches[0] as $match) {
                $valid_per_chars = $ch_per_char = array();
                $per_arr = explode('%', ltrim($match, '%'));
                $total_chinese_per = array_diff($per_arr, $entities);
                if (count($total_chinese_per) < 3) {
                    continue;
                } // ex.: http://
                foreach ($per_arr as $per) {
                    if (!in_array($per, $entities)) {
                        $ch_per_char[] = $per;
                    } else {
                        $valid_per_chars[] = $per;
                        $ch_per_char = array();
                        continue;
                    }
                    if (count($ch_per_char) == 3) {
                        $valid_per_chars = array_merge($valid_per_chars, $ch_per_char);
                        $ch_per_char = array();
                    }
                }
                $match_replace = '%' . implode('%', $valid_per_chars);
                if ($valid_per_chars && $match_replace != $match) {
                    //echo str_replace($match_replace, '', $match) . '_|_' . urldecode($match) . ';  ';
                    //$have_trun = true;
                    $url = str_replace($match, $match_replace, $url);
                }
            }
        }
        $query = parse_url($url, PHP_URL_QUERY);
        if (!$query) {
            return '';
        }
        mb_parse_str($query, $query_arr);
        if ($query_arr['word']) { //baidu,
            $query_str = $query_arr['word'];
        } elseif ($query_arr['w']) { //soso
            $query_str = $query_arr['w'];
        } elseif ($query_arr['wd']) { //baidu
            $query_str = $query_arr['wd'];
        } elseif ($query_arr['q']) { //google bing taobao
            $query_str = $query_arr['q'];
        } elseif ($query_arr['kw']) { //zhubajie
            $query_str = $query_arr['kw'];
        } elseif ($query_arr['bs']) { //baidu
            $query_str = $query_arr['bs'];
        } elseif ($query_arr['query']) { //sougou
            $query_str = $query_arr['query'];
        } elseif ($query_arr['key'] && !(ctype_alnum($query_arr['key']) && in_array(strlen($query_arr['key']),
                    array(32, 40, 64, 128)))
        ) { //md5, sha1, sha256, sha512  soso.com
            $query_str = $query_arr['key'];
        } elseif ($query_arr['p']) { //yahoo
            $query_str = $query_arr['p'];
        } else {
            return '';
        }
        if ($query_arr['ie'] && strstr(strtolower($query_arr['ie']), 'utf')) {
            $encoding = 'UTF-8';
        } elseif ($query_arr['ie'] && strstr(strtolower($query_arr['ie']), 'gbk')) {
            $encoding = 'GBK';
        } elseif ($query_arr['ie'] && strstr(strtolower($query_arr['ie']), 'gb2312')) {
            $encoding = 'GB2312';
        } else {
            $encoding = zbj_lib_BaseUtils::getStrEncoding($query_str);
        }
        if ($encoding != 'UTF-8') {
            $query_str = zbj_lib_BaseUtils::siconv($query_str, 'UTF-8', $encoding === false ? '' : $encoding);
        }
        $query_str = urldecode($query_str);
        $query_str = html_entity_decode(htmlentities(trim($query_str), ENT_IGNORE, 'UTF-8'), ENT_NOQUOTES,
            'UTF-8'); //del ex. <E7>
        $query_str = preg_replace('/%[A-F0-9]?$/', '', $query_str); //del ex. %A$
        $query_str = str_replace(array('?'), '', $query_str);
        $query_str = preg_replace('/\s+/', '||', trim($query_str));

        return $query_str;
    }

    /**
     * 获取当前ip
     *
     * @return string
     */
    public static function getIpNew()
    {
        $onlineip = $_SERVER['REMOTE_ADDR'];
        //蓝训IP列表
        $lx = "58.68.232.176183.136.239.23
221.228.229.2558.68.148.14858.68.231.164123.151.156.168222.73.234.149116.211.96.229218.106.116.101113.140.43.181221.11.84.149110.81.155.245175.43.122.213123.162.189.6961.54.29.69218.95.38.14958.17.85.21258.59.4.69124.133.16.6814.18.207.5122.13.64.101183.232.69.69221.228.229.2258.241.16.53221.228.229.69183.136.239.5121.52.241.229223.244.227.229103.28.207.229111.177.117.53115.238.228.21182.140.132.130221.204.234.16861.158.240.53124.95.137.37113.6.232.181116.114.20.229221.192.146.133202.100.92.6958.68.141.101117.34.22.165113.12.81.197222.178.179.197221.7.112.10158.68.148.14958.68.231.16358.68.231.165222.73.234.116222.73.234.146222.73.234.147222.73.234.148123.151.156.169222.73.234.157116.211.96.237218.106.116.109172.17.3.5172.17.4.5110.81.155.253175.43.122.221123.162.189.7761.54.29.77218.95.38.15658.17.85.21958.59.4.77124.133.16.7614.18.207.21122.13.64.117183.232.69.85172.17.15.8172.17.16.5172.17.2.5183.136.239.13121.52.241.237172.17.46.5172.17.47.5172.17.21.5115.238.228.29172.17.24.4172.17.29.561.158.240.61172.17.32.5113.6.232.189116.114.20.237172.17.40.5172.17.45.5172.17.48.5172.17.49.5172.17.51.5172.17.52.5172.17.53.558.68.148.15758.68.231.17158.68.231.172222.73.234.124222.73.234.154222.73.234.155222.73.234.15614.18.207.4514.18.207.1814.18.207.1914.18.207.20";
        if (strpos($lx, $onlineip) !== false) {
            $onlineip = getenv('HTTP_X_FORWARDED_FOR') ? getenv('HTTP_X_FORWARDED_FOR') : getenv('HTTP_CLIENT_IP');
        }
        preg_match("/[\d\.]{7,15}/", $onlineip, $onlineipmatches);

        return $onlineipmatches[0];
    }

    /**
     * 检查请求是否为机器 一般正在异步请求接口使用
     *
     * @param bool $isAjax
     *
     * @return bool
     */
    public static function checkRequestIsBot($isAjax = false)
    {
        if (self::isRefererMyDomain() === false || !$_COOKIE['_uq'] || !$_COOKIE['uniqid']/* or self::getIpNew() != self::getIp()*/) {
            return true;
        }
        if ($isAjax && self::isAjax() === false) {
            return true;
        }

        return false;
    }

    /**
     * 获取请求的状态 不获取请求内容
     *
     * @param string $url
     * @param int    $timeout
     *
     * @return mixed
     */
    public static function getHttpStatusCode($url, $timeout = 5)
    {
        $ch = curl_init($url);
        $timeout = abs(intval($timeout));
        curl_setopt_array($ch, array(
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_RETURNTRANSFER => true,
        ));
        curl_exec($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $status_code;
    }

    /**
     * 华泰保险接口开关
     *
     * @return bool
     */
    public static function huataiServcieStop()
    {
        $cache = new zbj_lib_cache('memcache');
        $begin = $cache->get('zhubajie.huatai.servicestop.begin');
        $end = $cache->get('zhubajie.huatai.servicestop.end');

        if (is_numeric($begin) && is_numeric($end) && time() >= $begin && time() <= $end) {
            if ($_COOKIE['_tu'] == 'jksdfhoawrl3ysdhf8a7df2jh') {
                return false;
            }
            if ($cache->get('zhubajie.huatai.servicestop.state') == 1) {
                return true;
            }

            return false;
        }

        return false;
    }

    /**
     * 根据user-agent判断是否为手机访问
     *
     * @param array $ignore 忽略的ua关键词,用于特定需求，如排除iPad
     *
     * @return bool
     */
    public static function isMobileVisit($ignore = array())
    {
        // 如果有HTTP_X_WAP_PROFILE则一定是移动设备
        if (isset($_SERVER['HTTP_X_WAP_PROFILE'])) {
            return true;
        }

        //如果via信息含有wap则一定是移动设备,部分服务商会屏蔽该信息
        if (isset($_SERVER['HTTP_VIA'])) {
            return stristr($_SERVER['HTTP_VIA'], "wap") ? true : false;
        }

        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            if (count($ignore) > 0) {
                if (preg_match("/(" . implode("|", $ignore) . ")/i", strtolower($_SERVER['HTTP_USER_AGENT']))) {
                    return false;
                }
            }
            //如果是android Pad
            if (preg_match("/(android)/i", strtolower($_SERVER['HTTP_USER_AGENT'])) && !preg_match("/(mobile)/i",
                    strtolower($_SERVER['HTTP_USER_AGENT']))
            ) {
                return false;
            }
            // 从HTTP_USER_AGENT中查找手机浏览器的关键字
            $clientkeywords = 'nokia,sony,ericsson,mot,samsung,htc,sgh,lg,sharp,sie-,philips,panasonic,alcatel,lenovo,iphone,ipod,blackberry,meizu,android,netfront,symbian,ucweb,windowsce,palm,operamini,operamobi,openwave,nexusone,cldc,midp,wap,mobile,baidu\sTranscoder';

            if (preg_match("/(" . implode('|', explode(',', $clientkeywords)) . ")/i",
                strtolower($_SERVER['HTTP_USER_AGENT']))) {
                return true;
            }
        }

        //协议法，因为有可能不准确，放到最后判断
        if (isset($_SERVER['HTTP_ACCEPT'])) {
            // 如果只支持wml并且不支持html那一定是移动设备
            // 如果支持wml和html但是wml在html之前则是移动设备
            if ((strpos($_SERVER['HTTP_ACCEPT'], 'vnd.wap.wml') !== false) && (strpos($_SERVER['HTTP_ACCEPT'],
                        'text/html') === false || (strpos($_SERVER['HTTP_ACCEPT'],
                            'vnd.wap.wml') < strpos($_SERVER['HTTP_ACCEPT'], 'text/html')))
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * 拿到模版目录的地址 by chengchao
     *
     * 如果定义了 smarty_tpls，那么直接读 smarty_tpls 否则会去框架平级的 smarty_tpl 目录找模版
     *
     * @param string $tpl
     *
     * @return string
     */
    private static function resolveTplPath($tpl)
    {

        if (defined('SMARTY_TPLS') && is_dir(SMARTY_DIR)) {
            $smarty_tpl_dir = SMARTY_TPLS . '/..';
        } else {
            if (defined('SMARTY_SLIGHTPHP_TPLS') && is_dir(SMARTY_SLIGHTPHP_TPLS)) {
                $smarty_tpl_dir = SMARTY_SLIGHTPHP_TPLS;
            } else {
                if (defined("ZBJCORE_DIR")) {
                    $smarty_tpl_dir = ZBJCORE_DIR . '/../../smarty_tpls';
                } else {
                    exit("No ZBJCORE_DIR constant defined");
                }
            }
        }

        return $smarty_tpl_dir . '/slightphp_tpl' . '/' . $tpl;
    }

    /**
     * 检查模板是否可读
     *
     * @param string $tpl
     *
     * @return bool
     */
    public static function checkTplReadable($tpl)
    {
        $tpl = self::resolveTplPath($tpl);

        return is_readable($tpl);
    }

    /**
     * 渲染模版
     *
     * @param string     $tpl smarty_tpl/slightphp_tpl为根目录
     * @param array      $params
     * @param string     $delimiter
     * @param bool|false $force_comiple
     *
     * @return string
     */
    public static function renderTpl($tpl, $params, $delimiter = '/', $force_comiple = false)
    {
        $SGui = new SGui();
        $tpl = self::resolveTplPath($tpl);

        return $SGui->render($tpl, $params, $delimiter, $force_comiple);
    }

    /**
     * 返回吉祥物征集大赛TASK_ID
     *
     * @return int
     * @author Wang Haojie <wanghaojie@zhubajie.com> at 2014-08-05
     */
    public static function getJXWZJDSTaskId()
    {
        return 4425030;
        //return 3425852;
    }

    /**
     * 获取用户头像地址 含域名的全地址
     *
     * @param int $user_id
     *
     * @return string
     */
    public static function getUserAvatarUrl($user_id)
    {
        $mc = new zbj_lib_cache("memcache");
        $key = self::getUserAvatarKey($user_id);
        $cached = $mc->get($key);
        if (!$cached) {
            return zbj_lib_Constant::FACE_URL . self::getUserAvatarPath($user_id);
        } else {
            return zbj_lib_Constant::FACE_URL . $cached;
        }
    }

    /**
     * 获取用户头像缓存key
     *
     * @param int $user_id
     *
     * @return string
     */
    public static function getUserAvatarKey($user_id)
    {
        return "slight.zbjcore.lib.base.useravatarkey.{$user_id}";
    }

    /**
     * 获取uid拼接头像路径
     *
     * @param int    $user_id
     * @param string $suffix 后缀名
     * @param string $prefix 前缀目录
     *
     * @return string
     */
    public static function getUserAvatarPath($user_id, $suffix = ".jpg", $prefix = "")
    {
        $uid = sprintf("%09d", abs(intval($user_id)));
        $dir1 = substr($uid, 0, 3);
        $dir2 = substr($uid, 3, 2);
        $dir3 = substr($uid, 5, 2);

        return $prefix . '/' . $dir1 . '/' . $dir2 . '/' . $dir3 . '/200x200_avatar_' . substr($uid, -2) . $suffix;
    }

    /**
     * 比较运行环境 self::compareRuntime('zhubajie.com','zhubajie.la');
     *
     * @return bool
     */
    public static function compareRuntime()
    {
        $runtime = func_get_args();
        foreach ($runtime as $env) {
            if ($env == zbj_lib_Constant::DOMAIN) {
                return true;
            }
        }

        return false;
    }

    /**
     * 兼容jsonp +echo +exit
     *
     * @param string $str
     * @param int    $type  0=html,1=json,2=iframe返回
     * @param int    $state 表示json返回状态
     * @param array  $other
     *
     * @return null exit echo;
     */
    public static function jsonp($str, $type = 1, $state = 1, $other = array())
    {
        $state = (int)$_GET['state'] ? (int)$_GET['state'] : $state;
        $callback = self::getStr(trim($_REQUEST['jsonpcallback']));
        $callback = self::getSafeJsonpName($callback);
        if ($_REQUEST['ifr'] == 2) {
            $type = 2;
        }
        $return = array('state' => $state, 'msg' => $str);
        if ($other && is_array($other)) {
            foreach ($other as $k => $v) {
                $return[$k] = $v;
            }
        }
        $json_return = json_encode($return);
        if ($type == 1) {
            if ($callback) {
                $str = "{$callback}({$json_return})";
            } else {
                $str = $json_return;
            }
        } elseif ($type == 2) {
            $domain = self::getStr($_GET['domain']);
            $domain = $domain ? $domain : zbj_lib_Constant::DOMAIN;
            $str = <<< EOT
<script>document.domain='{$domain}';window.parent.window.{$callback}({$json_return});</script>
EOT;
        }
        echo $str;
        exit;
    }

    /**
     * 新的异步返回接口 +echo +exit by chengchao
     * 兼容jsonp
     *
     * @param bool         $boolSuccess
     * @param string|array $mixData
     * @param int          $intType 0=html,1=json,2=iframe返回 默认为 1
     *
     * @return null exit|echo
     *
     * @see     http://1024.zbjwork.com/question/53
     *
     * @example 调用方式：
     * 成功的响应
     * zbj_lib_BaseUtils::jsonpRs( true, $dataObj );
     *
     * 错误的响应
     * zbj_lib_BaseUtils::jsonpRs( false, $dataObj );
     * 当错误时，$dataObj 里可以传 code 和 data
     * 没有传时为默认错误 code 和提示
     * 如果有 data 的 key ，那么 data 会被当成响应数据
     *
     * 比如 zbj_lib_BaseUtils::jsonpRs( false, '参数错误' );
     * 输出：{"success":false,"code":0,"data":"参数错误"}}
     *
     * 比如 zbj_lib_BaseUtils::jsonpRs( false, array('code' => -1001, 'msg' => 'abc') );
     * 输出：{"success":false,"code":-1001,"data":{"msg":"abc"}}
     *
     * 比如 zbj_lib_BaseUtils::jsonpRs( false, array('code' => -1001, 'data' => 'abc') );
     * 输出：{"success":false,"code":-1001,"data":"abc"}
     *
     * {"success":false,"code":-1001,"data":"abc"}
     *
     */
    public static function jsonpRs($boolSuccess, $mixData, $intType = 1)
    {

        $commonErrorTip = '操作失败';
        $commonErrorCode = 0;

        $errorCode = 0;

        if ($_REQUEST['ifr'] == 2) {
            $intType = 2;
        }

        $str = $mixData;

        $return = array('success' => $boolSuccess);

        if ($boolSuccess && $mixData) {
            $return['data'] = $mixData;
        }

        if (!$boolSuccess) {
            // check code and data status
            if (!$mixData) {
                $mixData = array(
                    'code' => $commonErrorCode,
                    'data' => $commonErrorTip,
                );
            }
            if (!is_array($mixData)) {
                $mixData = array(
                    'code' => $commonErrorCode,
                    'data' => $mixData,
                );
            }
            if (!array_key_exists('code', $mixData)) {
                $errorCode = $commonErrorCode;
            } else {
                $errorCode = $mixData['code'];
                unset($mixData['code']);
            }

            if (!array_key_exists('data', $mixData)) {
                $mixData['data'] = $mixData;
            }
        }

        if (!$boolSuccess) {
            // 错误编码 以及 错误信息
            $return['code'] = $errorCode;
            $return['data'] = $mixData['data'];
        }

        $callback = self::getStr(trim($_REQUEST['jsonpcallback']));

        $callback = self::getSafeJsonpName($callback);

        $json_return = json_encode($return);
        if ($intType == 1) {
            if ($callback) {
                $str = "{$callback}({$json_return})";
            } else {
                $str = $json_return;
            }
        } elseif ($intType == 2) {
            $domain = zbj_lib_Constant::DOMAIN;
            $str = <<< EOT
<script>document.domain='{$domain}';window.parent.window.{$callback}({$json_return});</script>
EOT;
        }
        echo $str;
        exit;
    }

    public static function getSafeJsonpName($callback)
    {
        $callback = strval($callback);
        $callback = self::getStr(trim($callback));
        if (empty($callback)) {
            return $callback;
        }

        //return str_replace(array(";", ' ', "\t", "\r\n", "\n", '(', ')', '{', '}'), '', $callback);

        //只匹配[A-Za-z0-9_]
        if(preg_match('/^[A-Za-z0-9_]+$/i',$callback)){
            return $callback;
        }
        return '';
    }

    /**
     * 获取远端文件暂存到本地 /tmp目录下，注意使用完以后删除临时文件
     *
     * @param string $url 远端url地址
     * @param string $ext 存储时临时文件的后缀
     *
     * @return string
     */
    private static function getRemoteFile($url, $ext)
    {
        $tmp_file = '/tmp/' . '-' . uniqid() . time() . '.' . $ext;
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        $imageData = curl_exec($curl);
        curl_close($curl);
        $tp = fopen($tmp_file, 'a');
        fwrite($tp, $imageData);
        fclose($tp);
        unset($imageData);

        return $tmp_file;
    }

    /**
     * 任务金额区间判断
     *
     * @param float $amount
     * @param int   $mode
     * @param int   $category_id
     * @param int   $createtime
     * @param int   $state
     *
     * @return array
     */
    public static function taskAmount($amount, $mode, $category_id = 0, $createtime = 0, $state = 0)
    {
        $isnewmode = null;
        if ($mode == 13 && in_array($category_id, array(361, 1000203)) && $createtime > 1420769700) {
            $isnewmode = 1;
            if ($state > 0 && $state < 3) {

                if ($amount == 0) {
                    $amountstr = '待商议';
                } elseif (1000 <= $amount && $amount < 5000) {
                    $amountstr = '1000-5000';
                } elseif (5000 <= $amount && $amount < 10000) {
                    $amountstr = '5000-10000';
                } elseif (10000 <= $amount && $amount < 50000) {
                    $amountstr = '10000-50000';
                } elseif (50000 <= $amount && $amount < 100000) {
                    $amountstr = '50000-100000';
                } /*elseif (100000<=$amount){
                    $amountstr = '>100000';
                }*/ else {
                    $amountstr = $amount;
                }
            } else {
                $amount = $amount > 0 ? $amount : 0;
                $amount = sprintf("%0.2f", round($amount, 2));
                $amountstr = $amount;
            }
        } else {
            $amount = $amount > 0 ? $amount : 0;
            $amount = sprintf("%0.2f", round($amount, 2));
            $amountstr = $amount;
        }

        return array('amount' => $amountstr, 'isnewmode' => $isnewmode);
    }

    /**
     * 获取搜索引擎蜘蛛来源名称
     *
     * @return string|false
     */
    public static function getSearchEngineRobot()
    {
        $spider = strtolower($_SERVER['HTTP_USER_AGENT']);
        if (empty($spider)) {
            return false;
        }

        $searchEngineBot = array(
            'googlebot'            => 'google',
            'mediapartners-google' => 'google',
            'baiduspider'          => 'baidu',
            'msnbot'               => 'msn',
            'yodaobot'             => 'yodao',
            'youdaobot'            => 'yodao',
            'yahoo! slurp'         => 'yahoo',
            'yahoo! slurp china'   => 'yahoo',
            'iaskspider'           => 'iask',
            'sogou web spider'     => 'sogou',
            'sogou push spider'    => 'sogou',
            'sosospider'           => 'soso',
            'spider'               => 'other',
            'crawler'              => 'other',
        );

        foreach ($searchEngineBot as $key => $value) {
            if (strpos($spider, $key) !== false) {
                return $value;
            }
        }

        return false;
    }

    /**
     * base64加密变种
     *
     * 建议所有主键参数都使用此方法进行简单加密，防止数据被遍历 重写的base64_encode 用于对称加密
     *
     * @param string $str
     *
     * @return string
     */
    public static function base64_encode($str)
    {
        $str_arr = str_split($str);//分成单个字符
        $mod = count($str_arr) % 3;//不够3个
        $bmod = $bit = $enstr = null; //fix undefined
        if ($mod > 0) {
            $bmod = 3 - $mod;
        } //计算需要补多少才能够3个
        for ($i = 0; $i < $bmod; $i++) {//不够3个补\0
            $str_arr[] = "\0";
        }
        //字符串转换为二进制
        foreach ($str_arr as $v) {
            $bit .= str_pad(decbin(ord($v)), 8, '0', STR_PAD_LEFT);
        }
        $len = ceil(strlen($bit) / 6);
        $base64_config = self::getBase64Config();
        //把二进制按照六位进行转换为base64索引
        for ($i = 0; $i < $len - $bmod; $i++) {
            $enstr .= $base64_config[bindec(str_pad(substr($bit, $i * 6, 6), 8, 0, STR_PAD_LEFT))];
        }
        //补=号
        for ($buf = 1; $buf <= $bmod; $buf++) {
            $enstr .= "=";
        }

        return $enstr;
    }

    /**
     * base64解密变种
     *
     * 重写的base64_decode 用于对称加密
     *
     * @param string $str
     *
     * @return string
     */
    public static function base64_decode($str)
    {
        $buf = substr_count($str, '=');//统计=个数
        $str_arr = str_split($str);//分成单个字符
        $base64_config = self::getBase64Config();
        //转换为二进制字符串
        $bit = $destr = null; //fix undefined
        foreach ($str_arr as $v) {
            $index = array_search($v, $base64_config);
            $index = $index ? $index : "\0";
            $bit .= str_pad(decbin($index), 6, 0, STR_PAD_LEFT);
        }
        $len = ceil(strlen($bit) / 8);
        //二进制转换为ASCII，在转换为字符串
        for ($i = 0; $i < $len - $buf; $i++) {
            $destr .= chr(bindec(str_pad(substr($bit, $i * 8, 8), 8, 0, STR_PAD_LEFT)));
        }

        return $destr;
    }

    /**
     * 混淆的base64索引
     *
     * @return array
     */
    public static function getBase64Config()
    {
        return array(
            'x',
            'T',
            'E',
            'Z',
            'O',
            'F',
            'm',
            'S',
            'Q',
            'r',
            'X',
            'N',
            'L',
            's',
            'p',
            'H',
            '9',
            't',
            'l',
            'y',
            'P',
            'J',
            'C',
            'c',
            'U',
            '3',
            'u',
            'a',
            'A',
            'd',
            'D',
            'f',
            'I',
            'k',
            '5',
            'w',
            'B',
            'g',
            'h',
            'z',
            'V',
            'R',
            'e',
            '2',
            '1',
            'Y',
            'j',
            '4',
            'b',
            'o',
            '8',
            '6',
            'i',
            'W',
            '0',
            'M',
            'n',
            '7',
            'K',
            'G',
            'q',
            'v',
            '+',
            '/',
        );
    }

    /**
     * 发送不缓存头
     *
     * @return bool
     */
    public static function sendNoCacheHeader()
    {
        if (headers_sent()) {
            return false;
        }
        $expire_time = 1;
        header("Pragma: no-cache");
        header('Cache-Control: no-store, no-cache, must-revalidate'); //HTTP/1.1
        header('Cache-Control: post-check=0, pre-check=0', false);
        header('Expires: ' . gmdate('D, d M Y H:i:s', $expire_time) . ' GMT'); // Date in the past
        return true;
    }

    /**
     * 发送缓存头
     *
     * @param int        $ttl
     * @param bool|false $check_ETag
     *
     * @exit
     * @return bool|null
     */
    public static function sendCacheHeader($ttl, $check_ETag = false)
    {
        if (headers_sent()) {
            return false;
        }
        $ttl = intval($ttl);
        if ($ttl <= 0) {
            return false;
        }
        $nowtime = time();
        $etag_time = intval($nowtime / $ttl);
        $last_modified_time = $etag_time * $ttl;
        $expire_time = $nowtime + $ttl;
        $browser_cache_time = strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']);
        header("Pragma: public");
        header("Cache-Control: public"); //HTTP/1.1
        header("Cache-Control: must-revalidate, max-age={$ttl}", false); //HTTP/1.1
        if ($browser_cache_time !== false && $browser_cache_time >= $last_modified_time) {
            zbj_lib_BaseUtils::httpStatus(304);
            exit;
        }

        if ($check_ETag) {
            $current_url = self::getCurrentUrl();
            $etag_new = md5($current_url . $etag_time);
            $etag_new = "${etag_new}:${etag_time}";
            $etag_browser = str_ireplace(array('W/', '"'), '', $_SERVER['HTTP_IF_NONE_MATCH']);
            if ($etag_browser) {
                if ($etag_browser === $etag_new) {
                    zbj_lib_BaseUtils::httpStatus(304);
                    exit;
                }
            }
            header("ETag: \"${etag_new}\"");
        }

        header('Expires: ' . gmdate('D, d M Y H:i:s', $expire_time) . ' GMT'); // Date in the past
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $last_modified_time) . ' GMT'); // Date in the past
        return true;
    }

    /**
     * 检查当前跑代码的主机是否是windows
     *
     * @return bool
     */
    public static function isHostWindows()
    {
        return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    }

    /**
     * Returns the values from a single column of the input array, identified by
     * the $columnKey.
     *
     * Optionally, you may provide an $indexKey to index the values in the returned
     * array by the values from the $indexKey column in the input array.
     *
     * @param array $input     A multi-dimensional array (record set) from which to pull
     *                         a column of values.
     * @param mixed $columnKey The column of values to return. This value may be the
     *                         integer key of the column you wish to retrieve, or it
     *                         may be the string key name for an associative array.
     * @param mixed $indexKey  (Optional.) The column to use as the index/keys for
     *                         the returned array. This value may be the integer key
     *                         of the column, or it may be the string key name.
     *
     * @return array|bool
     */
    public static function array_column($input = null, $columnKey = null, $indexKey = null)
    {
        // Using func_get_args() in order to check for proper number of
        // parameters and trigger errors exactly as the built-in array_column()
        // does in PHP 5.5.
        $argc = func_num_args();
        $params = func_get_args();
        if ($argc < 2) {
            trigger_error("array_column() expects at least 2 parameters, {$argc} given", E_USER_WARNING);

            return null;
        }
        if (!is_array($params[0])) {
            trigger_error(
                'array_column() expects parameter 1 to be array, ' . gettype($params[0]) . ' given',
                E_USER_WARNING
            );

            return null;
        }
        if (!is_int($params[1])
            && !is_float($params[1])
            && !is_string($params[1])
            && $params[1] !== null
            && !(is_object($params[1]) && method_exists($params[1], '__toString'))
        ) {
            trigger_error('array_column(): The column key should be either a string or an integer', E_USER_WARNING);

            return false;
        }
        if (isset($params[2])
            && !is_int($params[2])
            && !is_float($params[2])
            && !is_string($params[2])
            && !(is_object($params[2]) && method_exists($params[2], '__toString'))
        ) {
            trigger_error('array_column(): The index key should be either a string or an integer', E_USER_WARNING);

            return false;
        }
        $paramsInput = $params[0];
        $paramsColumnKey = ($params[1] !== null) ? (string)$params[1] : null;
        $paramsIndexKey = null;
        if (isset($params[2])) {
            if (is_float($params[2]) || is_int($params[2])) {
                $paramsIndexKey = (int)$params[2];
            } else {
                $paramsIndexKey = (string)$params[2];
            }
        }
        $resultArray = array();
        foreach ($paramsInput as $row) {
            $key = $value = null;
            $keySet = $valueSet = false;
            if ($paramsIndexKey !== null && array_key_exists($paramsIndexKey, $row)) {
                $keySet = true;
                $key = (string)$row[$paramsIndexKey];
            }
            if ($paramsColumnKey === null) {
                $valueSet = true;
                $value = $row;
            } elseif (is_array($row) && array_key_exists($paramsColumnKey, $row)) {
                $valueSet = true;
                $value = $row[$paramsColumnKey];
            }
            if ($valueSet) {
                if ($keySet) {
                    $resultArray[$key] = $value;
                } else {
                    $resultArray[] = $value;
                }
            }
        }

        return $resultArray;
    }

    /**
     * 将一个对象转化为数组
     *
     * @param $obj
     *
     * @return mixed
     */
    public static function object_to_array($obj)
    {
        $_arr = is_object($obj) ? get_object_vars($obj) : $obj;
        $arr = array();
        foreach ($_arr as $key => $val) {
            $val = (is_array($val) || is_object($val)) ? self::object_to_array($val) : $val;
            $arr[$key] = $val;
        }
        return $arr;
    }

    /**
     * 生成SOA请求参数对象
     *
     * @param object $obj
     * @param array  $data
     * @param string $relation
     *
     * @return mixed
     */
    public static function getParamDTO($obj, $data, $relation = '')
    {
        foreach ($data as $key => $val) {
            if ($relation) {
                $key = self::getSoaKey($relation, $key);
            }
            if (property_exists($obj, $key)) {
                if ($val !== '' && $val !== null) {
                    if ($key == "dateymd") {
                        $val = date('Y-m-d H:i:s', strtotime($val));
                    }
                    $obj->$key = $val;
                }
            }
        }
        return $obj;
    }

    /**
     * 把soa对象转换成数组
     *
     * @param        $obj
     * @param string $relation
     *
     * @return array
     */
    public static function objectToArray($obj, $relation = '')
    {
        $result = array();
        $ret = (array)$obj;
        foreach ($ret as $key => $val) {
            if ($relation != '') {
                $key = self::getLocalKey($relation, $key);
            }
            if (gettype($val) == "object" || gettype($val) == "array") {
                $result[$key] = self::objectToArray($val, $relation);
            } else {
                $result[$key] = $val;
            }
        }
        return $result;
    }

    /**
     * @param $relation
     * @param $key
     *
     * @return mixed
     */
    public static function getLocalKey($relation, $key)
    {
        $newKey = $key;
        $className = "zbj_relation_" . $relation;
        if (class_exists($className)) {
            $obj = new $className();
            if (method_exists($obj, "convertToLocal")) {
                $newKey = $obj->convertToLocal($key);
            }
        }
        return $newKey;
    }

    /**
     * @param $relation
     * @param $key
     *
     * @return mixed
     */
    public static function getSoaKey($relation, $key)
    {
        $newKey = $key;
        $className = "zbj_relation_" . $relation;
        if (class_exists($className)) {
            $obj = new $className();
            if (method_exists($obj, "convertToSoa")) {
                $newKey = $obj->convertToSoa($key);
            }
        }
        return $newKey;
    }

    /**
     * 判断当前域名是否为天蓬域名
     * 因为存在zbj_lib_Constant加载重写,所以这里不能使用常量
     */
    public static function isTianPengSite()
    {
        if (strpos(strtolower($_SERVER['HTTP_HOST']), zbj_conf_Constant::TP_COOKIE_DOMAIN) !== false) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 加载天蓬网一站式登陆方案
     *
     * @param string $backurl 指定天蓬登陆成功以后回跳地址,不填写时默认是当前页面
     */
    public static function loadTianpengSSOLogin($backurl = '')
    {
        if (empty($backurl)) {
            $backurl = self::getCurrentUrl();
        }
        $backurl = rawurlencode($backurl);
        $url = zbj_lib_Constant::TP_ZBJ_URL . '/ssoapi/jump?from=' . $backurl;
        header("Location: {$url}");
        exit();
    }

    /**
     * SOA返回数据公用处理方法，注：此方法外层必须try catch异常
     *
     * @param object $obj
     * @param string $relation
     * @param bool   $isArr
     *
     * @return array|mixed
     * @throws Exception
     */
    public static function getSoaResult($obj, $relation = '', $isArr = false)
    {
        //$ret = array();
        if ($obj->success == true) {
            if (isset($obj->data)) {
                if (is_object($obj->data) || is_array($obj->data)) {
                    $ret = self::objectToArray($obj->data, $relation);
                } else {
                    $ret = $obj->data;
                }
            } else {
                $ret = $isArr ? array() : $obj->success;
            }
        } else {
            throw new Exception($obj->description, intval($obj->code));
        }
        return $ret;
    }

    /**
     * 将soa接口返回的数据 key 改为以前的调用key(递归调用) ORM
     *
     * @param array $soaDto
     *
     * @return array
     */
    public static function renameSOADTO($soaDto)
    {
        $s2oKey = array(
            'virtual_id'          => 'categoryId',
            'parent_id'           => 'parentId',
            'virtual1id'          => 'level1id',
            'virtual2id'          => 'level2id',
            'virtual_name'        => 'categoryName',
            'is_show_trade'       => 'isShow',
            'is_show_user'        => '',
            'is_show_service'     => '',
            'level'               => 'level',
            'sort'                => 'sort',
            'show_index'          => '',
            'show_channel'        => '',
            'ico'                 => '',
            'paid_listing_fee'    => '',
            'task_top_tips'       => 'taskTopTips',
            'task_top_num'        => 'taskTopNum',
            'recommend_fws_fee1'  => '',
            'recommend_fws_fee2'  => '',
            'fws_top_fee'         => '',
            'fws_top_fee2'        => '',
            'fws_vas_fee'         => '',
            'fw_top_fee'          => '',
            'fw_top_fee2'         => '',
            'fw_vas_fee'          => '',
            'title_trade'         => '',
            'keywords_trade'      => '',
            'description_trade'   => '',
            'title_user'          => '',
            'keywords_user'       => '',
            'description_user'    => '',
            'title_service'       => '',
            'keywords_service'    => '',
            'description_service' => '',
            'redirect_url'        => 'redirectUrl',
            'option'              => '',
            'is_red'              => 'isRed',
            'pub_title'           => 'pubTitle',
            'pub_content'         => 'pubContent',
            'pub_amount'          => 'pubAmount',
            'information'         => 'information',
            'allow_pub_mode'      => 'allowPubMode',
            'rcmd_pub_mode'       => 'rcmdPubMode',
            'intro_tpl'           => 'introTpl',
            'list'                => 'children',
        );
        $reverse = array_flip($s2oKey);
        $result = array();
        foreach ($soaDto as $k => $v) {
            if (is_array($v)) {
                $v = self::renameSOADTO($v);
            }
            if ($k && in_array($k, $s2oKey)) {
                $result[$reverse[$k]] = $v;
            } else {
                $result[$k] = $v;
            }
        }
        return $result;
    }

    /**
     * 用消息机制发送 推广数据的统计信息 - copy from SlightPHP/zbjcore/service/task/base.class.php (SpreadTask)
     *
     * @param int    $task_id
     * @param int    $user_id
     * @param string $param "referer=1111&first_page=2222&pmcode=3333&uncode=4444&uncode_extid=5555&adunion_lead_id=6666&stt=777"
     *
     * @author luoqingbo
     * @return boolean
     */
    public static function spreadTask($task_id, $user_id, $param)
    {
        if (!$param) {
            $param = "referer=&first_page=&pmcode=&uncode=&uncode_extid=&adunion_lead_id=&stt=&way_type=0";
        }
        $tarParam = array();
        $paramArr = explode("&", $param);
        foreach ($paramArr as $v) {
            $tmp = explode("=", $v);
            $tarParam[$tmp[0]] = $tmp[1];
        }

        try {
            $stt_data = new stdClass();
            $stt_data->task_id = $task_id;
            $stt_data->user_id = $user_id;
            $stt_data->way_type = $tarParam['waytype']; //来源，枚举
            $stt_data->pub_page = $tarParam['pub_page'];
            $stt_data->way_2nd = $tarParam['way_2nd'];//二级来源
            $stt_data->way_3rd = $tarParam['way_3rd'];//三级来源

            $stt_data->referer = $tarParam['referer'];
            $stt_data->first_page = $tarParam['first_page'];
            $stt_data->pmcode = $tarParam['pmcode'];
            $stt_data->uncode = $tarParam['uncode'];
            $stt_data->uncode_extid = $tarParam['uncode_extid'];
            $stt_data->adunion_lead_id = $tarParam['adunion_lead_id'];
            $stt_data->stt = $tarParam['stt'];

            SMessageQueue::init();
            $message = new \MessageQueue\Message();
            $message->exchangeName = 'union.task.publish';//上线前要改和线上一致
            $message->routingKey = 'union.task.publish';//上线前要改和线上一致
            $message->content = json_encode($stt_data);
            \MessageQueue\Publisher::publish($message);

        } catch (Exception $e) {
            return false;
        }
        return true;
    }

    /**
     * cms推荐位图片地址转换
     *
     * @param string $str
     *
     * @return string
     */
    public static function getCmsImg($str)
    {
        if (empty($str)) {
            return '';
        } else {
            if (strpos($str, "http://") !== 0) {
                $str = zbj_lib_Constant::ZBJ_UPLOAD_FILE_URL . "/resource/redirect?key=" . $str;
            }
            return $str;
        }
    }

    /**
     * cms推荐位URL统一添加参数cmsspecialsymbol=0做标识来做流量统计
     *
     * @param  string $url_str
     *
     * @return string
     */

    public static function addCmsSymbol($url_str)
    {
        while (filter_var($url_str, FILTER_VALIDATE_URL)) {
            $addQuery = 'cmsspecialsymbol=' . base64_encode(time());
            $urlArr = parse_url($url_str);
            if (isset($urlArr['query'])) {
                $endStr = $url_str . '&' . $addQuery;
                return $endStr;
            }
            $endStr = $url_str . '?' . $addQuery;
            return $endStr;
        }
        return '';
    }

    /**
     * 获取字符串长度, 中文按1计算，2个英文按1计算，不足2个时不进1
     *
     * @param string $str    待获取的字符串
     * @param string $encode 编码
     * @deprecated  请改用 zbj_lib_BaseUtils::stringLength()
     *
     * @return int
     */
    public static function str_lenth($str, $encode = 'utf8')
    {
        if (!is_string($str)) {
            return false;
        }
        if (!is_string($encode)) {
            $encode = 'utf8';
        }
        return intval((strlen($str) + mb_strlen($str, $encode)) / 4);
    }

    /**
     * 是否是开发环境
     * @deprecated 请改用 zbj_lib_BaseUtils::isDevEnv()
     * @return boolean
     */
    public static function isdev()
    {
        if (zbj_lib_Constant::RUNTIME_ENVIRONMENT != 'product') {
            return true;
        }
        return false;
    }

    /**
     * 是否是开发环境
     * @return bool
     */
    public static function isDevEnv()
    {
        /** @noinspection PhpDeprecationInspection */
        return self::isdev();
    }

    /**
     * 获取字符串长度, 中文按1计算，2个英文按1计算，不足2个时不进1
     * @param string $string
     * @param string $encode 编码
     *
     * @return int
     */
    public static function stringLength($string, $encode='utf8')
    {
        /** @noinspection PhpDeprecationInspection */
        return self::str_lenth($string, $encode);
    }

    public static function render_utopia_common_script()
    {
        $cache = new zbj_lib_Cache("memcache");

        $cacheTime = 5 * 60;

        if(zbj_lib_BaseUtils::isTianPengSite()){
            $cacheName = 'utopia_tp_common_script';
        }else{
            $cacheName = 'utopia_zbj_common_script';
        }
        $rs = $cache->get($cacheName);
        if (!$rs) {
            $url = zbj_lib_BaseUtils::getUtopiaCommonHost()  . '/public/utopiaCommonForPhp';
            $rs = json_decode(self::file_get_contents_safe($url), true);
            if ($rs['success']) {
                $rs['data']['html'] = str_replace('${staticLibURI}', zbj_lib_Constant::HTTPS_STATIC_URL, $rs['data']['html']);
                $cache->set($cacheName, $rs, $cacheTime);
            }
        }
        return $rs['data']['html'];
    }

    public static function get_utopia_common_service($serviceType, $args)
    {
        // 增加本地化的 cookie
        if ($_COOKIE['localize_city_id']) {
            $args['localize_city_id'] = $_COOKIE['localize_city_id'];
        }

        $queryString = http_build_query($args);
        $cache = new zbj_lib_Cache("memcache");

        $cacheTime = 5 * 60;
        if(zbj_lib_BaseUtils::isTianPengSite()){
            $cacheName = 'utopia_tp_service' . $serviceType . $queryString;
        }else{
            $cacheName = 'utopia_zbj_service' . $serviceType . $queryString;
        }
        $rs = $cache->get($cacheName);

        if (!$rs) {
            // zbj公共头尾走post请求
            if(zbj_lib_BaseUtils::isTianPengSite()){
                $url = zbj_lib_BaseUtils::getUtopiaCommonHost('utopiacs') . '/service/tp-'.$serviceType.'?' . $queryString;
                $rs = json_decode(self::file_get_contents_safe($url), true);
            }else{
                $url = zbj_lib_BaseUtils::getUtopiaCommonHost('utopiacs') . '/service/'.$serviceType;
                $rs = json_decode(self::file_get_contents_safe($url,$queryString,'POST'), true);
            }
            if ($rs['success']) {
                $cache->set($cacheName, $rs, $cacheTime);
            }
        }
        return $rs;
    }



    public static function render_utopia_component_bootstrap()
    {
        return '<script>if (window.__global_utopia_script__) {for(var i=0; i<window.__global_utopia_script__.length;i++){' .
            'for(var j=0;j<window.__global_utopia_script__[i].length;j++){seajs.use(window.__global_utopia_script__[i][j])}}}</script>';
    }

    private static function getUtopiaCommonHost($subDomain = 'cmsapi')
    {
        if(zbj_lib_BaseUtils::isTianPengSite()){
            return str_replace('www', $subDomain, zbj_lib_Constant::TP_WWW_URL);
        }else{
            return str_replace('www', $subDomain, zbj_lib_Constant::MAIN_URL);
        }
    }
}
