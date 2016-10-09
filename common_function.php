<?php
if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * 后台常见的方法
 * author ideal
 */

/**
 *    作用：array转xml
 * @param        $data  mixed
 * @param string $root  元素根标签名称
 * @return string
 */
function arrayToXml($data, $root = 'xml') {
    $xml = "<$root>";
    foreach ($data as $key => $val) {
        if (is_numeric($val)) {
            $xml .= "<$key>$val</$key>";
        } elseif (is_array($val)) {
            if (is_numeric($key)) {
                $key = 'num_' . $key;
            }
            $xml .= arrayToXml($val, $key);
        } else {
            if (is_numeric($key)) {
                $key = 'num_' . $key;
            }
            $xml .= "<$key><![CDATA[$val]]></$key>";
        }
    }
    $xml .= "</$root>";
    return $xml;
}

/**
 *    作用：将xml转为array
 */
function xmlToArray($xml) {
    //将XML转为array
    $array_data = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
    return $array_data;
}
//获取目录下的所有文件
if (!function_exists('get_file')) {
    function get_file($dir) {
        $result_arr = array();

        if (!is_dir($dir)) {
            return $result_arr;
        }

        //目录下的文件：
        $dh = opendir($dir);
        while ($file = readdir($dh)) {
            if ($file != "." && $file != "..") {
                $fullpath = $dir . "/" . $file;
                if (is_file($fullpath)) {
                    $result_arr[] = $file;
                }
            }
        }
        return $result_arr;
    }
}

//删除文件夹及其文件夹下所有文件
if (!function_exists('deldir')) {
    function deldir($dir) {
        //先删除目录下的文件：
        $dh = opendir($dir);
        while ($file = readdir($dh)) {
            if ($file != "." && $file != "..") {
                $fullpath = $dir . "/" . $file;
                if (!is_dir($fullpath)) {
                    @unlink($fullpath);
                } else {
                    deldir($fullpath);
                }
            }
        }
        closedir($dh);
        //删除当前文件夹：
        if (rmdir($dir)) {
            return true;
        } else {
            return false;
        }
    }

}

if (!function_exists('anti_brush_sess')) {
    function anti_brush_sess() {
        @session_start();

        $curr_time = time();
        $allowTime = 60;//防刷新时间
        $allowNum = 3;//防刷新次数

        $session_expre_time = time() + $allowTime;//有效期时间点

        $session_num = isset($_SESSION['num']) ? $_SESSION['num'] : 0;
        $session_expre_time = isset($_SESSION['expre_time']) ? $_SESSION['expre_time'] : $session_expre_time;

        //更新次数
        $session_num += 1;
        $_SESSION['num'] = $session_num;
        $_SESSION['expre_time'] = $session_expre_time;

        if ($curr_time < $session_expre_time) {
            if ($session_num > $allowNum) {
                return false;
            }
        }
        //
        $_SESSION['num'] = 0;
        $_SESSION['expre_time'] = time() + $allowTime;

        return true;
    }
}

/**
 * 把数组所有元素，按照“参数=参数值”的模式用“&”字符拼接成字符串
 * @param $para 需要拼接的数组
 * @return 拼接完成以后的字符串
 */
function createQuerystring($para) {
    $arg = "";
    while (list ($key, $val) = each($para)) {
        $arg .= $key . "=" . $val . "&";
    }
    //去掉最后一个&字符
    $arg = substr($arg, 0, count($arg) - 2);

    //如果存在转义字符，那么去掉转义
    if (get_magic_quotes_gpc()) {
        $arg = stripslashes($arg);
    }

    return $arg;
}

//加载语言类型  简体 繁体
if (!function_exists('loading_language')) {
    function loading_language() {
        $CI = &get_instance();

        $langrage_type = getParam($CI->input->get_post("language_type"), 'string', '1');

        if ($langrage_type == '3') {
            $CI->lang->load("en_us");
        } elseif ($langrage_type == '2') {
            //加载繁体
            $CI->lang->load("zh_tw");
        } else {
            $CI->lang->load("zh_cn");
        }
        $CI->load->helper('language');

        return $langrage_type;
    }

}


//IP查找
if (!function_exists('ip_city_ext')) {
    function ip_city_ext($num) {
        $info = ipnum_info($num);
        if (empty($info)) {
            return "";
        }
        return strtoupper($info['area'] . ',' . $info['city']);
    }
}

/**
 * 记录日志文件
 */
if (!function_exists("file_log")) {
    function file_log($logFile, $data) {
        error_log("[" . date("Y-m-d H:i:s") . "]$data\r\n", 3, $logFile);
    }
}

/**
 * 验证邮箱
 */
if (!function_exists("validEmail")) {
    function validEmail($email) {
        if (strlen($email) > 50 || strlen($email) < 4) return false;
        return @eregi("^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$", $email);
    }
}

/**
 * IsMobile函数:检测参数的值是否为正确的中国手机号码格式
 * 返回值:是正确的手机号码返回手机号码,不是返回false
 */
if (!function_exists("validPhone")) {
    function validPhone($phone) {
        if (strlen($phone) != 11) return false;
        return @eregi("^(13[0-9]{1}|15[0-9]{1}|18[0-9]{1}|14[0-9]{1}|17[0-9]{1})[0-9]{8}$", $phone);
    }
}

/**
 * validNum函数:检测参数是否是纯数字
 * @param    string $string 被检测字符串
 * @return    boolean TRUE/FALSE
 */
if (!function_exists("validNum")) {
    function validNum($string) {
        return preg_match('/^[0-9]*$/', $string) ? TRUE : FALSE;
    }
}

/**
 * validStrIsStrAndNum验证字符串是否由4-16个字母和数字组成(不区分大小写)
 * @param    string $string 被检测字符串
 * @return    bool    TRUE/FALSE
 */
if (!function_exists('validStrIsStrAndNum')) {
    function validStrIsStrAndNum($string) {
        return preg_match('/^[a-z\d]{4,16}$/i', $string) ? TRUE : FALSE;
    }
}

/**
 * IsQQ函数:检测参数的值是否符合QQ号码的格式
 * 返回值:是正确的QQ号码返回QQ号码,不是返回false
 */
if (!function_exists("IsQQ")) {
    function IsQQ($Argv) {
        $RegExp = '/^[1-9][0-9]{5,16}$/';
        return preg_match($RegExp, $Argv) ? $Argv : false;
    }
}
/**
 * 验证是否为url
 * @param string  $str         url地址
 * @param boolean $exp_results 是否返回结果
 */
if (!function_exists("IsUrl")) {
    function IsUrl($str, $exp_results = false) {
        $RegExp = '/^(?:http[s]?\:\/\/)?[\w\.]+?\.(?:com|cn|mobi|net|org|so|co|gov|tel|tv|biz|cc|hk|name|info|asia|me|in).+$/';
        if (!preg_match($RegExp, $str, $m)) {
            return false;
        }
        if ($exp_results == true) {
            return $m;
        }
        return true;
    }
}

/**
 * 过淲敏感词汇
 * @return true,存在， false,不存在
 */
if (!function_exists("isFilterWords")) {
    function isFilterWords($word) {
        $filterwords = __ROOT__ . '/assets/filedata/filterwords.txt';
        foreach ($filterwords as $k => $v) {
            $filterwords[$k] = trim($v);
        }
        $str = implode('|', $filterwords);
        if (preg_match("/$str/", $word, $match) == 1) {//\n是匹配过滤字符后面的回车字符的
            return true;
        } else {
            return false;
        }
    }
}

/**
 * 替换敏感词汇
 * @param unknown_type $word
 * @return string
 */
if (!function_exists("filterWords")) {
    function filterWords($word) {
        $filterwords = __ROOT__ . '/assets/filedata/filterwords.txt';
        foreach ($filterwords as $k => $v) {
            $filterwords[$k] = trim($v);
        }
        $str = @implode('|', $filterwords);
        $content = preg_replace("/$str/i", '***', $word);
        return $content;
    }
}

/**
 * 获取客户端的IP地址
 * if( ! function_exists("get_client_ip")){
 * function get_client_ip(){
 * if (getenv("HTTP_CLIENT_IP") && strcasecmp(getenv("HTTP_CLIENT_IP"), "unknown")){
 * $ip = getenv("HTTP_CLIENT_IP");
 * }else if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown")){
 * $ip = getenv("HTTP_X_FORWARDED_FOR");
 * }else if (getenv("REMOTE_ADDR") && strcasecmp(getenv("REMOTE_ADDR"), "unknown"))
 * $ip = getenv("REMOTE_ADDR");
 * else if (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], "unknown"))
 * $ip = $_SERVER['REMOTE_ADDR'];
 * else
 * $ip = "unknown";
 *
 * if(!is_ip($ip)){
 * $ips = explode(",", $ip);
 * $ip = isset($ips[1])?trim($ips[1]):'';
 * }
 * return is_ip($ip) ? $ip : '0.0.0.0';
 * }
 * }
 */

/**
 * 获取客户端的IP地址
 */
if (!function_exists("get_client_ip")) {
    function get_client_ip() {
        $ks = array("HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP", "REMOTE_ADDR");
        $kc = count($ks);
        for ($i = 0; $i < $kc; $i++) {
            $k = $ks[$i];
            $ip = trim(isset($_SERVER[$k]) ? $_SERVER[$k] : getenv($k));
            if (empty($ip) || strcasecmp($ip, "unknown") == 0) {
                continue;
            }
            $ips = explode(",", $ip);
            $ip = trim($ips[0]);

            if (is_ip($ip)) return $ip;
        }
        return '0.0.0.0';
    }
}

//IP判断
if (!function_exists("is_ip")) {
    function is_ip($gonten) {
        $ip = explode(".", $gonten);
        for ($i = 0; $i < count($ip); $i++) {
            if ($ip[$i] > 255) {
                return (0);
            }
        }
        return @ereg("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", $gonten);
    }
}

/**
 * 安全过滤数据
 * @param string  $str        需要处理的字符
 * @param string  $type       返回的字符类型，支持，string,int,float,html
 * @param maxid   $default    当出现错误或无数据时默认返回值
 * @param boolean $checkempty 强制转化为正数
 * @return        mixed                   当出现错误或无数据时默认返回值
 */
if (!function_exists("getParam")) {
    function getParam($str, $type = 'string', $default = '', $checkempty = false, $pnumber = false) {

        $_str = "";
        switch ($type) {
            case 'string': //字符处理
                $_str = strip_tags($str);
                $_str = str_replace("'", '&#39;', $_str);
                $_str = str_replace("\"", '&quot;', $_str);
                $_str = str_replace("\\", '', $_str);
                $_str = str_replace("\/", '', $_str);

                $_str = daddslashes(html_escape($_str));

                break;
            case 'int': //获取整形数据
                $_str = verify_id($str);
                break;
            case 'float': //获浮点形数据
                $_str = (float)$str;
                break;
            case 'html': //获取HTML，防止XSS攻击
                $_str = self::reMoveXss($str);
                break;
            case 'time':
                $_str = $str ? strtotime($str) : '';
                break;
            default: //默认当做字符处理
                $_str = strip_tags($str);
                break;
        }
        if ($checkempty == true) {
            if (empty($str)) {
                header("content-type:text/html;charset=utf-8;");
                exit("非法操作！");
            }
        }

        if (empty($_str)) return $default;
        if ($type == "int" || $type == "float") {
            $_str = $pnumber == true ? abs($_str) : $_str;
            return $_str;
        }
        return trim($_str);
    }
}

//过滤XSS攻击
if (!function_exists("reMoveXss")) {
    function reMoveXss($val) {
        // remove all non-printable characters. CR(0a) and LF(0b) and TAB(9) are allowed
        // this prevents some character re-spacing such as <java\0script>
        // note that you have to handle splits with \n, \r, and \t later since they *are* allowed in some inputs
        $val = preg_replace('/([\x00-\x08|\x0b-\x0c|\x0e-\x19])/', '', $val);

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
        $ra1 = Array('javascript', 'vbscript', 'expression', 'applet', 'meta', 'xml', 'blink', 'link', '<script', 'object', 'iframe', 'frame', 'frameset', 'ilayer'/* , 'layer' */, 'bgsound', 'base');
        $ra2 = Array('onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload');
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
}

/**
 * 函数名称：verify_id()
 * 函数作用：校验提交的ID类值是否合法
 * 参　　数：$id: 提交的ID值
 * 返 回 值：返回处理后的ID
 */
if (!function_exists("verify_id")) {
    function verify_id($id = null) {
        if (!$id) {
            return 0;
        } // 是否为空判断
        elseif (inject_check($id)) {
            return 0;
        } // 注射判断
        elseif (!is_numeric($id)) {
            return 0;
        } // 数字判断
        $id = intval($id); // 整型化
        return $id;
    }
}

/**
 * 处理form 提交的参数过滤
 * $string    string  需要处理的字符串或者数组
 * $force    boolean 强制进行处理
 * @return    string  返回处理之后的字符串或者数组
 */
if (!function_exists("daddslashes")) {
    function daddslashes($string, $force = 1) {
        if (is_array($string)) {
            $keys = array_keys($string);
            foreach ($keys as $key) {
                $val = $string[$key];
                unset($string[$key]);
                $string[addslashes($key)] = daddslashes($val, $force);
            }
        } else {
            $string = addslashes($string);
        }
        return $string;
    }
}

/**
 * 处理form 提交的参数过滤
 * $string    string  需要处理的字符串
 * @return    string 返回处理之后的字符串或者数组
 */
if (!function_exists("dowith_sql")) {
    function dowith_sql($str) {
        $str = str_replace("and", "", $str);
        $str = str_replace("execute", "", $str);
        $str = str_replace("update", "", $str);
        $str = str_replace("count", "", $str);
        $str = str_replace("chr", "", $str);
        $str = str_replace("mid", "", $str);
        $str = str_replace("master", "", $str);
        $str = str_replace("truncate", "", $str);
        $str = str_replace("char", "", $str);
        $str = str_replace("declare", "", $str);
        $str = str_replace("select", "", $str);
        $str = str_replace("create", "", $str);
        $str = str_replace("delete", "", $str);
        $str = str_replace("insert", "", $str);
        // $str = str_replace("'","",$str);
        // $str = str_replace('"',"",$str);
        // $str = str_replace(" ","",$str);
        $str = str_replace("or", "", $str);
        $str = str_replace("=", "", $str);
        $str = str_replace("%20", "", $str);
        //echo $str;
        return $str;
    }
}

/**
 *检测提交的值是不是含有SQL注射的字符，防止注射，保护服务器安全
 *参　　数：$sql_str: 提交的变量
 *返 回 值：返回检测结果，ture or false
 */

if (!function_exists("inject_check")) {
    function inject_check($sql_str) {
        return @eregi('select|insert|and|or|update|delete|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile', $sql_str); // 进行过滤
    }
}

/**
 * 处理禁用HTML但允许换行的内容
 * @access    public
 * @param     string $msg 需要过滤的内容
 * @return    string
 */
if (!function_exists('TrimMsg')) {
    function TrimMsg($msg) {
        $msg = trim(stripslashes($msg));
        $msg = nl2br(htmlspecialchars($msg));
        $msg = str_replace("  ", "&nbsp;&nbsp;", $msg);
        return addslashes($msg);
    }
}

/**
 * PHP判断字符串纯汉字 OR 纯英文 OR 汉英混合
 * return 1:英文
 * return 2：纯汉字
 * return 3：汉字和英文
 */

function utf8_str($str) {
    $mb = mb_strlen($str, 'utf-8');
    $st = strlen($str);
    if ($st == $mb)
        return 1;
    if ($st % $mb == 0 && $st % 3 == 0)
        return 2;
    return 3;
}

/**
 * +----------------------------------------------------------
 * 字符串截取，支持中文和其他编码
 * +----------------------------------------------------------
 * @static
 * @access public
 * +----------------------------------------------------------
 * @param string $str      需要转换的字符串
 * @param string $start    开始位置
 * @param string $length   截取长度
 * @param string $charset  编码格式
 * @param string $suffix   截断显示字符
 * @param string $strength 字符串的长度
 *                         +----------------------------------------------------------
 * @return string
+----------------------------------------------------------
 */
function msubstr($str, $start = 0, $length, $strength, $charset = "utf-8", $suffix = true) {
    if (function_exists("mb_substr")) {
        if ($suffix) {
            if ($length < $strength) {
                return mb_substr($str, $start, $length, $charset) . "....";
            } else {
                return mb_substr($str, $start, $length, $charset);
            }
        } else {
            return mb_substr($str, $start, $length, $charset);
        }
    } elseif (function_exists('iconv_substr')) {
        if ($suffix) {//是否加上......符号
            if ($length < $strength) {
                return iconv_substr($str, $start, $length, $charset) . "....";
            } else {
                return iconv_substr($str, $start, $length, $charset);
            }
        } else {
            return iconv_substr($str, $start, $length, $charset);
        }
    }

    $re['utf-8'] = "/[\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xff][\x80-\xbf]{3}/";
    $re['gb2312'] = "/[\x01-\x7f]|[\xb0-\xf7][\xa0-\xfe]/";
    $re['gbk'] = "/[\x01-\x7f]|[\x81-\xfe][\x40-\xfe]/";
    $re['big5'] = "/[\x01-\x7f]|[\x81-\xfe]([\x40-\x7e]|\xa1-\xfe])/";
    preg_match_all($re[$charset], $str, $match);
    $slice = join("", array_slice($match[0], $start, $length));
    if ($suffix) {
        return $slice . "…";
    } else {
        return $slice;
    }
}


//替代上方中文截取方法 -周磊 2016-5-13 20:01
function m_substr($str, $start = 0, $length, $charset = "utf-8", $suffix = true) {
    if (function_exists("mb_substr")) {
        if ($suffix) {
            if ($str == mb_substr($str, $start, $length, $charset)) {
                return mb_substr($str, $start, $length, $charset);
            } else {
                return mb_substr($str, $start, $length, $charset) . "...";
            }
        } else {
            return mb_substr($str, $start, $length, $charset);
        }
    } elseif (function_exists('iconv_substr')) {
        if ($suffix) {
            if ($str == iconv_substr($str, $start, $length, $charset)) {
                return iconv_substr($str, $start, $length, $charset);
            } else {
                return iconv_substr($str, $start, $length, $charset) . "...";
            }
        } else {
            return iconv_substr($str, $start, $length, $charset);
        }
    }
    $re['utf-8'] = "/[\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xff][\x80-\xbf]{3}/";
    $re['gb2312'] = "/[\x01-\x7f]|[\xb0-\xf7][\xa0-\xfe]/";
    $re['gbk'] = "/[\x01-\x7f]|[\x81-\xfe][\x40-\xfe]/";
    $re['big5'] = "/[\x01-\x7f]|[\x81-\xfe]([\x40-\x7e]|\xa1-\xfe])/";
    preg_match_all($re[$charset], $str, $match);
    $slice = join("", array_slice($match[0], $start, $length));
    if ($suffix) return $slice . "…";
    return $slice;
}

/**
 * +----------------------------------------------------------
 * 字符串截取，支持中文和其他编码
 * +----------------------------------------------------------
 * @static
 * @access public
 * +----------------------------------------------------------
 * @param string $str     需要计算的字符串
 * @param string $charset 字符编码
 *                        +----------------------------------------------------------
 * @return length int
 *                        +----------------------------------------------------------
 */

function abslength($str, $charset = 'utf-8') {
    if (empty($str)) {
        return 0;
    }
    if (function_exists('mb_strlen')) {
        return mb_strlen($str, 'utf-8');
    } else {
        @preg_match_all("/./u", $str, $ar);
        return count($ar[0]);
    }
}

/**
 * $string 明文或密文
 * $operation 加密ENCODE或解密DECODE
 * $key 密钥
 * $expiry 密钥有效期 ， 默认是一直有效
 */
if (!function_exists("auth_code")) {
    function auth_code($string, $operation = 'DECODE', $key = '', $expiry = 0) {
        /*
        动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
        取值越大，密文变动规律越大，密文变化 = 16 的 $ckey_length 次方
        当此值为 0 时，则不产生随机密钥
        */

        $ckey_length = 4;
        $key = md5($key != '' ? $key : "sgxgjihoegs"); // 此处的key可以自己进行定义，写到配置文件也可以
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';

        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);

        $result = '';
        $box = range(0, 255);

        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }

        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }

        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }

        if ($operation == 'DECODE') {
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
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
}


/**
 * 计算密码强度
 */
if (!function_exists("getPassLevel")) {
    function getPassLevel($password) {
        $partArr = array('/[0-9]/', '/[a-z]/', '/[A-Z]/', '/[\W_]/');
        $score = 0;

        //根据长度加分
        $score += strlen($password);
        //根据类型加分
        foreach ($partArr as $part) {
            if (preg_match($part, $password)) $score += 5;//某类型存在加分
            $regexCount = preg_match_all($part, $password, $out);//某类型存在，并且存在个数大于2加2份，个数大于5加7份
            if ($regexCount >= 5) {
                $score += 7;
            } elseif ($regexCount >= 2) {
                $score += 2;
            }
        }
        //重复检测
        $repeatChar = '';
        $repeatCount = 0;
        for ($i = 0; $i < strlen($password); $i++) {
            if ($password{$i} == $repeatChar) $repeatCount++;
            else $repeatChar = $password{$i};
        }
        $score -= $repeatCount * 2;
        //等级输出
        $level = 0;
        if ($score <= 10) { //弱
            $level = 1;
        } elseif ($score <= 25) { //一般
            $level = 2;
        } elseif ($score <= 37) { //很好
            $level = 3;
        } elseif ($score <= 50) { //极佳
            $level = 4;
        } else {
            $level = 4;
        }
        //如果是密码为123456
        if (in_array($password, array('123456', 'abcdef'))) {
            $level = 1;
        }
        return $level;
    }
}

/**
 * 得到新订单号
 * @return  string
 */
if (!function_exists('get_order_sn')) {
    function get_order_sn() {
        /* 选择一个随机的方案 */
        mt_srand((double)microtime() * 1000000);
//        return date('YmdHis') . str_pad(mt_rand(1, 999999), 6, '0', STR_PAD_LEFT);
        return date('YmdHis') . substr(implode(NULL, array_map('ord', str_split(substr(uniqid(), 7, 13), 1))), 0, 8);
    }
}

/**
 * 打印接口消息提示
 */
if (!function_exists("printMessage")) {
    function printMessage($message, $result = 'false') {
        exit("{\"message\":\"" . $message . "\",\"success\":\"{$result}\"}");
    }
}

/**
 * 返回表前缀
 */
if (!function_exists("table_pre")) {
    function table_pre($group = 'default') {
        $table_pre = '';
        if ($group) {
            if (file_exists(__ROOT__ . "/include/config/db.inc.php")) {
                include __ROOT__ . "/include/config/db.inc.php";
                if (isset($db[$group]) && $db[$group]) {
                    if (isset($db[$group]['table_pre']) && $db[$group]['table_pre']) {
                        $table_pre = $db[$group]['table_pre'];
                    } elseif (isset($db[$group]['dbprefix']) && $db[$group]['dbprefix']) {
                        $table_pre = $db[$group]['dbprefix'];
                    }
                }
            }
        }
        return $table_pre;
    }
}

/**
 * 返回结果组织
 */
if (!function_exists("result_to_towf_new")) {
    function result_to_towf_new($vDataResult, $ret, $errmsg, $sigInfo) {
        $result_arr = array();
        $result_arr["resultcode"] = (string)$ret;
        $tmp_arr["errmsg"] = $errmsg;
        $tmp_arr["obj"] = $sigInfo;
        $vResult = array();
        $tmp_arr["list"] = $vDataResult;
        $result_arr["resultinfo"] = $tmp_arr;
        return json_encode($result_arr);
    }
}

/**
 * hash算法结构
 * @return string
 */
function hash_num($v1) {
    if (bccomp($v1, "9223372036854775807") > 0) {
        $v3 = bcsub($v1, "9223372036854775808");
        $v1 = bcadd("-9223372036854775808", $v3);

    } else if (bccomp($v1, "-9223372036854775808") < 0) {
        $v3 = bcadd($v1, "9223372036854775808");
        $v1 = bcadd("9223372036854775808", $v3);
    }

    return $v1;
}

function hash_left($v1, $v2) {
    $v1 = hash_num($v1);
    for ($i = 0; $i < $v2; $i++) {
        $v1 = bcmul($v1, "2");
        $v1 = hash_num($v1);
    }
    return $v1;
}

function hash_add($v1, $v2) {
    $v1 = hash_num($v1);
    $v1 = bcadd($v1, $v2);
    $v1 = hash_num($v1);
    return $v1;
}

function hash_sub($v1, $v2) {
    $v1 = hash_num($v1);
    $v1 = bcsub($v1, $v2);
    $v1 = hash_num($v1);
    return $v1;
}

if (!function_exists("hash_str")) {
    function hash_str($str) {
        $hash = "0";
        for ($i = 0; $i < strlen($str); $i++) {
            $val = hash_left($hash, 5);
            $val = hash_add($val, $hash);
            $val = hash_sub($val, "6");
            $v = strval(ord($str{$i}));
            $val = hash_add($val, $v);

            $hash = $val;
        }
        return $hash;
    }
}

//$v = hash_str("02:00:00:00:00:00");
//var_dump($v);

/**
 * app key 算法
 */
class APPKEY {

    static $INDEXS = array(5, 0, 7, 2, 6, 1, 4, 3);
    static $MASKS = array(0, 0, 0, 0, 0, 0, 0, 0);

    static function int2bytes($v1, $v2) {

        $buf = array();
        for ($i = 0; $i < 4; $i++) {
            $buf[3 - $i] = ($v1 >> ($i * 8)) & 0xff;
        }
        for ($i = 0; $i < 4; $i++) {
            $buf[7 - $i] = ($v2 >> ($i * 8)) & 0xff;
        }
        return $buf;
    }

    static function bytes_encode($buf) {

        if (count($buf) != 8) return null;

        $result = array();
        for ($i = 0; $i < 8; $i++) {
            $f = self::$INDEXS[$i];
            $result[$i] = ($buf[$f]) ^ (self::$MASKS[$i]);
        }

        return $result;
    }

    //编码
    static function encode($uid, $appid) {
        $buf = self::int2bytes($uid, $appid);
        $bytes = self::bytes_encode($buf);
        return sprintf("%02X%02X%02X%02X%02X%02X%02X%02X",
            $bytes[0], $bytes[1], $bytes[2], $bytes[3], $bytes[4], $bytes[5], $bytes[6], $bytes[7]);
    }
}

/**
 * Drkey 算法
 * $uid, $appid,$cid,$adid,$udid
 * '4816', '4485','6105','2806','24B0D5A7-20E9-4815-86D5-A033F33449C2'
 * 00008512110000D00000F6170A0000D924B0D5A7-20E9-4815-86D5-A033F33449C2
 */
class DrKey {

    static $INDEXS = array(5, 0, 7, 2, 6, 1, 4, 3);
    static $MASKS = array(0, 0, 0, 0, 0, 0, 0, 0);

    static function int2bytes($v1, $v2) {

        $buf = array();
        for ($i = 0; $i < 4; $i++) {
            $buf[3 - $i] = ($v1 >> ($i * 8)) & 0xff;
        }
        for ($i = 0; $i < 4; $i++) {
            $buf[7 - $i] = ($v2 >> ($i * 8)) & 0xff;
        }
        return $buf;
    }

    static function bytes_encode($buf) {

        if (count($buf) != 8) return null;

        $result = array();
        for ($i = 0; $i < 8; $i++) {
            $f = self::$INDEXS[$i];
            $result[$i] = ($buf[$f]) ^ (self::$MASKS[$i]);
        }
        return $result;
    }

    function bytes_decode($buf) {

        if (count($buf) != 8) return null;

        $result = array();
        for ($i = 0; $i < 8; $i++) {
            $f = self::$INDEXS[$i];
            $result[$f] = ($buf[$i]) ^ (self::$MASKS[$i]);
        }

        return $result;
    }

    static function appkey_encode($uid, $appid) {

        $buf = self::int2bytes($uid, $appid);
        $bytes = self::encode($buf);
        return sprintf("%02X%02X%02X%02X%02X%02X%02X%02X",
            $bytes[0], $bytes[1], $bytes[2], $bytes[3], $bytes[4], $bytes[5], $bytes[6], $bytes[7]);
    }

    static function appkey_decode($key) {

        $len = strlen($key);
        $bytes = array();
        $k = 0;
        for ($i = 0; $i < $len; $i += 2) {
            $code = substr($key, $i, 2);
            $bytes[$k++] = hexdec($code);
        }

        $bytes = self::bytes_decode($bytes);

        $v2 = ($bytes[4] << 24) | ($bytes[5] << 16) | ($bytes[6] << 8) | $bytes[7];
        $v1 = ($bytes[0] << 24) | ($bytes[1] << 16) | ($bytes[2] << 8) | $bytes[3];

        return array('v1' => $v1, "v2" => $v2);
    }

    //编码
    static function encode($uid, $appid, $cid, $adid, $udid) {
        $buf = self::int2bytes($uid, $appid);
        $buf_ads = self::int2bytes($cid, $adid);
        $bytes = self::bytes_encode($buf);
        $bytes_ads = self::bytes_encode($buf_ads);
        $result = sprintf("%02X%02X%02X%02X%02X%02X%02X%02X",
            $bytes[0], $bytes[1], $bytes[2], $bytes[3], $bytes[4], $bytes[5], $bytes[6], $bytes[7]);
        $result .= sprintf("%02X%02X%02X%02X%02X%02X%02X%02X",
            $bytes_ads[0], $bytes_ads[1], $bytes_ads[2], $bytes_ads[3], $bytes_ads[4], $bytes_ads[5], $bytes_ads[6], $bytes_ads[7]);
        return $result . $udid;
    }

    static function decode($drkey) {

        $len = strlen($drkey);
        $appkey = substr($drkey, 0, 16);
        $adskey = substr($drkey, 16, 16);

        $mac = '02:00:00:00:00:00';
        $idfa = '';
        if ($len - 32 > 17) {
            if (strpos($drkey, ':')) {
                $mac = substr($drkey, 32, 17);
                if ($len - 49 > 0) {
                    $idfa = substr($drkey, 49, $len - 49);
                }
            } else {
                $idfa = substr($drkey, 32, $len - 32);
            }
        } else {
            $mac = substr($drkey, 32, 17);
        }
        $appkey = self::appkey_decode($appkey);
        $adskey = self::appkey_decode($adskey);
        return array("mac" => $mac, "idfa" => $idfa, "uid" => $appkey['v1'], "appid" => $appkey['v2'], "cid" => $adskey['v1'], "adid" => $adskey['v2']);
    }
}

/**
 * 发送http请求
 * @return string
 */
function sendHttp($url, $var = '', $type = 'get', $timeout = 120, $referer = '') {
    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);

    curl_setopt($curl, CURLOPT_ENCODING, 'gzip');
    curl_setopt($curl, CURLOPT_NOSIGNAL, 1);
    //curl_setopt($curl, CURLOPT_HTTPHEADER, $theHeaders);
    if (!empty($referer)) {
        curl_setopt($curl, CURLOPT_REFERER, $referer);
    }
    //curl_setopt($curl, CURLOPT_COOKIEJAR, 'cookies.txt');
    //curl_setopt($curl, CURLOPT_COOKIEFILE, 'cookies.txt');
    if ($type == 'post') {
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $var);
    }
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    $data['str'] = curl_exec($curl);
    $data['status'] = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $data['errno'] = curl_error($curl);

    curl_close($curl);

    return $data;
}

/**
 * @param $url
 * @param $data
 * @return mixed
 * @throws Exception
 */
function http_post($url, $data_string) {
    $curl_handle=curl_init();
    curl_setopt($curl_handle,CURLOPT_URL, $url);
    curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl_handle,CURLOPT_HEADER, 0);
    curl_setopt($curl_handle,CURLOPT_POST, true);
    curl_setopt($curl_handle,CURLOPT_POSTFIELDS, $data_string);
    curl_setopt($curl_handle,CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($curl_handle,CURLOPT_SSL_VERIFYPEER, 0);
    $response =curl_exec($curl_handle);
    curl_close($curl_handle);
    return $response;
}

/**
 * @param $to         发送短信的手机号
 * @param $param      模版参数，多参数用,隔开
 * @return mixed 成功返回 000000
 * @param $templateId 模版id
 * @return mixed 成功返回000000
 */
function send_message($to, $param, $templateId) {

    $sms_info = config_item('sms_info');
    $appId = $sms_info['appId'];
    $CI = &get_instance();
    $config = array('accountsid' => $sms_info['account'], 'token' => $sms_info['password']);

    $CI->load->library('Ucpaas', $config);
    $templateId = $sms_info['templateId'][$templateId];
    $return = $CI->ucpaas->templateSMS($appId, $to, $templateId, $param);
    $return_arr = json_decode($return, true);

    return $return_arr['resp']['respCode'];
}

/**
 * @param        $length 随记数长度
 * @param string $chars  随机字符串
 * @return string 返回生成的随机数
 */
function random($length, $chars = '0123456789') {
    $hash = '';
    $max = strlen($chars) - 1;
    for ($i = 0; $i < $length; $i++) {
        $hash .= $chars[mt_rand(0, $max)];
    }
    return $hash;
}

/**
 * 随机生成字符串
 * @param $length
 * @return string
 */
function createRandomStr($length) {
    $str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';//62个字符
    $strlen = 62;
    while ($length > $strlen) {
        $str .= $str;
        $strlen += 62;
    }
    $str = str_shuffle($str);
    return substr($str, 0, $length);
}

//排序二维数组，指定字段排列
function sortArray($source, $filed, $sort = 'desc') {

    $arr = array();
    foreach ($source as $key => $value) {
        $arr[$key] = $value[$filed];
    }

    array_multisort($arr, $sort == 'desc' ? SORT_DESC : SORT_ASC, $source);
    return $source;
}

//二维数组去重
function arr_unique($array) {
    foreach ($array as $v) {
        $v = join(',', $v);//降维,也可以用implode,将一维数组转换为用逗号连接的字符串
        $temp[] = $v;
    }
    $temp = array_unique($temp);//去掉重复的字符串,也就是重复的一维数组
    foreach ($temp as $k => $v) {
        $temp[$k] = explode(',', $v);//再将拆开的数组重新组装
    }
    return $temp;
}

/**
 * 字符串查找
 * 是否包含
 */

function isContains($str, $find) {
    return isContain($str, $find);
}

function isContain($str, $find) {
    if (empty($find)) {
        return true;
    }

    $pos = strpos($str, $find);
    if ($pos === false) {
        return false;
    } else {
        return true;
    }
}

//$source 默认逗号分隔
function in_array_exist($source, $search, $d = ',') {

    if (empty($search) || empty($source)) {
        return false;
    }

    $source = explode(",", $source);
    if (in_array($search, $source)) {
        return true;
    }
    return false;
}

/**
 * 返回当前页面的URL
 */
function cur_page_url() {

    $pageURL = 'http';
    if (isset($_SERVER["HTTPS"]) ? $_SERVER["HTTPS"] : '' == "on") {
        $pageURL .= "s";
    }
    $pageURL .= "://";

    if ($_SERVER["SERVER_PORT"] != "80") {
        $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
    } else {
        $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
    }
    return $pageURL;
}

//SQL组合类
class SQL {

    static function field($keys) {
        $ks = '';
        foreach ($keys as $k) {
            if ($ks != '') $ks .= ",`$k`";
            else $ks = " `$k`";
        }
        return $ks;
    }

    static function value($values) {
        $ks = '';
        foreach ($values as $v) {
            if (is_array($v)) $v = json_encode($v, JSON_UNESCAPED_UNICODE);
            if ($ks != '') $ks .= ",'$v'";
            else $ks = " '$v'";
        }
        return $ks;
    }

    static function order($os, $ot = 'DESC') {
        $ks = '';
        foreach ($os as $k) {
            if ($ks != '') $ks .= ",`$k` $ot";
            else $ks = " `$k` $ot";
        }

        return " ORDER BY " . $ks;
    }

    static function query($tables, $attrs, $keys = NULL, $os = NULL, $ot = 'DESC', $limit = null) {
        if (is_array($tables)) {
            $ts = SQL::field($tables);
        } else {
            $ts = '`' . $tables . '`';
        }
        if (is_array($attrs)) {
            $w = SQL::where($attrs);
        } else {
            $w = "$attrs";
        }
        if (is_array($keys)) {
            $ks = SQL::field($keys);
        } else if ($keys == NULL) {
            $ks = '*';
        } else {
            $ks = "$keys";
        }
        $order = $os == NULL ? '' : SQL::order($os, $ot);

        $sql = 'SELECT  ' . $ks . ' FROM ' . $ts;
        if ($w != '') {
            $sql .= ' WHERE ' . $w;
        }
        if ($order != '') {
            $sql .= ' ' . $order;
        }

        if ($limit) {
            if (is_array($limit)) {
                $sql .= ' limit ' . $limit[0] . ',' . $limit[1];
            } else {
                $sql .= ' limit 0,' . $limit;
            }
        }

        return $sql;
    }

    static function insert($attrs) {
        $kv = array('k' => '', 'v' => '');
        foreach ($attrs as $k => $v) {
            if ($kv['k'] != '') $kv['k'] .= ",`$k`";
            else $kv['k'] = "`$k`";

            if (is_array($v)) $v = json_encode($v);
            if ($kv['v'] != '') $kv['v'] .= ",'$v'";
            else $kv['v'] = "'$v'";
        }
        return $kv;
    }

    static function update($attrs, $keys = NULL) {
        $kv = '';
        if ($keys == NULL) {
            foreach ($attrs as $k => $v) {
                if (is_array($v)) $v = json_encode($v);

                if ($kv != '') $kv .= ",`$k`='$v'";
                else $kv = "`$k`='$v'";
            }
        } else if (is_array($keys)) {
            foreach ($attrs as $k => $v) {
                if (is_array($v)) $v = json_encode($v);

                if (!array_key_exists($k, $keys)) {
                    if ($kv != '') $kv .= ",`$k`='$v'";
                    else $kv = "`$k`='$v'";
                }
            }
        } else {
            foreach ($attrs as $k => $v) {
                if ($k != $keys) {
                    if (is_array($v)) $v = json_encode($v);

                    if ($kv != '') $kv .= ",`$k`='$v'";
                    else $kv = "`$k`='$v'";
                }
            }
        }
        return $kv;
    }

    static function where($attrs, $keys = NULL, $glue = 'AND') {
        $kv = '';
        if ($keys == NULL) {
            foreach ($attrs as $k => $v) {

                if (is_array($v)) $v = '`' . $k . '` IN (' . SQL::value($v) . ')';
                else if (strlen($v) > 0 && $v[0] == '|') {
                    $v = substr($v, 1);
                    $v = " INSTR(`$k`,'\"" . $v . '"\')>0';
                } else if (strlen($v) > 0 && $v[0] == '?') {
                    $c = substr($v, 1, 2);
                    $v = substr($v, 3);
                    $v = " `$k`$c'$v'";
                } else $v = "`$k`='$v'";
                if ($kv != '') $kv .= " $glue $v";
                else $kv = "$v";
            }
        } else if (is_array($keys)) {
            foreach ($keys as $k => $v) {
                if (is_numeric($k)) {
                    $k = $v;
                    $v = $attrs[$k];
                    if (is_array($v)) $v = ' IN (' . SQL::value($v) . ',)';
                    else $v = "='$v'";

                    if ($kv != '') $kv .= " $glue `$k`$v";
                    else $kv = "`$k`$v";
                } else {
                    if (is_array($v)) $v = ' IN (' . SQL::value($v) . ',)';
                    else $v = "='$v'";

                    if ($kv != '') $kv .= " $glue `$k`$v";
                    else $kv = "`$k`$v";
                }
            }
        } else {
            $kv = " `$keys`='$attrs[$keys]'";
        }
        return $kv;
    }
}

/**
 * cookie设置
 * @param $var    设置的cookie名
 * @param $value  设置的cookie值
 * @param $life   设置的过期时间：为整型，单位秒 如60表示60秒后过期
 * @param $path   设置的cookie作用路径
 * @param $domain 设置的cookie作用域名
 */
function ssetcookie($array, $life = 0, $path = '/', $domain = COOKIE_DOMAIN) {
    //global $_SERVER;
    $_cookName_ary = array_keys($array);
    for ($i = 0; $i < count($array); $i++) {
        //setcookie($_cookName_ary[$i], $array[$_cookName_ary[$i]], $life ? (time() + $life) : 0, $path, $domain, $_SERVER['SERVER_PORT'] == 443 ? 1 : 0);
        setcookie($_cookName_ary[$i], $array[$_cookName_ary[$i]], $life ? (time() + $life) : 0, $path, $domain);
    }
}

/**
 * 页面用与输出函数
 * 并判断是否存在，不存在给默认是
 */
function iecho($val, $default = '') {
    echo isset($val) ? $val : $default;
}

function ireturn($val, $default = '') {
    $tmp = "";
    if (isset($val)) {
        $tmp = $val;
    }
    return empty($tmp) ? $default : $tmp;

}

/**
 * 文件目录生成规则
 */
function dir_rule($appid) {

    $l1 = ($appid >> 16) & 0xffff;
    $l2 = ($appid & 0xff00) >> 8;
    $l3 = $appid & 0xff;

    $path = sprintf("%04x/%02x/%02x/", $l1, $l2, $l3);
    return $path;
}

/**
 * @param $id
 * @param $key 缓存文件名
 * @return string 缓存路径
 */
if (!function_exists('get_cache_key')) {
    function get_cache_key($id, $key) {
        $dir = dir_rule($id);
        $path = $dir;
        $date = date('Ymd', time());
        $dir = APPPATH . 'cache/' . $date . '/' . $path;
        if (!file_exists($dir)) {
            @mkdir($dir, 0777, true);
        }
        return $date . '/' . $path . $key;
    }
}

/**
 * 科学计算法多值的计算
 * 加bcadd($a, $b, 4)（留4位小数）
 * 减bcsub($a, $b, 4)
 * 乘bcmul($a, $b, 4)
 * 除bcdiv($a, $b, 4)
 * 取余bcmod($a, $b)
 * @param array  $num_arr 数字数组
 * @param string $method  +-*\/%
 * @param number $scale   保留几位小数
 */
function calculate($num1, $num2, $method = '+', $scale = 4) {

    $func = '';
    switch ($method) {
        case '+':
            $func = 'bcadd';
            break;
        case '-':
            $func = 'bcsub';
            break;
        case '*':
            $func = 'bcmul';
            break;
        case '/':
            $func = 'bcdiv';
            break;
        case '%':
            $func = 'bcmod';
            break;
        default:
            return false;
    }

    $reNum = $func($num1, $num2, $scale);
    return $reNum;
}

/**
 * 文件写入操作
 * @param unknown_type $path
 * @param unknown_type $data
 * @param unknown_type $mode
 * @return boolean
 */
function write_txt($path, $data, $mode = FOPEN_WRITE_CREATE_DESTRUCTIVE) {
    if (!$fp = @fopen($path, $mode)) {
        return FALSE;
    }

    flock($fp, LOCK_EX);
    fwrite($fp, $data . "\r\n");
    flock($fp, LOCK_UN);
    fclose($fp);

    return TRUE;
}

/**
 * 创建目录
 * @param $path
 */
function create_dir($path) {
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
        @chmod($path, 0777);
    }
}

/**
 * 递归创建目录
 * @param $dir
 * @return bool
 */
function mkDirs($dir) {
    if (!is_dir($dir)) {
        if (!mkDirs(dirname($dir))) {
            return false;
        }
        if (!mkdir($dir, 0777)) {
            return false;
        }
    }
    return true;
}

//删除非空目录
function delete_dir($dir) {
    //先删除目录下的文件：
    $dh = opendir($dir);
    while ($file = readdir($dh)) {
        if ($file != "." && $file != "..") {
            $fullpath = $dir . "/" . $file;
            if (!is_dir($fullpath)) {
                unlink($fullpath);
            } else {
                deldir($fullpath);
            }
        }
    }

    closedir($dh);
    //删除当前文件夹：
    if (rmdir($dir)) {
        return true;
    } else {
        return false;
    }

}

/**
 * 记录上报日志
 */
function write_report_log($data, $type) {

    $dir = "";
    switch ($type) {
        case 1:
            $dir = "login";
            break;
        case -1:
            $dir = "login_error";
            break;
        case 2:
            $dir = "register";
            break;
        case -2:
            $dir = "register_error";
            break;
        case 3:
            $dir = "recharge";
            break;
        case -3:
            $dir = "recharge_error";
            break;
        case 4:
            $dir = "wechat_recharge";
            break;
        case -4:
            $dir = "wechat_recharge_error";
            break;
        case 5:
            $dir = "logout";
            break;
        case -5:
            $dir = "logout_error";
            break;
        case 20:    //安装收集
            $dir = "install";
            break;
    }

    $path = APPPATH . "home1/include_logs/" . date('Ymd', time()) . '/' . $dir . '/';
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
    }

    $filename = $path . date('Ymd-H') . '.log';
    write_txt($filename, $data, "a+");
}

/**
 * 测试用写入文件
 */
function write_test_log($data) {

    $path = APPPATH . "test/";
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
        @chmod($path, 0777);
    }

    $filename = $path . date('Ymd-H') . '.log';
    write_txt($filename, $data, "a+");
}


/**
 * 签到写入日志
 */
function write_sign_log($data) {
    
    $path = APPPATH . "logs/";
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
        @chmod($path, 0777);
    }

    $filename = $path . date('Ymd') . '.log';
    write_txt($filename, $data, "a+");
}

function write_apply_log($uid, $front, $money, $after) {

    //$path = __ROOT__."../include/apply/".date('Ymd',time()).'/';
    $path = "/home1/include_logs/apply/" . date('Ymd', time()) . '/';
    if (!is_dir($path)) {
        @mkdir($path, 0777, true);
    }

    $filename = $path . date('Ymd-H') . '.log';
    $tmp = $uid . ' ' . $front . ' ' . $money . ' ' . $after . '';
    write_txt($filename, $tmp, "a+");
}

//获取积分的对称加密算法
class DES {

    static $key = '$drhfzj$';

    //注释掉的为旧的方法
// 	static function encrypt($encrypt) {
// 		$key = self::$key;
//     	$iv = mcrypt_create_iv ( mcrypt_get_iv_size ( MCRYPT_DES, MCRYPT_MODE_ECB ), MCRYPT_RAND );
//     	$passcrypt = mcrypt_encrypt ( MCRYPT_DES, $key, $encrypt, MCRYPT_MODE_ECB, $iv );
//     	$encode = base64_encode ( $passcrypt );
//     	return $encode;
// 	}
// 	static function decrypt($decrypt) {
// 		$key = self::$key;
// 		$decoded = base64_decode ($decrypt );
// 		$iv = mcrypt_create_iv ( mcrypt_get_iv_size ( MCRYPT_DES, MCRYPT_MODE_ECB ), MCRYPT_RAND );
// 		$decrypted = mcrypt_decrypt ( MCRYPT_DES, $key, $decoded, MCRYPT_MODE_ECB, $iv );
// 		return $decrypted;
// 	}

    static function encrypt($encrypt) {
        $key = self::$key;
        // 根据 PKCS#7 RFC 5652 Cryptographic Message Syntax (CMS) 修正 Message 加入 Padding
        $block = mcrypt_get_block_size(MCRYPT_DES, MCRYPT_MODE_ECB);
        $pad = $block - (strlen($encrypt) % $block);
        $encrypt .= str_repeat(chr($pad), $pad);

        // 不需要设定 IV 进行加密
        $passcrypt = mcrypt_encrypt(MCRYPT_DES, $key, $encrypt, MCRYPT_MODE_ECB);
        return base64_encode($passcrypt);
    }

    static function decrypt($decrypt) {
        $key = self::$key;
        // 不需要设定 IV
        $str = mcrypt_decrypt(MCRYPT_DES, $key, base64_decode($decrypt), MCRYPT_MODE_ECB);

        // 根据 PKCS#7 RFC 5652 Cryptographic Message Syntax (CMS) 修正 Message 移除 Padding
        $pad = ord($str[strlen($str) - 1]);
        return substr($str, 0, strlen($str) - $pad);
    }
}

//新版 api3.3及以上的签名算法
class Checksum {
    private static $BYTE_TABLE = array(
        "20", "bb", "40", "d4", "4e", "00", "ec", "3d", "2f", "a5",
        "d4", "2f", "7d", "1e", "11", "91", "b2", "74", "20", "e9",
        "e3", "8b", "c0", "47", "e1", "c9", "d7", "bf", "84", "03",
        "00", "85", "3d", "a5", "51", "c2", "c8", "dc", "e3", "17",
        "cb", "3e", "e2", "98", "55", "6a", "ad", "99", "23", "61",
        "ad", "c8", "f7", "08", "2f", "5f", "d6", "a7", "a9", "cd",
        "38", "e3", "2e", "e5", "82", "9f", "22", "42", "7e", "4b",
        "2b", "9d", "e2", "72", "c6", "3b", "50", "14", "d1", "af",
        "9f", "65", "21", "88", "0c", "f0", "e4", "73", "51", "69",
        "4a", "de", "c1", "54", "66", "2a", "b6", "5c", "71", "21",
        "1f", "1f", "18", "c9", "49", "f8", "32", "d3", "36", "6f",
        "83", "6e", "7b", "d7", "32", "1d", "d9", "8a", "d9", "07",
        "76", "d1", "9c", "33", "e7", "2f", "4e", "32", "ae", "76",
        "46", "8a", "f0", "27", "da", "97", "8b", "78", "58", "64",
        "f0", "ac", "64", "ea", "fa", "02", "5f", "c9", "e5", "38",
        "e7", "6f", "1a", "be", "4f", "21", "56", "20", "4c", "a5",
        "f5", "f2", "68", "8b", "d0", "99", "5c", "de", "38", "de",
        "d1", "11", "e3", "5e", "67", "d0", "7a", "df", "7a", "44",
        "8e", "3a", "1f", "99", "92", "62", "07", "ee", "47", "32",
        "80", "43", "c3", "6a", "95", "e4", "49", "3f", "2a", "a4",
        "f0", "ce", "ea", "a5", "e2", "d4", "60", "77", "97", "3b",
        "3e", "0f", "d3", "96", "c8", "eb", "5f", "1d", "48", "11",
        "9c", "77", "21", "cc", "cb", "bb", "53", "e0", "d3", "1d",
        "a9", "11", "5c", "34", "cb", "6e", "ee", "f9", "93", "b7",
        "f7", "1e", "23", "4f", "92", "17", "03", "66", "5e", "fa",
        "12", "2a", "11", "a7", "01", "04"
    );
    private static $BYTE_TABLE_ANDROID = array(
        "20", "bb", "40", "d4", "4e", "00", "ec", "3d", "2f", "a5",
        "d4", "2f", "7d", "1e", "11", "91", "b2", "74", "20", "e9",
        "e3", "8b", "c0", "47", "e1", "c9", "d7", "bf", "84", "03",
        "00", "75", "3d", "a5", "51", "c2", "c8", "dc", "e3", "17",
        "cb", "3e", "e2", "98", "55", "6a", "ad", "99", "23", "61",
        "ad", "c8", "f7", "08", "2f", "5f", "t6", "a7", "a9", "cd",
        "38", "e3", "2e", "e5", "82", "9f", "22", "42", "7e", "4b",
        "2b", "9d", "e2", "72", "c6", "3b", "50", "14", "d1", "af",
        "9f", "65", "21", "88", "0c", "f0", "e4", "73", "51", "69",
        "4a", "de", "c1", "54", "66", "2a", "b6", "5c", "71", "21",
        "1f", "1f", "18", "c9", "49", "f8", "32", "d3", "36", "6f",
        "83", "6e", "7b", "d7", "32", "1d", "d9", "8a", "d9", "07",
        "76", "d1", "9c", "33", "e7", "2f", "4e", "32", "ae", "76",
        "46", "8a", "f0", "o0", "da", "97", "8b", "78", "58", "64",
        "f0", "ac", "64", "ea", "fa", "02", "5f", "c9", "e5", "38",
        "e7", "6f", "1a", "be", "4f", "21", "56", "w9", "4c", "a5",
        "f5", "f2", "68", "8b", "d0", "99", "5c", "de", "38", "de",
        "d1", "11", "e3", "5e", "67", "d0", "7a", "df", "7a", "44",
        "8e", "3a", "1f", "99", "92", "62", "07", "ee", "47", "32",
        "80", "43", "c3", "6a", "95", "e4", "49", "3f", "2a", "a4",
        "f0", "ce", "ea", "a5", "e2", "d4", "60", "77", "97", "3b",
        "3e", "q7", "d3", "96", "c8", "eb", "5f", "g7", "48", "11",
        "9c", "77", "21", "cc", "cb", "bb", "53", "e0", "d3", "1d",
        "a9", "11", "5c", "34", "cb", "6e", "ee", "f9", "93", "b7",
        "f7", "1e", "23", "4f", "92", "17", "03", "66", "5e", "fa",
        "12", "2a", "11", "a7", "01", "04"
    );

    private static function getKey($num) {
        $sb = "";
        for ($i = 0; $i < 4; $i++) {
            $tmp = 1 << $i;
            $v = self::$BYTE_TABLE[$tmp];
            $sb .= $v;
        }
        $n = $num;
        while ($n > 0) {
            $idx = $n & 0xff;
            $n = $num >> 16;
            $v = self::$BYTE_TABLE[$idx];
            $sb .= $v;
        }
        return $sb;
    }

    private static function byte2hex($string) {
        $buf = "";
        for ($i = 0; $i < strlen($string); $i++) {
            $val = dechex(ord($string{$i}));
            if (strlen($val) < 2) {
                $val = "0" . $val;
            }
            $buf .= $val;
        }
        return $buf;
    }

    private static function hex2byte($string) {
        $buf = "";
        for ($i = 0; $i < strlen($string); $i += 2) {
            $item = substr($string, $i, 2);
            $item = hexdec($item);
            $val = chr($item);
            $buf .= $val;
        }
        return $buf;
    }

    public static function encode($data, $key) {

        $key = self::getKey($key);
        $mac_key = hash_hmac('sha256', $data, $key);
        $rs = "";
        $bytes = self::hex2byte($mac_key);
        if (!empty($bytes)) {
            for ($i = 0; $i < strlen($bytes) / 2; $i++) {
                $rs .= $bytes{$i * 2};
            }
        }
        $rs = self::byte2hex($rs);
        return $rs;
    }

    private static function getKey_android($num) {
        $sb = "";
        for ($i = 0; $i < 4; $i++) {
            $tmp = 1 << $i;
            $v = self::$BYTE_TABLE_ANDROID[$tmp];
            $sb .= $v;
        }
        $n = $num;
        while ($n > 0) {
            $idx = $n & 0xff;
            $n = $num >> 16;
            $v = self::$BYTE_TABLE_ANDROID[$idx];
            $sb .= $v;
        }
        return $sb;
    }

    public static function encode_android($data, $key) {

        $key = self::getKey_android($key);
        $mac_key = hash_hmac('sha256', $data, $key);
        $rs = "";
        $bytes = self::hex2byte($mac_key);
        if (!empty($bytes)) {
            for ($i = 0; $i < strlen($bytes) / 2; $i++) {
                $rs .= $bytes{$i * 2};
            }
        }
        $rs = self::byte2hex($rs);
        return $rs;
    }
}


/**
 * IP城市查找
 */
function getCity() {

    $city = "";

    // 当前ip获取
    $ip = get_client_ip();
    if ($ip == 'unknown') {
        return $city;
    }

    // ip转int
    $longIp = ip2long($ip);

    // iputil扩展，利用c扩展进行ip段筛选
    $city = ip_city_ext($longIp);
    return $city;
}

/**
 * ads and meida file cache
 */
function get_file_json($id, $type = 'ads') {

    $content = "";
    if ($type != 'ads' && $type != 'media') {
        return $content;
    }
    if (empty($id)) {
        return $content;
    }

    $dir = dirname(__FILE__);
    $path = $dir . "/../cache/";

    $rule = dir_rule($id);
    $path = $path . $type . '/' . $rule . '/' . $id . '.json';
    if (file_exists($path)) {
        $content = @file_get_contents($path);
    }
    return $content;
}

/**
 * 导出excel公共部分
 * @param $excel_title
 * @param $tmp
 * @param $title_array
 */
function gzwrite_com($excel_title, $tmp, $title_array) {
    // 设置浏览器缓存下载
    $ua = $_SERVER["HTTP_USER_AGENT"];
    header("Pragma: public");
    header("Expires: 0");
    header('Content-Transfer-Encoding: utf-8');
    header("Cache-Control:must-revalidate, post-check=0, pre-check=0");
    header("Content-Type:application/octet-stream");
    header('Cache-Control: max-age=0');
    if (strstr($ua, "MSIE")) {
        header('Content-Disposition:attachment;filename="' . (urlencode($excel_title)) . '.csv.gz"');
    } else {
        header('Content-Disposition:attachment;filename="' . $excel_title . '.csv.gz"');
    }
    header("Content-Transfer-Encoding:binary");

    $of = gzopen($tmp . '.gz', 'w9');
    $titles = iconv("utf-8", "gbk", implode(",", $title_array));
    gzwrite($of, $titles . "\r\n");
    $if = fopen($tmp, 'r');
    while (!feof($if)) {
        $buf = fread($if, 32 * 1024);
        gzwrite($of, $buf);
    }
    gzclose($of);
    fclose($if);

    copy($tmp . '.gz', 'php://output');
    unlink($tmp);
    unlink($tmp . '.gz');
}


/**
 * 文件夹打包成压缩包
 * @param string $path    字符串或一维数组 打包的文件夹路径 最后必须以'/'结尾 例:upload/cartoon/1/
 * @param string $zip     保存到的路径  例：upload/cartoon/1/1.zip
 * @param bool   $opendir 仅 $path 为字符串时可用
 *                        $opendir=false 包含该文件夹打包 $opendir=true 打开文件夹对里面内容进行打包
 * @return bool  true/false
 */
function make_zip($path, $zip, $opendir = false) {

    // 获取文件夹 不存在则创建
    $zip_path = substr($zip, 0, strripos($zip, '/') + 1);
    if (!is_dir($zip_path))
        @mkdir($zip_path, 0777, true);


    set_time_limit(0);
    ini_set('memory_limit', '128M');

    $CI = &get_instance();
    $CI->load->library('zip');

    // 将文件夹添加到队列
    if (is_array($path)) {
        foreach ($path as $v)
            $CI->zip->read_dir($v, false); // false 去除目录结构
    } else {
        // if (substr($path, -1) != '/') $path = $path . '/';
        if ($opendir) {
            $handle = opendir($path);
            while ($dir = readdir($handle)) {
                if ($dir == '.' || $dir == '..')
                    continue;

                if (is_dir($path . $dir)) {
                    $CI->zip->read_dir($path . $dir . '/', false);
                } elseif (file_exists($path . $dir)) {
                    $CI->zip->read_file($path . $dir, false);
                } else {
                    return false;
                }
            }
        } else {
            $CI->zip->read_dir($path, false);
        }
    }
    $res = $CI->zip->archive($zip);
    return $res;

}


/**
 * array_column
 */
if (!function_exists('array_column'))
{
    function array_column($input, $column_key=null, $index_key=null)
    {
        $result = array();
        $i = 0;
        foreach ($input as $v)
        {
            $k = $index_key === null || !isset($v[$index_key]) ? $i++ : $v[$index_key];
            $result[$k] = $column_key === null ? $v : (isset($v[$column_key]) ? $v[$column_key] : null);
        }
        return $result;
    }
}

?>
