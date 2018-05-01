<?php

namespace tool;
//namespace tool\functions;

/**
 * 我的一些常用的方法,写到这里实现复用
 */
class tool_functions
{
    /**
     * summary
     */
    public function __construct()
    {

    }

    /**
     * 提示音
     */
    public static function music($music_num=4, $vdio_url='../resource_plugins/', $loop='no')
    {
        if(empty($vdio_url)){
            $vdio_url='../resource_plugins/';
        }
        $music = [
            0=>'quekly',
            1=>'success',
            2=>'warning',
            3=>'prepare_to_buy',
            4=>'newChance',
            5=>'dingdong',
            6=>'teacher_new_message',
            7=>'状态层次变化',
            8=>'增长中',
            9=>'抛出',
            10=>'买进',
        ];
        // download from http://sc.chinaz.com/tag_yinxiao/tishiyin.html

        if ($loop=='yes' || $loop==1) {
//        if ($loop=='yes') {
//            echo('<audio autoplay loop><source src="./newChance.wav" ></audio>');
            echo('<audio autoplay loop><source src="' . $vdio_url . $music[$music_num] . '.wav" ></audio>');

        } else {
//            echo('<audio autoplay><source src="../resource_plugins/newChance.wav" ></audio>');
            // echo('<audio autoplay><source src="../resource_plugins/'. $music[1] . '.wav" ></audio>');
            // echo('<audio autoplay><source src="../resource_plugins/'. $music[6] . '.wav" ></audio>');
            // echo('<audio autoplay><source src="../resource_plugins/'. $music[5] . '.wav" ></audio>');
            //            echo('<audio autoplay><source src="F:/wamp/www/resource_plugins/'. $music[$music_num] . '.wav" ></audio>'); // 都没有音乐
//            echo('<audio autoplay><source src="../resource_plugins/'. $music[$music_num] . '.wav" ></audio>'); // 有音乐
//            echo('<audio autoplay><source src="../../resource_plugins/'. $music[$music_num] . '.wav" ></audio>'); // 有音乐
            echo('<audio autoplay><source src="' . $vdio_url . $music[$music_num] . '.wav" ></audio>'); // YII有音乐--注意 要针对试图文件来决定相对路径， 而且不可以用绝对路径，可能是解析的路由规则问题
//                    var_dump(__FILE__);
//
//            echo('<audio autoplay><source src="../../resource_plugins/'. $music[$music_num] . '.wav" ></audio>');
        }
        echo('提示音含义: ' . $music[$music_num] . ' &nbsp&nbsp');


//         $music = [
//             0=>'quekly.wav',
//             1=>'success.wav',
//             2=>'warning.wav',
//             3=>'prepare_to_buy.wav',
//             4=>'newChance.wav',
//             5=>'dingdong.wav',
//             6=>'teacher_new_message.wav',
//             7=>'online_relex.mp3',
//         ];
//         // download from http://sc.chinaz.com/tag_yinxiao/tishiyin.html
    }

    /**
     * 保存内容到file
     * 参数: 数据 数组或者内容, 文件名 不要后缀, 是否添加php头部--新文件需要??php数组需要直接之后包含使用, 换行几个.
     * @param  array   $data_array  [description]
     * @param  integer $php         [description]
     * @param  integer $line_feed_n [description]
     * @return [type]               [description]
     *
     * 调用:

    $data=$data_array;
    $file='result_temp';
    $file='warning_gp_' . $this->gpId;
    $file='confirm_gp_' . $this->gpId;
    $php=0;
    $line_feed_n=2;
    save_file($data, $file, $php, $line_feed_n);

     */
    public static function save_file($data=array(), $file_nme='result_temp.php', $start_end=['', ''], $line_feed_n=2, $file_append='FILE_APPEND')
    {
        if ( ! $data) {
            return 'no data';
        }

        $content = '';
        if ($start_end && $start_end[0]) { // $start_end &&  兼容以前的用法
            $content .= $start_end[0] . "\r\n";
        }

        if (is_array($data)) {
            $content .= implode("\r\n", $data);
        } else {
            $content .= $data;
        }

        if ($start_end && $start_end[1]) { // 有的末尾需要加分号或者其他
            // $content .= $start_end[1] . "\r\n";
            $content .= $start_end[1];
        }
        for($i=0; $i< $line_feed_n; $i++) {
            $content .= "\r\n";
        }

//        var_dump($content);exit();
        if ( ! $file_append) {
//            file_put_contents($file_nme, $content);
            $res = file_put_contents($file_nme, $content);
//            估计是权限不够
//            echo substr(sprintf('%o', fileperms('你的目录')), -4); //看看是什么结果
//            echo substr(sprintf('%o', fileperms($file_nme)), -4);
//            return $res;
        } else {
            $res = file_put_contents($file_nme, $content, FILE_APPEND);
        }
        if($res !== false){
            return 1;
        } else{
            return 0;
        }
    }

    /**
     * 取文件最后$n行
     * @param string $filename 文件路径
     * @param int $n 最后几行
     * @return mixed false表示有错误，成功则返回字符串
     */
    public static function FileLastLines($filename,$n){
        if(!$fp=fopen($filename,'r')){
            echo "打开文件失败，请检查文件路径是否正确，路径和文件名不要包含中文";
            return false;
        }
        $pos=-2;
        $eof="";
        $str="";
        while($n>0){
            while($eof!="\n"){
                if(!fseek($fp,$pos,SEEK_END)){
                    $eof=fgetc($fp);
                    $pos--;
                }else{
                    break;
                }
            }
            $str.=fgets($fp);
            $eof="";
            $n--;
        }
        return $str;
    }

    /**
     * 刷新页面
     */
    public static function freshPage($alert=0, $msg='刷新页面', $settime = 0){
//    public static function freshPage($alert=0){

        // $settime = 1000 * 60 * $n + rand(20, 1000); // 更像随机时间
        if ($alert) {
            echo "<script language=\"javascript\"> alert ('" . $msg . "');</script>";
        }

        // todo: note  $settime is micro secend
        if($settime > 0){
            echo "<script language=\"javascript\">setTimeout(function () {
                 window.location.reload();}, $settime);</script>";
        } else {
            echo "<script language=\"javascript\"> window.location.reload();</script>";
        }
    }
    /**
     * 重定向页面
     */
    public static function relocatePage($href){
        // echo "<script language=\"javascript\"> alert (\"一共'.$.'个3000条\");</script>";
        echo "<script language=\"javascript\">window.location.href=\"$href\";</script>";
    }


    /**
     * Curl随机IP 模拟随机IP
     *
     * @return string
     */
    public static function rand_IP(){

        $ip2id= round(rand(600000, 2550000) / 10000); //第一种方法，直接生成
        $ip3id= round(rand(600000, 2550000) / 10000);
        $ip4id= round(rand(600000, 2550000) / 10000);
        //下面是第二种方法，在以下数据中随机抽取
        $arr_1 = array("218","218","66","66","218","218","60","60","202","204","66","66","66","59","61","60","222","221","66","59","60","60","66","218","218","62","63","64","66","66","122","211");
        $randarr= mt_rand(0,count($arr_1)-1);
        $ip1id = $arr_1[$randarr];
        return $ip1id.".".$ip2id.".".$ip3id.".".$ip4id;
    }

    /**
     *   生成某个范围内的随机时间
     * @param <type> $begintime  起始时间 格式为 Y-m-d H:i:s
     * @param <type> $endtime    结束时间 格式为 Y-m-d H:i:s
     */
    public static function randomDate($begintime='1970-01-01', $endtime="2017-10-30") {
        $begin = strtotime($begintime);
        $end = $endtime == "" ? mktime() : strtotime($endtime);
        $timestamp = rand($begin, $end);
        return date("Y-m-d H:i:s", $timestamp);
    }

    public static function formateDate($time='') {
        return date("Y-m-d H:i:s", $time ? $time : time());
    }

    public static function iconvstr($str='', $inchareset='GBK') {
//    public static function iconvstr($str='', $inchareset='GB2312') {

//        if(! preg_match('/<meta[^>]+charset=/i', $html)) {
//            $charset = mb_check_encoding($html, 'utf-8') ? 'utf-8' : 'gbk';
//            $html = sprintf('<meta http-equiv="Content-Type" content="text/html; charset=%s">%s', $charset, $html);
//        }
//
        // 检查编码
        $encode = mb_detect_encoding($str, array("ASCII",'UTF-8',"GB2312", "GBK", 'BIG5'));

        switch ($inchareset) {
            case "ASCII":
//                return iconv('ASCII', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'ASCII');
                break;

            case 'UTF-8':
//                return iconv('UTF', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'UTF');
                break;

            case "GB2312":
//                return iconv('GB2312', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'GB2312');
                break;

            case "GBK":
//                return iconv('GBK', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'GBK');
                break;

            case 'BIG5';
//                return iconv('BIG5', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'BIG5');
                break;

            case 'CP936';
//                return iconv('CP936', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'CP936');
                break;

            default :
//                return iconv('GB2312', 'UTF-8', $str);
                return mb_convert_encoding ($str, 'UTF-8', 'GB2312');
                break;
        }
//        return iconv('GB2312', 'UTF-8', $str);
        return iconv($inchareset, 'UTF-8', $str);
        return iconv("$inchareset", 'UTF-8', $str);
    }

    /**
     * 输出显示utf-8的header
     *
     * @param string $str
     */
    public static function headericonv($str='') {
        header("Content-Type: text/html;charset=utf-8");
    }

    /**
     * 目前自用数据库的时间字段统一处理方式
     *
     * @param array $data
     * @param string $key
     * @param int $type 1新增 2更新 3删除
     * @return array
     */
    public static function htimeFieldHandle($data = [], $key = '', $type = 1) {

        // $create_time
        // $create_str_time
        // $update_time // 初始创建为空
        // $delete_time // 初始创建为空
        $temp = time();
        if($type == 1) {
            if (isset($data[$key]['create_time'])) {
                $data[$key]['create_time'] = self::formateDate($temp);
            }
            if (isset($data[$key]['create_str_time'])) {
                $data[$key]['create_str_time'] = $temp; // 字符串形式时间戳
            }
        } else if($type == 2) {
            if (isset($data[$key]['update_time'])) {
                $data[$key]['update_time'] = self::formateDate($temp);
            }
        } else if($type == 3) {
            if (isset($data[$key]['delete_time'])) {
                $data[$key]['delete_time'] = self::formateDate($temp);
            }
        }
        return $data;
    }

    public static function windowOpen($url)
    {
        echo "<script>window.open('{$url}', '_blank');</script>";
    }

    public static function windowReload()
    {
        echo "<script>window.location.reload();</script>";
    }


    /**
     * 0-1的随机数  小数点有很多位
     * @param int $min
     * @param int $max
     * @return float|int
     */
    public static function randomFloat($min = 0, $max = 1) {
        // lcg_value()函数返回范围为 (0, 1) 的一个伪随机数。
        return $min + mt_rand() / mt_getrandmax() * ($max - $min);
    }



    // todo: 公司工具方法类,
    // todo: 公司工具方法类,
    // todo: 公司工具方法类,
    // todo: 时间处理 默认时间和更闹心时间
    // todo: 时间处理 默认时间和更闹心时间
    // todo: 时间处理 默认时间和更闹心时间

}