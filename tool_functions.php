<?php

namespace tool;

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
    public static function music($music_num=4, $vdio_url='', $loop='no')
    {
        $music = [
            0=>'quekly',
            1=>'success',
            2=>'warning',
            3=>'prepare_to_buy',
            4=>'newChance',
            5=>'dingdong',
            6=>'teacher_new_message',
        ];
        // download from http://sc.chinaz.com/tag_yinxiao/tishiyin.html
        if ($loop=='yes' || $loop==1) {
//        if ($loop=='yes') {
//            echo('提示音: <audio autoplay loop><source src="./newChance.wav" ></audio>');
            echo('提示音: <audio autoplay loop><source src="../resource_plugins/'. $music[$music_num] . '.wav" ></audio>');
        } else {
//            echo('提示音: <audio autoplay><source src="../resource_plugins/newChance.wav" ></audio>');
            // echo('提示音: <audio autoplay><source src="../resource_plugins/'. $music[1] . '.wav" ></audio>');
            // echo('提示音: <audio autoplay><source src="../resource_plugins/'. $music[6] . '.wav" ></audio>');
            // echo('提示音: <audio autoplay><source src="../resource_plugins/'. $music[5] . '.wav" ></audio>');
            echo('提示音: <audio autoplay><source src="../resource_plugins/'. $music[$music_num] . '.wav" ></audio>');
            echo('提示音: <audio autoplay><source src="F:/wamp/www/resource_plugins/'. $music[$music_num] . '.wav" ></audio>');
                    var_dump(__FILE__);

            echo('提示音: <audio autoplay><source src="../../resource_plugins/'. $music[$music_num] . '.wav" ></audio>');
        }
        var_dump('提示音含义: ' . $music[$music_num]);


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
//         if ($loop=='yes' || $loop==1) {
// //        if ($loop=='yes') {
// //            echo('提示音: <audio autoplay loop><source src="./newChance.wav" ></audio>');
//             echo('提示音: <audio autoplay loop><source src="F:/wamp/www/resource_plugins/'. $music[$music_num] . '" ></audio>');
//         } else {
// //            echo('提示音: <audio autoplay><source src="../resource_plugins/newChance" ></audio>');
//             echo('提示音: <audio autoplay><source src="F:/wamp/www/resource_plugins/'. $music[$music_num] . '" ></audio>');
//             echo('提示音: <audio autoplay><source src="F:\wamp\www\resource_plugins\teacher_new_message.wav" ></audio>');
//             echo('提示音: <audio autoplay><source src="F:/wamp/www/resource_plugins/teacher_new_message.wav" ></audio>');
//         }
//         var_dump('提示音含义: ' . $music[$music_num]);

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
            file_put_contents($file_nme, $content);
        } else {
            file_put_contents($file_nme, $content, FILE_APPEND);
        }
        return 1;
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
    public static function freshPage($alert=0, $msg='刷新页面'){
//    public static function freshPage($alert=0){
        // echo "window.location.reload()";

        if ($alert) {
//                        echo "<script language=\"javascript\"> alert ('" . $msg . "');</script>";
//                        sleep(2);
//                        var_dump(25);exit();
//            echo "<script language=\"javascript\"> alert ('2266');</script>";
//            var_dump(223);exit();
        }
//        var_dump(22);

        // alert('定时刷新');
        echo "<script language=\"javascript\"> window.location.reload();</script>";
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
    public static function headericonv($str='') {
        header("Content-Type: text/html;charset=utf-8");
    }
}