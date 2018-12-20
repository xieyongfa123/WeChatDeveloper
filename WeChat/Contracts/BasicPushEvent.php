<?php

// +----------------------------------------------------------------------
// | WeChatDeveloper
// +----------------------------------------------------------------------
// | 版权所有 2014~2018 广州楚才信息科技有限公司 [ http://www.cuci.cc ]
// +----------------------------------------------------------------------
// | 官方网站: http://think.ctolog.com
// +----------------------------------------------------------------------
// | 开源协议 ( https://mit-license.org )
// +----------------------------------------------------------------------
// | github开源项目：https://github.com/zoujingli/WeChatDeveloper
// +----------------------------------------------------------------------

namespace WeChat\Contracts;

use WeChat\Exceptions\InvalidArgumentException;
use WeChat\Exceptions\InvalidDecryptException;
use WeChat\Exceptions\InvalidResponseException;

/**
 * 微信通知处理基本类
 * Class BasicPushEvent
 * @package WeChat\Contracts
 */
class BasicPushEvent
{
    /**
     * 公众号APPID
     * @var string
     */
    protected $appid;

    /**
     * 公众号推送XML内容
     * @var string
     */
    protected $postxml;

    /**
     * 公众号推送加密类型
     * @var string
     */
    protected $encryptType;

    /**
     * 公众号的推送请求参数
     * @var DataArray
     */
    public $config;

    /**
     * 公众号的推送请求参数
     * @var DataArray
     */
    protected $input;

    /**
     * 公众号推送内容对象
     * @var DataArray
     */
    protected $receive;

    /**
     * 准备回复的消息内容
     * @var array
     */
    protected $message;
    /**
     * 是否使用密钥
     * @var array
     */
    protected $is_encodingaeskey = false;

    /**
     * BasicPushEvent constructor.
     * @param array $options
     * @throws InvalidResponseException
     */
    public function __construct(array $options)
    {
        if (empty($options['appid'])) {
            throw new InvalidArgumentException("Missing Config -- [appid]");
        }
//        if (!isset($options['appsecret'])) {
//            throw new InvalidArgumentException("Missing Config -- [appsecret]");
//        }
//        if (!isset($options['token'])) {
//            throw new InvalidArgumentException("Missing Config -- [token]");
//        }
        // 参数初始化
        $this->config = new DataArray($options);
        $this->params = new DataArray($_REQUEST);
        $this->appid = $this->config->get('appid');
        // 推送消息处理
        if ($_SERVER['REQUEST_METHOD'] == "POST") {
            $this->postxml     = file_get_contents("php://input");
            $result            = Tools::xml2arr($this->postxml);
            $this->encryptType = $this->params->get('encrypt_type');
            if ($this->isEncrypt()) {
                if (!class_exists('Prpcrypt', false)) {
                    require __DIR__ . '/Prpcrypt.php';
                }
                //优先用平台密钥解密
                $prpcrypt = new \Prpcrypt($this->config->get('component_encodingaeskey'));
                $array    = $prpcrypt->decrypt($result['Encrypt']);
                if (intval($array[0]) > 0) {
                    throw new InvalidResponseException($array[1], $array[0]);
                }
                list($this->postxml, $this->appid) = [$array[1], $array[2]];
                if (!tools()::xml_parser($this->postxml)) {
                    //解密失败后判断如果有商户密钥 则继续尝试解密
                    if (empty($options['encodingaeskey'])) {
                        throw new InvalidArgumentException("Missing Config -- [encodingaeskey]");
                    }
                    $prpcrypt = new \Prpcrypt($this->config->get('encodingaeskey'));
                    $array    = $prpcrypt->decrypt($result['Encrypt']);
                    if (intval($array[0]) > 0) {
                        throw new InvalidResponseException($array[1], $array[0]);
                    }
                    list($this->postxml, $this->appid) = [$array[1], $array[2]];
                    $this->is_encodingaeskey = true;
                }
                $array         = Tools::xml2arr($this->postxml) ?: Tools::xml2arr(tools()::emoji_encode($this->postxml, true));
                $this->receive = new DataArray($array);
            }
        } elseif ($_SERVER['REQUEST_METHOD'] == "GET" && $this->checkSignature()) {
            @ob_clean();
            exit($this->params->get('echostr'));
        } else {
            throw new InvalidResponseException('Invalid interface request.', '0');
        }
    }
    /**
     * 消息是否需要加密
     * @return boolean
     */
    public function isEncrypt()
    {
        return $this->encryptType === 'aes';
    }

    /**
     * 回复消息
     * @param array $data 消息内容
     * @param bool $return 是否返回XML内容
     * @param boolean $isEncrypt 是否加密内容
     * @return string
     * @throws InvalidDecryptException
     */
    public function reply(array $data = [], $return = false, $isEncrypt = false)
    {
        $reply_data = empty($data) ? $this->message : $data;
        if (empty($reply_data['CreateTime'])) {
            //如果不包含 CreateTime 则认为是发送客服消息,否则输出xml
            $app = weixin($this->config->get('appid'))::WeChatCustom();
            $app->send($reply_data);
            exit('success');
        }
        $xml = Tools::arr2xml($reply_data);
        if ($this->isEncrypt() || $isEncrypt) {
            if (!class_exists('Prpcrypt', false)) {
                require __DIR__ . '/Prpcrypt.php';
            }
            $encodingaeskey = $this->is_encodingaeskey ? $this->config->get('encodingaeskey') : $this->config->get('component_encodingaeskey');
            $prpcrypt       = new \Prpcrypt($encodingaeskey);
            // 如果是第三方平台，加密得使用 component_appid
            $component_appid = $this->config->get('component_appid');
            // $appid = $this->config->get('authorized') ? $component_appid : $this->appid;
            $appid = $this->is_encodingaeskey ? $this->appid : $component_appid;
            $array = $prpcrypt->encrypt($xml, $appid);
            if ($array[0] > 0) {
                throw new InvalidDecryptException('Encrypt Error.', '0');
            }
            list($timestamp, $encrypt) = [time(), $array[1]];
            $nonce  = rand(77, 999) * rand(605, 888) * rand(11, 99);
            $token  = $this->is_encodingaeskey ? $this->config->get('token') : $this->config->get('component_token');
            $tmpArr = [$token, $timestamp, $nonce, $encrypt];
            sort($tmpArr, SORT_STRING);
            $signature = sha1(implode($tmpArr));
            $format    = "<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp>%s</TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>";
            $xml       = sprintf($format, $encrypt, $signature, $timestamp, $nonce);
        }
        if ($return) {
            return $xml;
        }
        @ob_clean();
        echo $xml;
    }

    /**
     * 验证来自微信服务器
     * @param string $str
     * @return bool
     */
    private function checkSignature($str = '')
    {
        $nonce = $this->params->get('nonce');
        $timestamp = $this->params->get('timestamp');
        $msg_signature = $this->params->get('msg_signature');
        $signature = empty($msg_signature) ? $this->params->get('signature') : $msg_signature;
        $tmpArr = [$this->config->get('token'), $timestamp, $nonce, $str];
        sort($tmpArr, SORT_STRING);
        if (sha1(implode($tmpArr)) == $signature) {
            return true;
        }
        return false;
    }
    /**
     * 获取微信服务器发来的内容
     * @return $this
     */
    public function getRev()
    {
        if ($this->receive) {
            return $this;
        }
        $postStr = !empty($this->postxml) ? $this->postxml : file_get_contents("php://input");
        !empty($postStr) && $this->receive = (array)simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
        return $this;
    }

    /**
     * 获取微信服务器发来的信息数据
     * @return array
     */
    public function getRevData()
    {
        return $this->receive;
    }
    /**
     * 获取公众号推送对象
     * @param null|string $field 指定获取字段
     * @return array
     */
    public function getReceive($field = null)
    {
        return $this->receive->get($field);
    }

    /**
     * 获取当前微信OPENID
     * @return string
     */
    public function getOpenid()
    {
        return $this->receive->get('FromUserName');
    }

    /**
     * 获取当前推送消息类型
     * @return string
     */
    public function getMsgType()
    {
        return $this->receive->get('MsgType');
    }

    /**
     * 获取当前推送消息ID
     * @return string
     */
    public function getMsgId()
    {
        return $this->receive->get('MsgId');
    }

    /**
     * 获取当前推送时间
     * @return integer
     */
    public function getMsgTime()
    {
        return $this->receive->get('CreateTime');
    }

    /**
     * 获取当前推送公众号
     * @return string
     */
    public function getToOpenid()
    {
        return $this->receive->get('ToUserName');
    }

    /**
     * 获取卡券事件推送 - 卡卷审核是否通过
     * 当Event为 card_pass_check(审核通过) 或 card_not_pass_check(未通过)
     * @return bool|string  返回卡券ID
     */
    public function getRevCardPass()
    {
        return (isset($this->receive['CardId'])) ? $this->receive['CardId'] : false;
    }

    /**
     * 获取卡券事件推送 - 领取卡券
     * 当Event为 user_get_card(用户领取卡券)
     * @return bool|array
     */
    public function getRevCardGet()
    {
        $array = [];
        if (isset($this->receive['CardId'])) {
            $array['CardId'] = $this->receive['CardId'];
        }
        if (isset($this->receive['IsGiveByFriend'])) {
            $array['IsGiveByFriend'] = $this->receive['IsGiveByFriend'];
        }
        $array['OldUserCardCode'] = $this->receive['OldUserCardCode'];
        if (isset($this->receive['UserCardCode']) && !empty($this->receive['UserCardCode'])) {
            $array['UserCardCode'] = $this->receive['UserCardCode'];
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取卡券事件推送 - 删除卡券
     * 当Event为 user_del_card (用户删除卡券)
     * @return bool|array
     */
    public function getRevCardDel()
    {
        if (isset($this->receive['CardId'])) {  //卡券 ID
            $array['CardId'] = $this->receive['CardId'];
        }
        if (isset($this->receive['UserCardCode']) && !empty($this->receive['UserCardCode'])) {
            $array['UserCardCode'] = $this->receive['UserCardCode'];
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取接收消息内容正文
     * @return bool
     */
    public function getRevContent()
    {
        if (isset($this->receive['Content'])) {
            return $this->receive['Content'];
        } else if (isset($this->receive['Recognition'])) {
            return $this->receive['Recognition'];
        }
        return false;
    }

    /**
     * 获取接收消息图片
     * @return array|bool
     */
    public function getRevPic()
    {
        if (isset($this->receive['PicUrl'])) {
            return [
                'mediaid' => $this->receive['MediaId'],
                'picurl'  => (string)$this->receive['PicUrl'],
            ];
        }
        return false;
    }

    /**
     * 获取接收消息链接
     * @return bool|array
     */
    public function getRevLink()
    {
        if (isset($this->receive['Url'])) {
            return [
                'url'         => $this->receive['Url'],
                'title'       => $this->receive['Title'],
                'description' => $this->receive['Description']
            ];
        }
        return false;
    }

    /**
     * 获取接收地理位置
     * @return bool|array
     */
    public function getRevGeo()
    {
        if (isset($this->receive['Location_X'])) {
            return [
                'x'     => $this->receive['Location_X'],
                'y'     => $this->receive['Location_Y'],
                'scale' => $this->receive['Scale'],
                'label' => $this->receive['Label']
            ];
        }
        return false;
    }

    /**
     * 获取上报地理位置事件
     * @return bool|array
     */
    public function getRevEventGeo()
    {
        if (isset($this->receive['Latitude'])) {
            return [
                'x'         => $this->receive['Latitude'],
                'y'         => $this->receive['Longitude'],
                'precision' => $this->receive['Precision'],
            ];
        }
        return false;
    }

    /**
     * 获取接收事件推送
     * @return bool|array
     */
    public function getRevEvent()
    {
        if (isset($this->receive['Event'])) {
            $array['event'] = $this->receive['Event'];
        }
        if (isset($this->receive['EventKey'])) {
            $array['key'] = $this->receive['EventKey'];
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取自定义菜单的扫码推事件信息
     *
     * 事件类型为以下两种时则调用此方法有效
     * Event    事件类型, scancode_push
     * Event    事件类型, scancode_waitmsg
     * @return bool|array
     */
    public function getRevScanInfo()
    {
        if (isset($this->receive['ScanCodeInfo'])) {
            if (!is_array($this->receive['ScanCodeInfo'])) {
                $array = (array)$this->receive['ScanCodeInfo'];
                $this->receive['ScanCodeInfo'] = $array;
            } else {
                $array = $this->receive['ScanCodeInfo'];
            }
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取自定义菜单的图片发送事件信息
     *
     * 事件类型为以下三种时则调用此方法有效
     * Event     事件类型，pic_sysphoto        弹出系统拍照发图的事件推送
     * Event     事件类型，pic_photo_or_album  弹出拍照或者相册发图的事件推送
     * Event     事件类型，pic_weixin          弹出微信相册发图器的事件推送
     *
     * @return bool|array
     * array (
     *   'Count' => '2',
     *   'PicList' =>array (
     *         'item' =>array (
     *             0 =>array ('PicMd5Sum' => 'aaae42617cf2a14342d96005af53624c'),
     *             1 =>array ('PicMd5Sum' => '149bd39e296860a2adc2f1bb81616ff8'),
     *         ),
     *   ),
     * )
     *
     */
    public function getRevSendPicsInfo()
    {
        if (isset($this->receive['SendPicsInfo'])) {
            if (!is_array($this->receive['SendPicsInfo'])) {
                $array = (array)$this->receive['SendPicsInfo'];
                if (isset($array['PicList'])) {
                    $array['PicList'] = (array)$array['PicList'];
                    $item = $array['PicList']['item'];
                    $array['PicList']['item'] = [];
                    foreach ($item as $key => $value) {
                        $array['PicList']['item'][$key] = (array)$value;
                    }
                }
                $this->receive['SendPicsInfo'] = $array;
            } else {
                $array = $this->receive['SendPicsInfo'];
            }
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取自定义菜单的地理位置选择器事件推送
     *
     * 事件类型为以下时则可以调用此方法有效
     * Event     事件类型，location_select        弹出地理位置选择器的事件推送
     *
     * @return bool|array
     * array (
     *   'Location_X' => '33.731655000061',
     *   'Location_Y' => '113.29955200008047',
     *   'Scale' => '16',
     *   'Label' => '某某市某某区某某路',
     *   'Poiname' => '',
     * )
     *
     */
    public function getRevSendGeoInfo()
    {
        if (isset($this->receive['SendLocationInfo'])) {
            if (!is_array($this->receive['SendLocationInfo'])) {
                $array = (array)$this->receive['SendLocationInfo'];
                if (empty($array['Poiname'])) {
                    $array['Poiname'] = "";
                }
                if (empty($array['Label'])) {
                    $array['Label'] = "";
                }
                $this->receive['SendLocationInfo'] = $array;
            } else {
                $array = $this->receive['SendLocationInfo'];
            }
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取接收语音推送
     * @return bool|array
     */
    public function getRevVoice()
    {
        if (isset($this->receive['MediaId'])) {
            return [
                'mediaid' => $this->receive['MediaId'],
                'format'  => $this->receive['Format'],
            ];
        }
        return false;
    }

    /**
     * 获取接收视频推送
     * @return array|bool
     */
    public function getRevVideo()
    {
        if (isset($this->receive['MediaId'])) {
            return [
                'mediaid'      => $this->receive['MediaId'],
                'thumbmediaid' => $this->receive['ThumbMediaId']
            ];
        }
        return false;
    }

    /**
     * 获取接收TICKET
     * @return bool|string
     */
    public function getRevTicket()
    {
        return (isset($this->receive['Ticket'])) ? $this->receive['Ticket'] : false;
    }

    /**
     * 获取二维码的场景值
     * @return bool|string
     */
    public function getRevSceneId()
    {
        if (isset($this->receive['EventKey'])) {
            return str_replace('qrscene_', '', $this->receive['EventKey']);
        }
        return false;
    }

    /**
     * 获取主动推送的消息ID
     * 经过验证，这个和普通的消息MsgId不一样
     * 当Event为 MASSSENDJOBFINISH 或 TEMPLATESENDJOBFINISH
     * @return bool|string
     */
    public function getRevTplMsgID()
    {
        return (isset($this->receive['MsgID'])) ? $this->receive['MsgID'] : false;
    }

    /**
     * 获取模板消息发送状态
     * @return bool|string
     */
    public function getRevStatus()
    {
        return (isset($this->receive['Status'])) ? $this->receive['Status'] : false;
    }

    /**
     * 获取群发或模板消息发送结果
     * 当Event为 MASSSENDJOBFINISH 或 TEMPLATESENDJOBFINISH，即高级群发/模板消息
     * @return bool|array
     */
    public function getRevResult()
    {
        if (isset($this->receive['Status'])) { //发送是否成功，具体的返回值请参考 高级群发/模板消息 的事件推送说明
            $array['Status'] = $this->receive['Status'];
        }
        if (isset($this->receive['MsgID'])) { //发送的消息id
            $array['MsgID'] = $this->receive['MsgID'];
        }
        //以下仅当群发消息时才会有的事件内容
        if (isset($this->receive['TotalCount'])) {  //分组或openid列表内粉丝数量
            $array['TotalCount'] = $this->receive['TotalCount'];
        }
        if (isset($this->receive['FilterCount'])) { //过滤（过滤是指特定地区、性别的过滤、用户设置拒收的过滤，用户接收已超4条的过滤）后，准备发送的粉丝数
            $array['FilterCount'] = $this->receive['FilterCount'];
        }
        if (isset($this->receive['SentCount'])) {  //发送成功的粉丝数
            $array['SentCount'] = $this->receive['SentCount'];
        }
        if (isset($this->receive['ErrorCount'])) { //发送失败的粉丝数
            $array['ErrorCount'] = $this->receive['ErrorCount'];
        }
        if (isset($array) && count($array) > 0) {
            return $array;
        }
        return false;
    }

    /**
     * 获取多客服会话状态推送事件 - 接入会话
     * 当Event为 kfcreatesession 即接入会话
     * @return bool|string
     */
    public function getRevKFCreate()
    {
        if (isset($this->receive['KfAccount'])) {
            return $this->receive['KfAccount'];
        }
        return false;
    }

    /**
     * 获取多客服会话状态推送事件 - 关闭会话
     * 当Event为 kfclosesession 即关闭会话
     * @return bool|string
     */
    public function getRevKFClose()
    {
        if (isset($this->receive['KfAccount'])) {
            return $this->receive['KfAccount'];
        }
        return false;
    }

    /**
     * 获取多客服会话状态推送事件 - 转接会话
     * 当Event为 kfswitchsession 即转接会话
     * @return bool|array
     */
    public function getRevKFSwitch()
    {
        if (isset($this->receive['FromKfAccount'])) {  //原接入客服
            $array['FromKfAccount'] = $this->receive['FromKfAccount'];
        }
        if (isset($this->receive['ToKfAccount'])) { //转接到客服
            $array['ToKfAccount'] = $this->receive['ToKfAccount'];
        }
        return (isset($array) && count($array) > 0) ? $array : false;
    }

    /**
     * 获取待回复的消息体
     * @return bool|array
     */
    public function getMessage()
    {
        return $this->message;
    }
}