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

namespace WeMini;

use WeChat\Contracts\BasicWeChat;
use WeChat\Contracts\Tools;
use WeChat\Exceptions\InvalidDecryptException;
use WeChat\Exceptions\InvalidResponseException;


/**
 * 数据加密处理
 * Class Crypt
 * @package WeMini
 */
class Crypt extends BasicWeChat
{

    /**
     * 数据签名校验
     * @param string $iv
     * @param string $sessionKey
     * @param string $encryptedData
     * @return bool
     */
    public function decode($iv, $sessionKey, $encryptedData)
    {
        require_once __DIR__ . DIRECTORY_SEPARATOR . 'crypt' . DIRECTORY_SEPARATOR . 'wxBizDataCrypt.php';
        $pc      = new \WXBizDataCrypt($this->config->get('appid'), $sessionKey);
        $errCode = $pc->decryptData($encryptedData, $iv, $data);
        if ($errCode == 0) {
            return json_decode($data, true);
        }
        wr_log('解密失败:code=' . $errCode . 'iv=' . $iv . 'sessionKey=' . $sessionKey . 'encryptedData=' . $encryptedData);
        return false;
    }

    /**
     * 登录凭证校验
     * @param string $code 登录时获取的 code
     * @return array
     */
    public function session($code)
    {
        $appid = $this->config->get('appid');
        if ($this->isAuthorized()) {
            $open = $this->getOpenService();
            return $open->jsCodeToSession($code, $appid);
        }
        $secret = $this->config->get('appsecret');
        $url    = "https://api.weixin.qq.com/sns/jscode2session?appid={$appid}&secret={$secret}&js_code={$code}&grant_type=authorization_code";
        return json_decode(Tools::get($url), true);
    }

    /**
     * 换取用户信息
     * @param string $code 用户登录凭证（有效期五分钟）
     * @param string $iv 加密算法的初始向量
     * @param string $encryptedData 加密数据( encryptedData )
     * @return array
     * @throws InvalidDecryptException
     * @throws InvalidResponseException
     */
    public function userInfo($code, $iv, $encryptedData)
    {
        $result = $this->session($code);
        if (empty($result['session_key'])) {
            throw new InvalidResponseException('Code 换取 SessionKey 失败', 403);
        }
        $userinfo = $this->decode($iv, $result['session_key'], $encryptedData);
        if (empty($userinfo)) {
            throw  new InvalidDecryptException('用户信息解析失败', 403);
        }
        return array_merge($result, $userinfo);
    }

    /**
     * 获取解密数据
     * @param string $code 用户登录凭证（有效期五分钟）
     * @param string $iv 加密算法的初始向量
     * @param string $encryptedData 加密数据( encryptedData )
     * @return array|string
     * @throws InvalidDecryptException
     * @throws InvalidResponseException
     */
    public function decodeData($code, $iv, $encryptedData)
    {
        if ($encryptedData == 'undefined' || $iv == 'undefined') {
            $msg = '小程序用户信息获取失败,encrypted_data或者iv为undefined，code=' . $code;
            wr_log($msg);
            return $msg;
            //throw new InvalidResponseException($msg, 403);
        }
        $cache_key = 'code:' . md5($code . $encryptedData . $iv);
        if ($result = cache($cache_key)) {
            return (array)$result;
        }
        $result = $this->session($code);
        if (empty($result['session_key']) || empty($result['openid'])) {
            $msg = 'Code 换取 SessionKey 失败,session_key或者openid为空，code=' . $code;
            wr_log($msg);
            return $msg;
            //throw new InvalidResponseException($msg, 403);
        }
        $decode_result = $this->decode($iv, $result['session_key'], $encryptedData);
        if ($decode_result === false) {
            $db_api_log        = new \app\common\model\ApiLog();
            $session_key_array = $db_api_log->getSessionKey($result['openid']);
            foreach ($session_key_array as $key => $val) {
                $decode_result = $this->decode($iv, $val, $encryptedData);
                if ($decode_result !== false) {
                    wr_log('iv:' . $iv . '通过新sessionKey:' . $val . '解密成功');
                    break;
                }
            }
            if ($decode_result === false) {
                $msg = '用户信息解析失败，code=' . $code;
                wr_log($msg);
                return $msg;
                //throw new InvalidDecryptException($msg, 403);
            }
        }
        $result = array_merge($result, $decode_result);
        cache($cache_key, $result, 60);
        return (array)$result;
    }
}