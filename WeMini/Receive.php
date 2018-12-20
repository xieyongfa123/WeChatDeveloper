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

use WeChat\Contracts\BasicPushEvent;

/**
 * 小程序推送管理
 * Class Receive
 * @package WeChat
 */
class Receive extends BasicPushEvent
{

    /**
     * 转发多客服消息
     * @param string $account
     * @return $this
     */
    public function transferCustomerService($account = '')
    {
        $this->message = [
            'CreateTime'   => time(),
            'ToUserName'   => $this->getOpenid(),
            'FromUserName' => $this->getToOpenid(),
            'MsgType'      => 'transfer_customer_service',
        ];
        empty($account) || $this->message['TransInfo'] = ['KfAccount' => $account];
        return $this;
    }

    /**
     * 设置文本消息
     * @param string $content 文本内容
     * @return $this
     */
    public function text($content = '')
    {
        $this->message = [
            'touser'  => $this->getOpenid(),
            'msgtype' => 'text',
            'text'    => ['content' => $content]
        ];
        return $this;
    }

    /**
     * 设置图文链接
     * @param string $title 消息标题
     * @param string $description 图文链接消息
     * @param string $url 图文链接消息被点击后跳转的链接
     * @param string $thumb_url 图文链接消息的图片链接，支持 JPG、PNG 格式，较好的效果为大图 640 X 320，小图 80 X 80
     * @return $this
     */
    public function link($title, $description, $url, $thumb_url)
    {
        $this->message = [
            'touser'  => $this->getOpenid(),
            'msgtype' => 'link',
            'link'    => [
                'title'       => $title,
                'description' => $description,
                'url'         => $url,
                'thumb_url'   => $thumb_url
            ],
        ];
        return $this;
    }

    /**
     * 设置小程序卡片
     * @param string $title 消息标题
     * @param string $pagepath 小程序的页面路径，跟app.json对齐，支持参数，比如pages/index/index?foo=bar
     * @param string $thumb_media_id 小程序消息卡片的封面， image 类型的 media_id，通过 新增素材接口 上传图片文件获得，建议大小为 520*416
     * @return $this
     */
    public function miniprogrampage($title, $pagepath, $thumb_media_id)
    {
        $this->message = [
            'touser'          => $this->getOpenid(),
            'msgtype'         => 'miniprogrampage',
            'miniprogrampage' => [
                'title'          => $title,
                'pagepath'       => $pagepath,
                'thumb_media_id' => $thumb_media_id
            ],
        ];
        return $this;
    }

    /**
     * 设置图片消息
     * @param string $mediaId 发送的图片的媒体ID，通过 新增素材接口 上传图片文件获得。
     * @return $this
     */
    public function image($mediaId)
    {
        $this->message = [
            'touser'  => $this->getOpenid(),
            'msgtype' => 'image',
            'image'   => ['media_id' => $mediaId],
        ];
        return $this;
    }
}