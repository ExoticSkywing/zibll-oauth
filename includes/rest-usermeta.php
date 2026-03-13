<?php
/**
 * 用户 TG 绑定 REST 端点
 * 
 * 供外部应用通过 appid + appkey 鉴权读写 wp_usermeta 中的 _xingxy_telegram_uid。
 * 
 * POST /user/bindtg  — 精灵 Bot 绑定时写入 tg_uid
 * GET  /user/tgbind  — 空投机检查 TG 用户是否已绑定
 *
 * @package Zibll_Oauth
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Usermeta
{
    const META_KEY = '_xingxy_telegram_uid';

    /**
     * POST /user/bindtg
     * 
     * 将 TG user ID 写入 WordPress usermeta，使 WP 成为身份数据中心。
     * 
     * 参数（POST body）：
     *   - appid    (string, 必须) 应用 ID
     *   - openid   (string, 必须) 用户 OpenID（绑定时获取）
     *   - tg_uid   (int, 必须)    Telegram user ID
     *   - sign     (string, 必须) 签名 = md5(appid + openid + tg_uid + appkey)
     */
    public static function bindtg(WP_REST_Request $request)
    {
        $appid  = trim((string) $request->get_param('appid'));
        $openid = trim((string) $request->get_param('openid'));
        $tg_uid = trim((string) $request->get_param('tg_uid'));
        $sign   = trim((string) $request->get_param('sign'));

        if ($appid === '' || $openid === '' || $tg_uid === '' || $sign === '') {
            return new WP_Error('missing_param', '缺少必要参数', array('status' => 400));
        }

        if (!ctype_digit($tg_uid)) {
            return new WP_Error('invalid_tg_uid', 'tg_uid 必须为正整数', array('status' => 400));
        }

        // 验证应用
        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线', array('status' => 403));
        }

        $appkey = !empty($site['appkey']) ? (string) $site['appkey'] : '';
        if ($appkey === '') {
            return new WP_Error('app_config_error', '应用配置不完整', array('status' => 500));
        }

        // 验证签名：md5(appid + openid + tg_uid + appkey)
        $expected_sign = md5($appid . $openid . $tg_uid . $appkey);
        if (!hash_equals($expected_sign, $sign)) {
            return new WP_Error('invalid_sign', '签名验证失败', array('status' => 403));
        }

        // 通过 openid 查找 user_id
        $user_id = Zibll_Oauth_Provider_Util::get_user_id_by_openid($appid, $openid);
        if (!$user_id) {
            return new WP_Error('user_not_found', 'OpenID 对应的用户不存在', array('status' => 404));
        }

        // 写入 usermeta（使用 WordPress 原生函数，尊重 hooks 和缓存）
        update_user_meta($user_id, self::META_KEY, $tg_uid);

        return new WP_REST_Response(array(
            'success' => true,
            'user_id' => $user_id,
            'tg_uid'  => (int) $tg_uid,
            'message' => 'TG 绑定信息已写入',
        ), 200);
    }

    /**
     * GET /user/tgbind
     * 
     * 检查 TG 用户是否已绑定站点账号。
     * 
     * 参数（GET query）：
     *   - appid    (string, 必须) 应用 ID
     *   - tg_uid   (string, 必须) Telegram user ID
     *   - sign     (string, 必须) 签名 = md5(appid + tg_uid + appkey)
     */
    public static function tgbind(WP_REST_Request $request)
    {
        $appid  = trim((string) $request->get_param('appid'));
        $tg_uid = trim((string) $request->get_param('tg_uid'));
        $sign   = trim((string) $request->get_param('sign'));

        if ($appid === '' || $tg_uid === '' || $sign === '') {
            return new WP_Error('missing_param', '缺少必要参数', array('status' => 400));
        }

        // 验证应用
        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线', array('status' => 403));
        }

        $appkey = !empty($site['appkey']) ? (string) $site['appkey'] : '';
        if ($appkey === '') {
            return new WP_Error('app_config_error', '应用配置不完整', array('status' => 500));
        }

        // 验证签名：md5(appid + tg_uid + appkey)
        $expected_sign = md5($appid . $tg_uid . $appkey);
        if (!hash_equals($expected_sign, $sign)) {
            return new WP_Error('invalid_sign', '签名验证失败', array('status' => 403));
        }

        // 查询 usermeta：按 meta_value 反查
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s LIMIT 1",
            self::META_KEY,
            $tg_uid
        ));

        $bound = !empty($row);

        return new WP_REST_Response(array(
            'success' => true,
            'bound'   => $bound,
            'tg_uid'  => (int) $tg_uid,
            'user_id' => $bound ? (int) $row->user_id : null,
        ), 200);
    }
}
