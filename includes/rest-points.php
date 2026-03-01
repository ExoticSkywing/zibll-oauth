<?php
/**
 * 积分充值 REST 端点
 * 
 * 供外部应用（如 TG Bot）通过 appid + appkey 鉴权给用户充值站点积分。
 * 内部调用 zibpay_update_user_points() 实现积分变动。
 * 
 * 使用服务端鉴权（appid + appkey），不依赖用户 access_token。
 *
 * @package Zibll_Oauth
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Points
{
    /**
     * POST /points/add
     * 
     * 参数（POST body）：
     *   - appid    (string, 必须) 应用 ID
     *   - openid   (string, 必须) 用户 OpenID（绑定时获取）
     *   - amount   (int, 必须, >0) 充值积分数量
     *   - desc     (string, 可选) 说明
     *   - sign     (string, 必须) 签名 = md5(appid + openid + amount + appkey)
     */
    public static function add(WP_REST_Request $request)
    {
        // 1. 参数提取
        $appid  = trim((string) $request->get_param('appid'));
        $openid = trim((string) $request->get_param('openid'));
        $amount = (int) $request->get_param('amount');
        $desc   = trim((string) $request->get_param('desc'));
        $sign   = trim((string) $request->get_param('sign'));

        // 2. 基础参数校验
        if ($appid === '' || $openid === '' || $sign === '') {
            return new WP_Error('missing_param', '缺少必要参数', array('status' => 400));
        }

        if ($amount <= 0) {
            return new WP_Error('invalid_amount', '积分数量必须大于0', array('status' => 400));
        }

        if ($amount > 10000) {
            return new WP_Error('amount_too_large', '单次充值不能超过10000积分', array('status' => 400));
        }

        // 3. 验证应用
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

        // 4. 验证签名：md5(appid + openid + amount + appkey)
        $expected_sign = md5($appid . $openid . $amount . $appkey);
        if (!hash_equals($expected_sign, $sign)) {
            return new WP_Error('invalid_sign', '签名验证失败', array('status' => 403));
        }

        // 5. 通过 openid 查找 user_id（参数顺序：appid, openid）
        $user_id = Zibll_Oauth_Provider_Util::get_user_id_by_openid($appid, $openid);

        if (!$user_id) {
            return new WP_Error('user_not_found', 'OpenID 对应的用户不存在', array('status' => 404));
        }

        // 6. 检查积分函数是否可用
        if (!function_exists('zibpay_update_user_points')) {
            return new WP_Error('points_unavailable', '积分系统未启用', array('status' => 503));
        }

        // 7. 执行积分充值
        if ($desc === '') {
            $desc = 'TG Bot 积分兑换';
        }

        $points_data = array(
            'value' => $amount,
            'type'  => 'TG兑换',
            'desc'  => $desc,
        );
        zibpay_update_user_points($user_id, $points_data);

        // 8. 获取充值后的积分余额
        $new_points = 0;
        if (function_exists('zibpay_get_user_points')) {
            $new_points = zibpay_get_user_points($user_id);
        }

        return new WP_REST_Response(array(
            'success' => true,
            'user_id' => $user_id,
            'amount'  => $amount,
            'points'  => $new_points,
            'message' => '积分充值成功',
        ), 200);
    }

    /**
     * GET /points/balance
     * 
     * 查询用户站点积分余额
     * 
     * 参数（GET query）：
     *   - appid    (string, 必须) 应用 ID
     *   - openid   (string, 必须) 用户 OpenID
     *   - sign     (string, 必须) 签名 = md5(appid + openid + appkey)
     */
    public static function balance(WP_REST_Request $request)
    {
        // 1. 参数提取
        $appid  = trim((string) $request->get_param('appid'));
        $openid = trim((string) $request->get_param('openid'));
        $sign   = trim((string) $request->get_param('sign'));

        // 2. 基础参数校验
        if ($appid === '' || $openid === '' || $sign === '') {
            return new WP_Error('missing_param', '缺少必要参数', array('status' => 400));
        }

        // 3. 验证应用
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

        // 4. 验证签名：md5(appid + openid + appkey)
        $expected_sign = md5($appid . $openid . $appkey);
        if (!hash_equals($expected_sign, $sign)) {
            return new WP_Error('invalid_sign', '签名验证失败', array('status' => 403));
        }

        // 5. 通过 openid 查找 user_id
        $user_id = Zibll_Oauth_Provider_Util::get_user_id_by_openid($appid, $openid);
        if (!$user_id) {
            return new WP_Error('user_not_found', 'OpenID 对应的用户不存在', array('status' => 404));
        }

        // 6. 查询积分余额
        $points = 0;
        if (function_exists('zibpay_get_user_points')) {
            $points = zibpay_get_user_points($user_id);
        }

        return new WP_REST_Response(array(
            'success' => true,
            'user_id' => $user_id,
            'points'  => $points,
        ), 200);
    }
}
