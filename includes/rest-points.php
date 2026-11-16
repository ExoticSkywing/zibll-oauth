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
        // A points credit requires a durable order identity and an explicit
        // per-app points-write capability. finance_enabled is unrelated to
        // this route and must never grant it implicitly.
        $appid_raw = $request->get_param('appid');
        $openid_raw = $request->get_param('openid');
        $amount_raw = $request->get_param('amount');
        $desc_raw = $request->get_param('desc');
        $order_raw = $request->get_param('order_no');
        $version_raw = $request->get_param('sign_version');
        $sign_raw = $request->get_param('sign');

        $appid = is_string($appid_raw) || is_int($appid_raw) ? trim((string) $appid_raw) : '';
        $openid = is_string($openid_raw) || is_int($openid_raw) ? trim((string) $openid_raw) : '';
        $desc = is_string($desc_raw) ? trim($desc_raw) : '';
        $order_no = is_string($order_raw) ? trim($order_raw) : '';
        $sign_version = is_string($version_raw) ? trim($version_raw) : '';
        $sign = is_string($sign_raw) ? trim($sign_raw) : '';

        $amount = null;
        if (is_int($amount_raw)) {
            $amount = $amount_raw;
        } elseif (is_string($amount_raw) && preg_match('/\A(?:[1-9][0-9]{0,3}|10000)\z/', trim($amount_raw)) === 1) {
            $amount = (int) trim($amount_raw);
        }

        if ($appid === '' || $openid === '' || $order_no === '' || $desc === ''
            || $sign_version !== '2' || $sign === '') {
            return new WP_Error('invalid_request', '缺少必要的 v2 积分请求参数', array('status' => 400));
        }
        if (!is_int($amount) || $amount <= 0) {
            return new WP_Error('invalid_amount', '积分数量必须大于0', array('status' => 400));
        }
        if ($amount > 10000) {
            return new WP_Error('amount_too_large', '单次充值不能超过10000积分', array('status' => 400));
        }
        if (preg_match('/\A[A-Za-z0-9._:-]{1,128}\z/', $order_no) !== 1) {
            return new WP_Error('invalid_order_no', '订单号格式无效', array('status' => 400));
        }
        if (strlen($desc) > 255 || strpos($desc, "\0") !== false || preg_match('//u', $desc) !== 1) {
            return new WP_Error('invalid_description', '说明格式无效', array('status' => 400));
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效', array('status' => 403));
        }
        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线', array('status' => 403));
        }
        if (!method_exists('Zibll_Oauth_Provider_Util', 'client_ip')
            || !method_exists('Zibll_Oauth_Provider_Util', 'is_ip_allowed_for_site')) {
            return new WP_Error('points_unavailable', '应用访问策略暂不可用，请稍后重试', array('status' => 503));
        }
        $client_ip = Zibll_Oauth_Provider_Util::client_ip();
        if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
            return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403));
        }

        // The app table has no points-specific column. Keep this capability
        // explicit and deny by default through the existing OAuth options
        // record, with a filter for deployments that manage app policy in code.
        $configured_appids = '';
        if (class_exists('Zibll_Oauth_Options')
            && method_exists('Zibll_Oauth_Options', 'get')) {
            $configured_appids = Zibll_Oauth_Options::get('zibll_oauth_points_write_appids', '');
        }
        $configured_appids = is_array($configured_appids)
            ? $configured_appids
            : preg_split('/\r\n|\r|\n|,/', (string) $configured_appids);
        $points_write_allowed = false;
        foreach ((array) $configured_appids as $configured_appid) {
            if (is_string($configured_appid) && trim($configured_appid) === $appid) {
                $points_write_allowed = true;
                break;
            }
        }
        if (function_exists('apply_filters')) {
            $points_write_allowed = (bool) apply_filters(
                'zibll_oauth_points_write_allowed',
                $points_write_allowed,
                $appid,
                $site,
                $request
            );
        }
        if (!$points_write_allowed) {
            return new WP_Error('points_write_not_allowed', '应用未获积分写入权限', array('status' => 403));
        }

        $appkey = !empty($site['appkey']) ? (string) $site['appkey'] : '';
        if ($appkey === '') {
            return new WP_Error('app_config_error', '应用配置不完整', array('status' => 500));
        }

        // v2 wire format: length-prefixed UTF-8 fields prevent concatenation
        // ambiguity and HMAC-SHA256 avoids the legacy MD5 construction.
        $signed_fields = array($appid, $openid, (string) $amount, $order_no, $desc);
        $wire_fields = array();
        foreach ($signed_fields as $field) {
            $wire_fields[] = strlen($field) . ':' . $field;
        }
        $signed_payload = "xingxy-points-add-v2\n" . implode("\n", $wire_fields);
        $expected_sign = hash_hmac('sha256', $signed_payload, $appkey);
        if (!hash_equals($expected_sign, $sign)) {
            return new WP_Error('invalid_sign', '签名验证失败', array('status' => 403));
        }

        $user_id = Zibll_Oauth_Provider_Util::get_user_id_by_openid($appid, $openid);
        if (!$user_id) {
            return new WP_Error('user_not_found', 'OpenID 对应的用户不存在', array('status' => 404));
        }
        if (!function_exists('apply_filters')) {
            return new WP_Error('points_unavailable', '统一积分账本未启用', array('status' => 503));
        }

        $points_data = array(
            'value'           => $amount,
            'type'            => 'TG兑换',
            'desc'            => $desc,
            'order_num'       => $order_no,
            'event_namespace' => 'oauth.app.' . substr(hash('sha256', $appid), 0, 24),
            'event_id'        => $order_no,
        );
        $managed = apply_filters('xingxy_ecosystem_points_update', null, (int) $user_id, $points_data);
        if (function_exists('is_wp_error') && is_wp_error($managed)) {
            $writer_status = 503;
            $writer_code = 'points_unavailable';
            $writer_data = $managed->get_error_data();
            if (is_array($writer_data) && isset($writer_data['status'])) {
                $candidate_status = (int) $writer_data['status'];
                if (in_array($candidate_status, array(400, 409, 422, 503), true)) {
                    $writer_status = $candidate_status;
                }
            }
            if ($writer_status === 409) {
                $writer_code = 'points_conflict';
            }
            return new WP_Error($writer_code, $writer_status === 409
                ? '订单与既有积分账本记录冲突'
                : '统一积分账本暂不可用，请稍后重试', array('status' => $writer_status));
        }
        if ($managed !== true) {
            return new WP_Error('points_unavailable', '统一积分账本暂不可用，请稍后重试', array('status' => 503));
        }

        $new_points = 0;
        if (function_exists('zibpay_get_user_points')) {
            $new_points = zibpay_get_user_points((int) $user_id);
        }
        return new WP_REST_Response(array(
            'success'     => true,
            'user_id'     => (int) $user_id,
            'amount'      => $amount,
            'points'      => (int) $new_points,
            'order_no'    => $order_no,
            'is_duplicate'=> false,
            'message'     => '积分充值成功',
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

    /**
     * GET /user/profile
     * 
     * 查询用户站点个人信息（昵称、推荐人数）
     * 
     * 参数（GET query）：
     *   - appid    (string, 必须) 应用 ID
     *   - openid   (string, 必须) 用户 OpenID
     *   - sign     (string, 必须) 签名 = md5(appid + openid + appkey)
     */
    public static function profile(WP_REST_Request $request)
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

        // 6. 获取用户信息
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new WP_Error('user_not_found', '用户不存在', array('status' => 404));
        }

        $display_name = (string) $user->display_name;

        // 推荐好友人数
        $invite_count = (int) get_user_meta($user_id, 'invite_count', true);

        return new WP_REST_Response(array(
            'success'      => true,
            'user_id'      => $user_id,
            'display_name' => $display_name,
            'invite_count' => $invite_count,
        ), 200);
    }
}
