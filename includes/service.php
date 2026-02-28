<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Service
{
    private static function code_key($code)
    {
        return 'zibll_oauth_code_' . md5((string) $code);
    }

    public static function revoke_user_tokens($client_id, $user_id)
    {
        $client_id = trim((string) $client_id);
        $user_id = (int) $user_id;
        if ($client_id === '' || $user_id <= 0) {
            return;
        }

        $idx_key = self::refresh_index_key($client_id, $user_id);
        $rt = get_transient($idx_key);
        delete_transient($idx_key);

        if (is_string($rt) && trim($rt) !== '') {
            delete_transient(self::refresh_token_key($rt));
        }
    }

    public static function revoke(WP_REST_Request $request)
    {
        $client_id = trim((string) $request->get_param('client_id'));
        $client_secret = (string) $request->get_param('client_secret');
        $token = trim((string) $request->get_param('token'));
        $hint = trim((string) $request->get_param('token_type_hint'));

        if ($client_id === '' || $token === '') {
            return new WP_Error('invalid_request', '缺少必要参数：client_id、token', array('status' => 400));
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            return new WP_Error('unauthorized_client', 'client_id 无效或未配置', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线，请联系应用管理员', array('status' => 403));
        }

        if ((string) $client_secret !== (string) $site['appkey']) {
            return new WP_Error('invalid_client', 'client_secret 无效', array('status' => 401));
        }

        if ($hint === 'access_token') {
            delete_transient(self::token_key($token));
            return new WP_REST_Response(array('revoked' => true), 200);
        }

        $rt_data = get_transient(self::refresh_token_key($token));
        delete_transient(self::refresh_token_key($token));

        if ($rt_data && is_array($rt_data) && !empty($rt_data['user_id'])) {
            $idx_key = self::refresh_index_key($client_id, (int) $rt_data['user_id']);
            $current = get_transient($idx_key);
            if (is_string($current) && trim($current) === $token) {
                delete_transient($idx_key);
            }
        }

        return new WP_REST_Response(array('revoked' => true), 200);
    }

    private static function issue_code($appid, $user_id, $scope, $finance_grant, $redirect_uri)
    {
        $code = Zibll_Oauth_Provider_Util::random_token(32);
        if ($code === '') {
            return '';
        }

        $expires_in = 600;
        set_transient(self::code_key($code), array(
            'appid' => (string) $appid,
            'user_id' => (int) $user_id,
            'scope' => (string) $scope,
            'finance_grant' => !empty($finance_grant) ? 1 : 0,
            'redirect_uri' => (string) $redirect_uri,
            'created_at' => time(),
        ), $expires_in);

        return $code;
    }

    private static function consume_code($code)
    {
        $code = trim((string) $code);
        if ($code === '') {
            return null;
        }

        $data = get_transient(self::code_key($code));
        if (!$data || !is_array($data)) {
            return null;
        }

        delete_transient(self::code_key($code));
        return $data;
    }

    public static function authorize(WP_REST_Request $request)
    {
        $response_type = trim((string) $request->get_param('response_type'));
        $client_id = trim((string) $request->get_param('client_id'));
        $req_redirect_uri = trim((string) $request->get_param('redirect_uri'));
        $client_state = (string) $request->get_param('state');
        $scope = (string) $request->get_param('scope');

        $deny = (string) $request->get_param('deny');
        $consent_nonce = (string) $request->get_param('consent_nonce');

        if ($response_type !== 'code') {
            self::authorize_error('invalid_request', 'response_type 必须为 code', 400);
        }

        if ($client_id === '' || $req_redirect_uri === '') {
            self::authorize_error('invalid_request', '缺少必要参数：client_id、redirect_uri', 400);
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            self::authorize_error('unauthorized_client', 'client_id 无效或未配置', 403);
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            self::authorize_error('app_not_online', '应用暂未上线，请联系应用管理员', 403);
        }

        $redirect_uri = !empty($site['redirect_uri']) ? (string) $site['redirect_uri'] : '';
        if ($redirect_uri === '') {
            self::authorize_error('redirect_uri_not_configured', '站点未配置回调地址（redirect_uri）', 500);
        }

        if (trim($req_redirect_uri) !== trim($redirect_uri)) {
            self::authorize_error('invalid_request', 'redirect_uri 与后台配置不一致', 400);
        }

        if ($scope === '') {
            $scope = !empty($site['default_scope']) ? (string) $site['default_scope'] : 'basic';
        }

        // REST 场景下可能不会自动识别 cookie 登录态：尝试从 auth cookie 恢复当前用户
        if (!is_user_logged_in() && function_exists('wp_validate_auth_cookie') && function_exists('wp_set_current_user')) {
            $uid = wp_validate_auth_cookie('', 'logged_in');
            if ($uid) {
                wp_set_current_user((int) $uid);
            }
        }

        // 未登录先跳转登录（优先使用 Zibll 主题的登录页）
        if (!is_user_logged_in()) {
            $return_to = add_query_arg($request->get_params(), rest_url(Zibll_Oauth_Rest::REST_NAMESPACE . '/authorize'));

            if (function_exists('zib_get_sign_url')) {
                $zib_login = zib_get_sign_url('signin');
                if (is_string($zib_login) && $zib_login !== '') {
                    $login_url = add_query_arg('redirect_to', urlencode($return_to), $zib_login);
                    Zibll_Oauth_Provider_Util::redirect($login_url);
                }
            }

            $login_url = wp_login_url($return_to);
            Zibll_Oauth_Provider_Util::redirect($login_url);
        }

        $share_items = Zibll_Oauth_Provider_Util::scope_share_items($scope);

        // 拒绝授权：关闭窗口
        if ($deny !== '') {
            // 记录拒绝授权的日志
            if (is_user_logged_in() && class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
                $user_id = get_current_user_id();
                Zibll_Oauth_Admin_Log::add_log($client_id, $user_id, 'authorize_reject', '用户拒绝授权应用');
            }
            $html = Zibll_Oauth_Provider_Util::render_close_page('你已拒绝授权，本页面将尝试关闭。');
            Zibll_Oauth_Provider_Util::send_html($html, 200);
        }

        // 展示授权页面
        $deny_url = add_query_arg(array_merge($request->get_params(), array(
            'deny' => '1',
        )), rest_url(Zibll_Oauth_Rest::REST_NAMESPACE . '/authorize'));

        $consent_nonce = wp_create_nonce(self::nonce_action($client_id, $redirect_uri));
        $content = Zibll_Oauth_Provider_Util::render_consent_page($site, $share_items, $deny_url, array(
            'client_id' => $client_id,
            'response_type' => 'code',
            'redirect_uri' => $req_redirect_uri,
            'state' => $client_state,
            'scope' => $scope,
            'consent_nonce' => $consent_nonce,
        ));

        // 尽量使用 Zibll 的主题结构输出完整页面（含导航/页脚），避免布局错位
        $title_base = '互联授权';
        $blog_title = function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '';
        $title = $blog_title ? ($blog_title . ' - ' . $title_base) : $title_base;
        if (function_exists('wp_head') && function_exists('wp_footer')) {
            ob_start();
            echo '<!DOCTYPE HTML>';
            echo '<html ' . 'lang="' . esc_attr(get_bloginfo('language')) . '"' . '>';
            echo '<head>';
            echo '<meta charset="UTF-8">';
            echo '<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">';
            echo '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0, minimum-scale=1.0, maximum-scale=0.0, viewport-fit=cover">';
            echo '<title>' . esc_html($title) . '</title>';
            wp_head();
            if (function_exists('tb_xzh_head_var')) {
                tb_xzh_head_var();
            }
            echo '</head>';
            echo '<body ';
            if (function_exists('body_class') && function_exists('_bodyclass')) {
                body_class(_bodyclass());
            }
            echo '>';

            if (function_exists('qj_dh_nr')) {
                echo qj_dh_nr();
            }
            if (function_exists('zib_seo_image')) {
                zib_seo_image();
            }
            if (function_exists('zib_header')) {
                zib_header();
            }

            echo $content;

            if (function_exists('get_footer')) {
                get_footer();
            } else {
                if (function_exists('zib_footer_conter') || function_exists('do_action')) {
                    echo '<footer class="footer">';
                    if (function_exists('dynamic_sidebar')) {
                        dynamic_sidebar('all_footer');
                    }
                    echo '<div class="container-fluid container-footer">';
                    do_action('zib_footer_conter');
                    echo '</div></footer>';
                }
                wp_footer();
                echo '</body></html>';
            }

            $full = (string) ob_get_clean();
            Zibll_Oauth_Provider_Util::send_html($full, 200);
        }

        Zibll_Oauth_Provider_Util::send_html($content, 200);
    }

    private static function authorize_error($code, $message, $status)
    {
        $code = (string) $code;
        $message = (string) $message;

        if (function_exists('zib_die_page')) {
            if (function_exists('http_response_code')) {
                http_response_code((int) $status);
            }
            $t = '授权失败';
            $con = '<h4 class="c-red box-body separator mb30">' . esc_html($t) . '</h4>';
            $con .= '<div class="mb20 muted-box text-left" style=" max-width: 600px; margin: auto; ">错误：' . esc_html($message) . '，错误代码：' . esc_html($code) . '</div>';

            $title = $t;
            if (function_exists('zib_get_delimiter_blog_name')) {
                $title .= zib_get_delimiter_blog_name();
            }

            zib_die_page($con, array(
                'img' => defined('ZIB_TEMPLATE_DIRECTORY_URI') ? (ZIB_TEMPLATE_DIRECTORY_URI . '/img/null-user.svg') : '',
                'title' => $title,
            ));
        }

        $fragment = Zibll_Oauth_Provider_Util::render_zibll_error_fragment($message, $code, 'danger');
        $page = Zibll_Oauth_Provider_Util::render_zibll_theme_page('互联授权', '<main role="main" class="container" style="padding:18px 0;">' . $fragment . '</main>');
        Zibll_Oauth_Provider_Util::send_html($page, (int) $status);
    }

    public static function token(WP_REST_Request $request)
    {
        $grant_type = trim((string) $request->get_param('grant_type'));
        $client_id = trim((string) $request->get_param('client_id'));
        $client_secret = (string) $request->get_param('client_secret');
        $code = (string) $request->get_param('code');
        $redirect_uri = trim((string) $request->get_param('redirect_uri'));
        $refresh_token = (string) $request->get_param('refresh_token');

        if ($grant_type !== 'authorization_code' && $grant_type !== 'refresh_token') {
            return new WP_Error('unsupported_grant_type', 'grant_type 必须为 authorization_code 或 refresh_token', array('status' => 400));
        }

        if ($grant_type === 'authorization_code') {
            if ($client_id === '' || trim($code) === '' || $redirect_uri === '') {
                return new WP_Error('invalid_request', '缺少必要参数：client_id、code、redirect_uri', array('status' => 400));
            }
        }

        if ($grant_type === 'refresh_token') {
            if ($client_id === '' || trim($refresh_token) === '') {
                return new WP_Error('invalid_request', '缺少必要参数：client_id、refresh_token', array('status' => 400));
            }
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            return new WP_Error('unauthorized_client', 'client_id 无效或未配置', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线，请联系应用管理员', array('status' => 403));
        }

        if ((string) $client_secret !== (string) $site['appkey']) {
            return new WP_Error('invalid_client', 'client_secret 无效', array('status' => 401));
        }

        $refresh_ttl = 180 * DAY_IN_SECONDS;

        if ($grant_type === 'refresh_token') {
            $rt_data = get_transient(self::refresh_token_key($refresh_token));
            if (!$rt_data || !is_array($rt_data)) {
                return new WP_Error('invalid_grant', 'refresh_token 无效或已过期', array('status' => 400));
            }

            $rotate = $request->get_param('rotate_refresh_token');
            $rotate = !($rotate === '0' || $rotate === 0 || $rotate === false || $rotate === 'false');

            if ($rotate) {
                delete_transient(self::refresh_token_key($refresh_token));
            }

            if (empty($rt_data['appid']) || (string) $rt_data['appid'] !== (string) $client_id) {
                return new WP_Error('invalid_grant', 'refresh_token 与应用不匹配', array('status' => 400));
            }
            if (empty($rt_data['user_id'])) {
                return new WP_Error('invalid_grant', 'refresh_token 数据不完整', array('status' => 400));
            }

            $access_token = Zibll_Oauth_Provider_Util::random_token(40);
            $expires_in = Zibll_Oauth_Options::token_expires();

            set_transient(self::token_key($access_token), array(
                'appid' => $client_id,
                'user_id' => (int) $rt_data['user_id'],
                'scope' => !empty($rt_data['scope']) ? (string) $rt_data['scope'] : 'basic',
                'finance_grant' => !empty($rt_data['finance_grant']) ? true : false,
                'created_at' => time(),
            ), $expires_in);

            if (!$rotate) {
                set_transient(self::refresh_token_key($refresh_token), array(
                    'appid' => $client_id,
                    'user_id' => (int) $rt_data['user_id'],
                    'scope' => !empty($rt_data['scope']) ? (string) $rt_data['scope'] : 'basic',
                    'finance_grant' => !empty($rt_data['finance_grant']) ? true : false,
                    'created_at' => time(),
                ), $refresh_ttl);

                set_transient(self::refresh_index_key($client_id, (int) $rt_data['user_id']), $refresh_token, $refresh_ttl);

                return new WP_REST_Response(array(
                    'access_token' => $access_token,
                    'token_type' => 'bearer',
                    'expires_in' => $expires_in,
                    'refresh_token' => $refresh_token,
                    'refresh_token_expires_in' => $refresh_ttl,
                ), 200);
            }

            $new_refresh = Zibll_Oauth_Provider_Util::random_token(40);
            if ($new_refresh === '') {
                return new WP_Error('server_error', '生成 refresh_token 失败', array('status' => 500));
            }
            set_transient(self::refresh_token_key($new_refresh), array(
                'appid' => $client_id,
                'user_id' => (int) $rt_data['user_id'],
                'scope' => !empty($rt_data['scope']) ? (string) $rt_data['scope'] : 'basic',
                'finance_grant' => !empty($rt_data['finance_grant']) ? true : false,
                'created_at' => time(),
            ), $refresh_ttl);

            set_transient(self::refresh_index_key($client_id, (int) $rt_data['user_id']), $new_refresh, $refresh_ttl);

            return new WP_REST_Response(array(
                'access_token' => $access_token,
                'token_type' => 'bearer',
                'expires_in' => $expires_in,
                'refresh_token' => $new_refresh,
                'refresh_token_expires_in' => $refresh_ttl,
            ), 200);
        }

        $site_redirect_uri = !empty($site['redirect_uri']) ? (string) $site['redirect_uri'] : '';
        if ($site_redirect_uri === '' || trim($redirect_uri) !== trim($site_redirect_uri)) {
            return new WP_Error('invalid_request', 'redirect_uri 与后台配置不一致', array('status' => 400));
        }

        $code_data = self::consume_code($code);
        if (!$code_data) {
            return new WP_Error('invalid_grant', 'code 无效或已过期', array('status' => 400));
        }
        if (empty($code_data['appid']) || (string) $code_data['appid'] !== (string) $client_id) {
            return new WP_Error('invalid_grant', 'code 与应用不匹配', array('status' => 400));
        }
        if (empty($code_data['redirect_uri']) || trim((string) $code_data['redirect_uri']) !== trim($redirect_uri)) {
            return new WP_Error('invalid_grant', 'redirect_uri 与 code 不匹配', array('status' => 400));
        }
        if (empty($code_data['user_id'])) {
            return new WP_Error('invalid_grant', 'code 数据不完整', array('status' => 400));
        }

        $access_token = Zibll_Oauth_Provider_Util::random_token(40);
        $expires_in = Zibll_Oauth_Options::token_expires();

        $issued_refresh = Zibll_Oauth_Provider_Util::random_token(40);
        if ($issued_refresh === '') {
            return new WP_Error('server_error', '生成 refresh_token 失败', array('status' => 500));
        }

        set_transient(self::token_key($access_token), array(
            'appid' => $client_id,
            'user_id' => (int) $code_data['user_id'],
            'scope' => !empty($code_data['scope']) ? (string) $code_data['scope'] : 'basic',
            'finance_grant' => !empty($code_data['finance_grant']) ? true : false,
            'created_at' => time(),
        ), $expires_in);

        set_transient(self::refresh_token_key($issued_refresh), array(
            'appid' => $client_id,
            'user_id' => (int) $code_data['user_id'],
            'scope' => !empty($code_data['scope']) ? (string) $code_data['scope'] : 'basic',
            'finance_grant' => !empty($code_data['finance_grant']) ? true : false,
            'created_at' => time(),
        ), $refresh_ttl);

        set_transient(self::refresh_index_key($client_id, (int) $code_data['user_id']), $issued_refresh, $refresh_ttl);

        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            Zibll_Oauth_Admin_Log::add_log($client_id, (int) $code_data['user_id'], 'token_issue', '通过 code 获取 access_token');
        }

        return new WP_REST_Response(array(
            'access_token' => $access_token,
            'token_type' => 'bearer',
            'expires_in' => $expires_in,
            'refresh_token' => $issued_refresh,
            'refresh_token_expires_in' => $refresh_ttl,
        ), 200);
    }

    public static function userinfo(WP_REST_Request $request)
    {
        $token = '';
        $auth = $request->get_header('authorization');
        if (is_string($auth) && stripos($auth, 'bearer ') === 0) {
            $token = trim(substr($auth, 7));
        }

        if ($token === '') {
            return new WP_Error('missing_token', '缺少 access_token（请使用 Authorization: Bearer <token>）', array('status' => 401));
        }

        $data = get_transient(self::token_key($token));
        if (!$data || !is_array($data)) {
            return new WP_Error('token_invalid', 'access_token 无效或已过期', array('status' => 401));
        }

        if (empty($data['user_id'])) {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 user_id', array('status' => 401));
        }

        $appid = !empty($data['appid']) ? (string) $data['appid'] : '';
        if ($appid === '') {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 appid', array('status' => 401));
        }

        $user_id = (int) $data['user_id'];

        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效或未配置', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);

        // 应用 IP 白名单校验（若有配置）
        $client_ip = Zibll_Oauth_Provider_Util::client_ip();
        if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
            return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403, 'ip' => $client_ip));
        }

        $is_granted = Zibll_Oauth_Grant::is_granted($appid, $user_id);
        if (!$is_granted) {
            return new WP_Error('not_authorized', '用户未授权该应用', array('status' => 403));
        }

        $scope = !empty($data['scope']) ? (string) $data['scope'] : 'basic';

        $include_balance = false;
        if (!empty($site['finance_enabled'])) {
            $grant = Zibll_Oauth_Grant::get_by_appid_user($appid, $user_id);
            if ($grant && (int) $grant['status'] === 1 && (int) $grant['finance_scope'] === 1) {
                $include_balance = true;
            }
        }

        $userinfo = Zibll_Oauth_Provider_Util::wp_userinfo_by_scope($user_id, $scope, $appid, $include_balance);
        if (is_wp_error($userinfo)) {
            return $userinfo;
        }

        $refresh_ttl = 180 * DAY_IN_SECONDS;
        $refresh_token = get_transient(self::refresh_index_key($appid, $user_id));
        if (is_string($refresh_token) && $refresh_token !== '') {
            $userinfo['refresh_token'] = $refresh_token;
            $userinfo['refresh_token_expires_in'] = $refresh_ttl;
        }

        return new WP_REST_Response(array(
            'userinfo' => $userinfo,
        ), 200);
    }

    private static function token_key($token)
    {
        return 'zibll_oauth_token_' . md5((string) $token);
    }

    private static function refresh_token_key($token)
    {
        return 'zibll_oauth_refresh_' . md5((string) $token);
    }

    private static function refresh_index_key($client_id, $user_id)
    {
        return 'zibll_oauth_refresh_idx_' . md5((string) $client_id . '|' . (int) $user_id);
    }

    private static function nonce_action($appid, $redirect_uri)
    {
        return 'zibll_oauth_consent_' . md5((string) $appid . '|' . (string) $redirect_uri);
    }

    public static function unionid(WP_REST_Request $request)
    {
        $token = '';
        $auth = $request->get_header('authorization');
        if (is_string($auth) && stripos($auth, 'bearer ') === 0) {
            $token = trim(substr($auth, 7));
        }
        if ($token === '') {
            return new WP_Error('missing_token', '缺少 access_token（请使用 Authorization: Bearer <token>）', array('status' => 401));
        }

        $data = get_transient(self::token_key($token));
        if (!$data || !is_array($data)) {
            return new WP_Error('token_invalid', 'access_token 无效或已过期', array('status' => 401));
        }
        if (empty($data['user_id'])) {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 user_id', array('status' => 401));
        }

        $appid = !empty($data['appid']) ? (string) $data['appid'] : '';
        if ($appid === '') {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 appid', array('status' => 401));
        }

        $user_id = (int) $data['user_id'];

        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效或未配置', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);

        // 应用 IP 白名单校验（若有配置）
        $client_ip = Zibll_Oauth_Provider_Util::client_ip();
        if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
            return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403, 'ip' => $client_ip));
        }

        $is_granted = Zibll_Oauth_Grant::is_granted($appid, $user_id);
        if (!$is_granted) {
            return new WP_Error('not_authorized', '用户未授权该应用', array('status' => 403));
        }

        $openid = Zibll_Oauth_Provider_Util::get_openid($user_id, $appid);
        if ($openid === '') {
            return new WP_Error('openid_error', 'OpenID 生成失败', array('status' => 500));
        }

        return new WP_REST_Response(array(
            'openid' => $openid,
            'unionid' => (string) ((int) $data['user_id']),
        ), 200);
    }

    public static function ajax_approve()
    {
        if (!is_user_logged_in()) {
            echo json_encode(array('error' => 1, 'msg' => '请先登录'));
            exit;
        }

        if (function_exists('zib_ajax_man_machine_verification')) {
            zib_ajax_man_machine_verification('zibll_oauth_approve');
        }

        $client_id = isset($_POST['client_id']) ? trim((string) $_POST['client_id']) : '';
        $response_type = isset($_POST['response_type']) ? trim((string) $_POST['response_type']) : '';
        $req_redirect_uri = isset($_POST['redirect_uri']) ? trim((string) $_POST['redirect_uri']) : '';
        $client_state = isset($_POST['state']) ? (string) $_POST['state'] : '';
        $scope = isset($_POST['scope']) ? (string) $_POST['scope'] : '';
        $consent_nonce = isset($_POST['consent_nonce']) ? (string) $_POST['consent_nonce'] : '';

        if ($response_type !== 'code') {
            echo json_encode(array('error' => 1, 'msg' => 'response_type 必须为 code'));
            exit;
        }

        if ($client_id === '' || $req_redirect_uri === '') {
            echo json_encode(array('error' => 1, 'msg' => '缺少必要参数：client_id、redirect_uri'));
            exit;
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            echo json_encode(array('error' => 1, 'msg' => 'client_id 无效或未配置'));
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            echo json_encode(array('error' => 1, 'msg' => '应用暂未上线，请联系应用管理员'));
            exit;
        }

        $redirect_uri = !empty($site['redirect_uri']) ? (string) $site['redirect_uri'] : '';
        if ($redirect_uri === '') {
            echo json_encode(array('error' => 1, 'msg' => '站点未配置回调地址（redirect_uri）'));
            exit;
        }

        if (trim($req_redirect_uri) !== trim($redirect_uri)) {
            echo json_encode(array('error' => 1, 'msg' => 'redirect_uri 与后台配置不一致'));
            exit;
        }
        if (!$consent_nonce || !wp_verify_nonce($consent_nonce, self::nonce_action($client_id, $redirect_uri))) {
            echo json_encode(array('error' => 1, 'msg' => '授权确认已失效，请刷新页面重新授权'));
            exit;
        }

        if ($scope === '') {
            $scope = !empty($site['default_scope']) ? (string) $site['default_scope'] : 'basic';
        }

        $user_id = get_current_user_id();
        if (!$user_id) {
            echo json_encode(array('error' => 1, 'msg' => '用户未登录'));
            exit;
        }

        Zibll_Oauth_Grant::insert($client_id, $user_id, $scope, !empty($site['id']) ? (int) $site['id'] : 0);

        $finance_grant = 0;
        $code = self::issue_code($client_id, $user_id, $scope, $finance_grant, $redirect_uri);
        if ($code === '') {
            echo json_encode(array('error' => 1, 'msg' => '生成 code 失败'));
            exit;
        }

        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            Zibll_Oauth_Admin_Log::add_log($client_id, $user_id, 'authorize_grant', '用户同意授权应用');
        }

        $rurl = add_query_arg(array(
            'state' => $client_state,
            'code' => $code,
        ), $redirect_uri);

        echo json_encode(array('error' => 0, 'reload' => 1, 'goto' => $rurl, 'msg' => '授权成功，页面跳转中'));
        exit;
    }

    public static function ajax_finance_approve()
    {
        if (!is_user_logged_in()) {
            echo json_encode(array('error' => 1, 'msg' => '请先登录'));
            exit;
        }

        if (function_exists('zib_ajax_man_machine_verification')) {
            zib_ajax_man_machine_verification('zibll_oauth_finance_approve');
        }

        $client_id = isset($_POST['client_id']) ? trim((string) $_POST['client_id']) : '';
        $response_type = isset($_POST['response_type']) ? trim((string) $_POST['response_type']) : '';
        $req_redirect_uri = isset($_POST['redirect_uri']) ? trim((string) $_POST['redirect_uri']) : '';
        $client_state = isset($_POST['state']) ? (string) $_POST['state'] : '';
        $scope = isset($_POST['scope']) ? (string) $_POST['scope'] : '';
        $consent_nonce = isset($_POST['consent_nonce']) ? (string) $_POST['consent_nonce'] : '';

        if ($response_type !== 'code') {
            echo json_encode(array('error' => 1, 'msg' => 'response_type 必须为 code'));
            exit;
        }

        if ($client_id === '' || $req_redirect_uri === '') {
            echo json_encode(array('error' => 1, 'msg' => '缺少必要参数：client_id、redirect_uri'));
            exit;
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            echo json_encode(array('error' => 1, 'msg' => 'client_id 无效或未配置'));
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            echo json_encode(array('error' => 1, 'msg' => '应用暂未上线，请联系应用管理员'));
            exit;
        }

        $redirect_uri = !empty($site['finance_callback_url']) ? (string) $site['finance_callback_url'] : '';
        if ($redirect_uri === '') {
            echo json_encode(array('error' => 1, 'msg' => '站点未配置回调地址'));
            exit;
        }

        if (trim($req_redirect_uri) !== trim($redirect_uri)) {
            echo json_encode(array('error' => 1, 'msg' => 'redirect_uri 与后台配置不一致'));
            exit;
        }

        if (!$consent_nonce || !wp_verify_nonce($consent_nonce, self::nonce_action($client_id, $redirect_uri))) {
            echo json_encode(array('error' => 1, 'msg' => '授权确认已失效，请刷新页面重新授权'));
            exit;
        }

        if ($scope === '') {
            $scope = !empty($site['default_scope']) ? (string) $site['default_scope'] : 'basic';
        }

        $user_id = get_current_user_id();
        if (!$user_id) {
            echo json_encode(array('error' => 1, 'msg' => '用户未登录'));
            exit;
        }

        Zibll_Oauth_Grant::update_finance_scope($client_id, $user_id, 1);

        $finance_grant = 1;
        $code = self::issue_code($client_id, $user_id, $scope, $finance_grant, $redirect_uri);
        if ($code === '') {
            echo json_encode(array('error' => 1, 'msg' => '生成 code 失败'));
            exit;
        }

        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            Zibll_Oauth_Admin_Log::add_log($client_id, $user_id, 'finance_grant', '用户同意财务（免密支付）授权');
        }

        $rurl = add_query_arg(array(
            'state' => $client_state,
            'code' => $code,
        ), $redirect_uri);

        echo json_encode(array('error' => 0, 'reload' => 1, 'goto' => $rurl, 'msg' => '财务授权成功，页面跳转中'));
        exit;
    }

    public static function authorize_finance(WP_REST_Request $request)
    {
        $response_type = trim((string) $request->get_param('response_type'));
        $client_id = trim((string) $request->get_param('client_id'));
        $req_redirect_uri = trim((string) $request->get_param('redirect_uri'));
        $client_state = (string) $request->get_param('state');
        $scope = (string) $request->get_param('scope');

        $deny = (string) $request->get_param('deny');
        $consent_nonce = (string) $request->get_param('consent_nonce');

        if ($response_type !== 'code') {
            self::authorize_error('invalid_request', 'response_type 必须为 code', 400);
        }

        if ($client_id === '' || $req_redirect_uri === '') {
            self::authorize_error('invalid_request', '缺少必要参数：client_id、redirect_uri', 400);
        }

        $app_row = Zibll_Oauth_App_DB::find_by_appid($client_id);
        if (!$app_row) {
            self::authorize_error('unauthorized_client', 'client_id 无效或未配置', 403);
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);
        if (empty($site['enabled'])) {
            self::authorize_error('app_not_online', '应用暂未上线，请联系应用管理员', 403);
        }

        if (empty($site['finance_enabled'])) {
            self::authorize_error('finance_not_enabled', '该应用未开启财务权限', 403);
        }

        $redirect_uri = !empty($site['finance_callback_url']) ? (string) $site['finance_callback_url'] : '';
        if ($redirect_uri === '') {
            self::authorize_error('callback_not_configured', '站点未配置财务回调地址', 500);
        }

        if (trim($req_redirect_uri) !== trim($redirect_uri)) {
            self::authorize_error('invalid_request', 'redirect_uri 与后台配置不一致', 400);
        }

        if ($scope === '') {
            $scope = !empty($site['default_scope']) ? (string) $site['default_scope'] : 'basic';
        }

        if (!is_user_logged_in() && function_exists('wp_validate_auth_cookie') && function_exists('wp_set_current_user')) {
            $uid = wp_validate_auth_cookie('', 'logged_in');
            if ($uid) {
                wp_set_current_user((int) $uid);
            }
        }

        if (!is_user_logged_in()) {
            $return_to = add_query_arg($request->get_params(), rest_url(Zibll_Oauth_Rest::REST_NAMESPACE . '/authorize_finance'));
            if (function_exists('zib_get_sign_url')) {
                $zib_login = zib_get_sign_url('signin');
                if (is_string($zib_login) && $zib_login !== '') {
                    $login_url = add_query_arg('redirect_to', urlencode($return_to), $zib_login);
                    Zibll_Oauth_Provider_Util::redirect($login_url);
                }
            }
            $login_url = wp_login_url($return_to);
            Zibll_Oauth_Provider_Util::redirect($login_url);
        }

        $user_id = (int) get_current_user_id();
        if ($user_id <= 0) {
            self::authorize_error('invalid_request', '用户未登录', 401);
        }

        $is_granted = Zibll_Oauth_Grant::is_granted($client_id, $user_id, false);
        if (!$is_granted) {
            self::authorize_error('not_authorized', '请先完成应用授权，再进行财务授权', 403);
        }

        if ($deny !== '') {
            $html = Zibll_Oauth_Provider_Util::render_close_page('你已拒绝授权，本页面将尝试关闭。');
            Zibll_Oauth_Provider_Util::send_html($html, 200);
        }

        $deny_url = add_query_arg(array_merge($request->get_params(), array(
            'deny' => '1',
        )), rest_url(Zibll_Oauth_Rest::REST_NAMESPACE . '/authorize_finance'));

        $consent_nonce = wp_create_nonce(self::nonce_action($client_id, $redirect_uri));
        $content = Zibll_Oauth_Provider_Util::render_finance_consent_page($site, $deny_url, array(
            'client_id' => $client_id,
            'response_type' => 'code',
            'redirect_uri' => $req_redirect_uri,
            'state' => $client_state,
            'scope' => $scope,
            'consent_nonce' => $consent_nonce,
        ));

        $title_base = '财务授权';
        $blog_title = function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '';
        $title = $blog_title ? ($blog_title . ' - ' . $title_base) : $title_base;
        if (function_exists('wp_head') && function_exists('wp_footer')) {
            ob_start();
            echo '<!DOCTYPE HTML>';
            echo '<html ' . 'lang="' . esc_attr(get_bloginfo('language')) . '"' . '>';
            echo '<head>';
            echo '<meta charset="UTF-8">';
            echo '<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">';
            echo '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0, minimum-scale=1.0, maximum-scale=0.0, viewport-fit=cover">';
            echo '<title>' . esc_html($title) . '</title>';
            wp_head();
            if (function_exists('tb_xzh_head_var')) {
                tb_xzh_head_var();
            }
            echo '</head>';
            echo '<body ';
            if (function_exists('body_class') && function_exists('_bodyclass')) {
                body_class(_bodyclass());
            }
            echo '>';

            if (function_exists('qj_dh_nr')) {
                echo qj_dh_nr();
            }
            if (function_exists('zib_seo_image')) {
                zib_seo_image();
            }
            if (function_exists('zib_header')) {
                zib_header();
            }

            echo $content;

            if (function_exists('get_footer')) {
                get_footer();
            } else {
                if (function_exists('zib_footer_conter') || function_exists('do_action')) {
                    echo '<footer class="footer">';
                    if (function_exists('dynamic_sidebar')) {
                        dynamic_sidebar('all_footer');
                    }
                    echo '<div class="container-fluid container-footer">';
                    do_action('zib_footer_conter');
                    echo '</div></footer>';
                }
                wp_footer();
                echo '</body></html>';
            }

            $full = (string) ob_get_clean();
            Zibll_Oauth_Provider_Util::send_html($full, 200);
        }

        Zibll_Oauth_Provider_Util::send_html($content, 200);
    }

    public static function finance_deduct(WP_REST_Request $request)
    {
        $token = '';
        $auth = $request->get_header('authorization');
        if (is_string($auth) && stripos($auth, 'bearer ') === 0) {
            $token = trim(substr($auth, 7));
        }

        if ($token === '') {
            return new WP_Error('missing_token', '缺少 access_token（请使用 Authorization: Bearer <token>）', array('status' => 401));
        }

        $data = get_transient(self::token_key($token));
        if (!$data || !is_array($data)) {
            return new WP_Error('token_invalid', 'access_token 无效或已过期', array('status' => 401));
        }

        if (empty($data['user_id'])) {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 user_id', array('status' => 401));
        }

        $appid = !empty($data['appid']) ? (string) $data['appid'] : '';
        if ($appid === '') {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 appid', array('status' => 401));
        }

        $user_id = (int) $data['user_id'];

        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if (!$app_row) {
            return new WP_Error('invalid_appid', 'AppID 无效或未配置', array('status' => 403));
        }

        $site = Zibll_Oauth_App_DB::to_site_array($app_row);

        // 应用 IP 白名单校验（若有配置）
        $client_ip = Zibll_Oauth_Provider_Util::client_ip();
        if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
            return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403, 'ip' => $client_ip));
        }

        if (empty($site['enabled'])) {
            return new WP_Error('app_not_online', '应用暂未上线，请联系应用管理员', array('status' => 403));
        }

        if (empty($site['finance_enabled'])) {
            return new WP_Error('finance_not_enabled', '该应用未开启财务权限', array('status' => 403));
        }

        $is_finance_granted = Zibll_Oauth_Grant::is_granted($appid, $user_id, true);
        if (!$is_finance_granted) {
            return new WP_Error('finance_not_granted', '用户未授权该应用的财务权限', array('status' => 403));
        }

        $openid = Zibll_Oauth_Provider_Util::get_openid($user_id, $appid);
        if ($openid === '') {
            return new WP_Error('openid_error', 'OpenID 生成失败', array('status' => 500));
        }

        $product_name = trim((string) $request->get_param('product_name'));
        $amount = (float) $request->get_param('amount');
        $order_no = trim((string) $request->get_param('order_no'));

        if ($product_name === '') {
            return new WP_Error('missing_param', '缺少必要参数：product_name（商品名称）', array('status' => 400));
        }

        if ($amount <= 0) {
            return new WP_Error('invalid_amount', '金额必须大于0', array('status' => 400));
        }

        if ($order_no === '') {
            return new WP_Error('missing_param', '缺少必要参数：order_no（订单号）', array('status' => 400));
        }

        global $wpdb;
        $deduct_table = $wpdb->prefix . 'zibll_oauth_deduct';

        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT id, status, trade_no, amount FROM {$deduct_table} WHERE order_no = %s LIMIT 1",
            $order_no
        ), ARRAY_A);

        if ($existing) {
            if ((int) $existing['status'] === 1) {
                $trade_no = !empty($existing['trade_no']) ? (string) $existing['trade_no'] : '';
                $existing_amount = isset($existing['amount']) ? (float) $existing['amount'] : 0.0;
                // 获取当前用户余额
                $current_balance = 0.0;
                if (function_exists('zibpay_get_user_balance')) {
                    $current_balance = (float) zibpay_get_user_balance($user_id);
                }
                return new WP_REST_Response(array(
                    'trade_no' => (string) $trade_no,
                    'order_no' => $order_no,
                    'status' => 'success',
                    'message' => '订单已处理完成',
                    'amount' => (float) $existing_amount,
                    'balance' => $current_balance,
                ), 200);
            }

            if ((int) $existing['status'] === 0) {
                $trade_no = !empty($existing['trade_no']) ? (string) $existing['trade_no'] : '';
                $existing_amount = isset($existing['amount']) ? (float) $existing['amount'] : 0.0;

                $existing_id = !empty($existing['id']) ? (int) $existing['id'] : 0;
                if ($existing_id > 0) {
                    $buf = '';
                    if (function_exists('ob_start')) {
                        ob_start();
                    }
                    self::cron_finance_deduct_process($existing_id);
                    if (function_exists('ob_get_clean')) {
                        $buf = (string) ob_get_clean();
                    }
                    if (trim($buf) !== '') {
                        error_log('[zibll-oauth] finance_deduct buffered output: ' . substr(trim($buf), 0, 300));
                    }
                    $after = $wpdb->get_row($wpdb->prepare(
                        "SELECT id, status, trade_no, amount, error_msg FROM {$deduct_table} WHERE id = %d LIMIT 1",
                        $existing_id
                    ), ARRAY_A);
                    if ($after && is_array($after) && isset($after['status']) && (int) $after['status'] !== 0) {
                        $status_map = array(
                            0 => 'processing',
                            1 => 'success',
                            2 => 'failed',
                        );
                        $st = (int) $after['status'];
                        $text = isset($status_map[$st]) ? $status_map[$st] : 'unknown';
                        return new WP_REST_Response(array(
                            'trade_no' => (string) (!empty($after['trade_no']) ? $after['trade_no'] : $trade_no),
                            'order_no' => $order_no,
                            'status' => $text,
                            'message' => $text === 'success' ? '订单已处理完成' : ($text === 'failed' ? '订单处理失败' : '订单处理中'),
                            'amount' => (float) (isset($after['amount']) ? $after['amount'] : $existing_amount),
                            'error_msg' => (string) (!empty($after['error_msg']) ? $after['error_msg'] : ''),
                        ), 200);
                    }
                }
                return new WP_REST_Response(array(
                    'trade_no' => (string) $trade_no,
                    'order_no' => $order_no,
                    'status' => 'processing',
                    'message' => '订单处理中',
                    'amount' => (float) $existing_amount,
                ), 200);
            }

            if ((int) $existing['status'] === 2) {
                $trade_no = !empty($existing['trade_no']) ? (string) $existing['trade_no'] : '';
                $existing_amount = isset($existing['amount']) ? (float) $existing['amount'] : 0.0;
                return new WP_REST_Response(array(
                    'trade_no' => (string) $trade_no,
                    'order_no' => $order_no,
                    'status' => 'failed',
                    'message' => '订单处理失败',
                    'amount' => (float) $existing_amount,
                ), 200);
            }

            return new WP_Error('duplicate_order', '订单号已存在且未完成', array('status' => 409));
        }

        $trade_no = 'zod_' . strtolower(wp_generate_password(24, false, false));

        $wpdb->insert($deduct_table, array(
            'appid' => $appid,
            'user_id' => $user_id,
            'openid' => $openid,
            'product_name' => $product_name,
            'amount' => $amount,
            'order_no' => $order_no,
            'trade_no' => $trade_no,
            'trade_type' => 'third_party',
            'status' => 0,
            'error_msg' => '',
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql'),
        ), array('%s', '%d', '%s', '%s', '%f', '%s', '%s', '%s', '%d', '%s', '%s', '%s'));

        if (!$wpdb->insert_id) {
            return new WP_Error('db_error', '创建扣款记录失败', array('status' => 500));
        }

        self::schedule_finance_deduct_process((int) $wpdb->insert_id);

        return new WP_REST_Response(array(
            'trade_no' => $trade_no,
            'order_no' => $order_no,
            'status' => 'processing',
            'message' => '订单已受理，处理中',
            'amount' => (float) $amount,
        ), 200);
    }

    private static function schedule_finance_deduct_process($deduct_id)
    {
        $deduct_id = (int) $deduct_id;
        if ($deduct_id <= 0) {
            return;
        }

        if (!function_exists('wp_schedule_single_event')) {
            return;
        }

        $lock = get_transient('zibll_oauth_deduct_job_' . (int) $deduct_id);
        if (!empty($lock)) {
            return;
        }
        set_transient('zibll_oauth_deduct_job_' . (int) $deduct_id, 1, 60);

        wp_schedule_single_event(time() + 1, 'zibll_oauth_finance_deduct_process', array($deduct_id));
    }

    public static function schedule_callback_send($callback_url, $payload)
    {
        $callback_url = trim((string) $callback_url);
        if ($callback_url === '' || !is_array($payload)) {
            return;
        }

        if (!function_exists('wp_schedule_single_event') || !function_exists('wp_remote_post')) {
            return;
        }

        if (class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url')) {
            if (!Zibll_Oauth_Provider_Util::is_safe_callback_url($callback_url)) {
                return;
            }
        }

        $job_id = '';
        if (class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'random_token')) {
            $job_id = (string) Zibll_Oauth_Provider_Util::random_token(24);
        } else {
            $job_id = (string) wp_generate_password(24, false, false);
        }
        if ($job_id === '') {
            return;
        }

        $job_key = self::callback_job_key($job_id);
        set_transient($job_key, array(
            'url' => $callback_url,
            'payload' => $payload,
            'attempt' => 0,
            'created_at' => time(),
        ), DAY_IN_SECONDS);

        wp_schedule_single_event(time() + 1, 'zibll_oauth_callback_send', array($job_id));
    }

    public static function finalize_callback_payload($payload, $appkey)
    {
        if (!is_array($payload)) {
            $payload = array();
        }
        $payload['timestamp'] = time();
        $payload['nonce'] = class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'random_token') ? (string) Zibll_Oauth_Provider_Util::random_token(16) : (string) wp_generate_password(16, false, false);
        $payload['event_id'] = class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'random_token') ? (string) Zibll_Oauth_Provider_Util::random_token(24) : (string) wp_generate_password(24, false, false);
        $payload['sign2'] = Zibll_Oauth_Provider_Util::sign_hmac_sha256_v2($payload, (string) $appkey);
        return $payload;
    }

    private static function dedupe_and_enqueue_callback($type, $appid, $callback_url, $payload)
    {
        $type = trim((string) $type);
        $appid = trim((string) $appid);
        $callback_url = trim((string) $callback_url);
        if ($type === '' || $appid === '' || $callback_url === '' || !is_array($payload)) {
            return;
        }
        if (empty($payload['event_id'])) {
            return;
        }

        $dedupe_key = 'zibll_oauth_cb_' . md5($type . '|' . $appid . '|' . (string) $payload['event_id']);
        if (get_transient($dedupe_key)) {
            return;
        }
        set_transient($dedupe_key, 1, DAY_IN_SECONDS);
        self::schedule_callback_send($callback_url, $payload);
    }

    public static function cron_callback_send($job_id)
    {
        $job_id = trim((string) $job_id);
        if ($job_id === '') {
            return;
        }

        if (!function_exists('wp_remote_post') || !function_exists('wp_schedule_single_event')) {
            return;
        }

        $job_key = self::callback_job_key($job_id);
        $job = get_transient($job_key);
        if (!$job || !is_array($job)) {
            return;
        }

        $url = !empty($job['url']) ? trim((string) $job['url']) : '';
        $payload = !empty($job['payload']) && is_array($job['payload']) ? $job['payload'] : array();
        $attempt = isset($job['attempt']) ? (int) $job['attempt'] : 0;

        if ($url === '' || empty($payload)) {
            delete_transient($job_key);
            return;
        }

        if (class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url')) {
            if (!Zibll_Oauth_Provider_Util::is_safe_callback_url($url)) {
                delete_transient($job_key);
                return;
            }
        }

        $resp = wp_remote_post($url, array(
            'body' => wp_json_encode($payload),
            'timeout' => 5,
            'blocking' => true,
            'redirection' => 0,
            'reject_unsafe_urls' => true,
            'headers' => array(
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ),
        ));

        $ok = true;
        $status_code = 0;
        if (is_wp_error($resp)) {
            $ok = false;
        } else {
            $status_code = (int) wp_remote_retrieve_response_code($resp);
            if ($status_code < 200 || $status_code >= 300) {
                $ok = false;
            }
        }

        if ($ok) {
            delete_transient($job_key);
            return;
        }

        // 4xx 通常是参数/鉴权问题，不重试
        if ($status_code >= 400 && $status_code < 500) {
            delete_transient($job_key);
            return;
        }

        $attempt++;
        if ($attempt >= 6) {
            delete_transient($job_key);
            return;
        }

        $job['attempt'] = $attempt;
        set_transient($job_key, $job, DAY_IN_SECONDS);

        $delay = (int) pow(2, $attempt);
        if ($delay < 5) {
            $delay = 5;
        }
        if ($delay > 3600) {
            $delay = 3600;
        }

        wp_schedule_single_event(time() + $delay, 'zibll_oauth_callback_send', array($job_id));
    }

    public static function cron_finance_deduct_process($deduct_id)
    {
        $deduct_id = (int) $deduct_id;
        if ($deduct_id <= 0) {
            return;
        }

        global $wpdb;
        $deduct_table = $wpdb->prefix . 'zibll_oauth_deduct';
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$deduct_table} WHERE id = %d LIMIT 1", $deduct_id), ARRAY_A);
        if (!$row || !is_array($row)) {
            return;
        }
        if ((int) $row['status'] !== 0) {
            return;
        }

        $appid = !empty($row['appid']) ? (string) $row['appid'] : '';
        $user_id = !empty($row['user_id']) ? (int) $row['user_id'] : 0;
        $openid = !empty($row['openid']) ? (string) $row['openid'] : '';
        $order_no = !empty($row['order_no']) ? (string) $row['order_no'] : '';
        $trade_no = !empty($row['trade_no']) ? (string) $row['trade_no'] : '';
        $amount = isset($row['amount']) ? (float) $row['amount'] : 0.0;
        $product_name = !empty($row['product_name']) ? (string) $row['product_name'] : '';

        $deduct_result = false;
        $error_msg = '';

        $app_row = $appid ? Zibll_Oauth_App_DB::find_by_appid($appid) : null;
        $site = $app_row ? Zibll_Oauth_App_DB::to_site_array($app_row) : array();

        if (!$app_row || empty($site['enabled']) || empty($site['finance_enabled'])) {
            $deduct_result = false;
            $error_msg = '应用不可用或未开启财务权限';
        } elseif ($user_id <= 0 || $amount <= 0 || $order_no === '' || $trade_no === '') {
            $deduct_result = false;
            $error_msg = '扣款记录数据不完整';
        } elseif (!Zibll_Oauth_Grant::is_granted($appid, $user_id, true)) {
            $deduct_result = false;
            $error_msg = '用户未授权财务权限';
        } elseif (!function_exists('zibpay_get_user_balance') || !function_exists('zibpay_deduct_user_balance')) {
            $deduct_result = false;
            $error_msg = '支付系统不可用';
        } else {
            $current_balance = (float) zibpay_get_user_balance($user_id);
            if ($current_balance < $amount) {
                $deduct_result = false;
                $error_msg = '用户余额不足';
            } else {
                $app_title = !empty($site['title']) ? (string) $site['title'] : '三方';
                $deduct_result = zibpay_deduct_user_balance($user_id, $amount, $order_no, $app_title);
                if (!$deduct_result) {
                    $error_msg = '扣除余额失败';
                }
            }
        }

        $status = $deduct_result ? 1 : 2;
        $wpdb->update($deduct_table, array(
            'status' => $status,
            'error_msg' => $error_msg,
            'updated_at' => current_time('mysql'),
        ), array('id' => $deduct_id), array('%d', '%s', '%s'), array('%d'));

        $balance_after = 0.0;
        if (function_exists('zibpay_get_user_balance')) {
            $balance_after = (float) zibpay_get_user_balance($user_id);
        }

        if ($deduct_result && class_exists('ZibPay') && method_exists('ZibPay', 'add_order') && isset($wpdb->zibpay_order_meta)) {
            $exists_order_id = (int) $wpdb->get_var($wpdb->prepare(
                "SELECT order_id FROM {$wpdb->zibpay_order_meta} WHERE meta_key = %s AND meta_value = %s LIMIT 1",
                'zibll_oauth_trade_no',
                (string) $trade_no
            ));

            if ($exists_order_id <= 0) {
                $order_type = function_exists('zib_shop_get_order_type') ? (string) zib_shop_get_order_type() : 'shop';
                $order_data = array(
                    'product_title' => $product_name,
                    'pay_modo' => 'price',
                    'count' => 1,
                    'prices' => array(
                        'unit_price' => (float) $amount,
                        'pay_price' => (float) $amount,
                    ),
                    'third_party' => array(
                        'appid' => $appid,
                        'openid' => $openid,
                        'order_no' => $order_no,
                        'trade_no' => $trade_no,
                    ),
                );

                $created = ZibPay::add_order(array(
                    'user_id' => $user_id,
                    'post_id' => 0,
                    'count' => 1,
                    'order_price' => (float) $amount,
                    'order_type' => $order_type,
                    'pay_type' => 'balance',
                    'pay_num' => (string) $trade_no,
                    'pay_price' => (float) $amount,
                    'pay_time' => current_time('mysql'),
                    'status' => 1,
                    'meta' => array(
                        'order_data' => $order_data,
                        'shipping_status' => 2,
                        'shipping_data' => array(
                            'delivery_type' => 'no_express',
                            'delivery_time' => current_time('mysql'),
                            'delivery_remark' => '无需发货',
                        ),
                        'zibll_oauth_trade_no' => (string) $trade_no,
                    ),
                ));

                if (is_array($created) && !empty($created['id'])) {
                    ZibPay::update_meta((int) $created['id'], 'zibll_oauth_trade_no', (string) $trade_no);
                }
            }
        }

        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            $summary = $deduct_result
                ? sprintf('扣款成功：订单号 %s，金额 %.2f', $order_no, $amount)
                : sprintf('扣款失败：订单号 %s，金额 %.2f，原因：%s', $order_no, $amount, $error_msg);
            Zibll_Oauth_Admin_Log::add_log($appid, $user_id, 'finance_deduct', $summary);
        }

        if (!function_exists('wp_remote_post') || empty($site['appkey'])) {
            return;
        }

        // 扣款结果回调
        if (!empty($site['finance_deduct_callback_url'])) {
            $callback_url = (string) $site['finance_deduct_callback_url'];
            if (class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url') && Zibll_Oauth_Provider_Util::is_safe_callback_url($callback_url)) {
                $callback_data = array(
                    'appid' => $appid,
                    'openid' => $openid,
                    'order_no' => $order_no,
                    'trade_no' => $trade_no,
                    'amount' => (float) $amount,
                    'status' => $deduct_result ? 'success' : 'failed',
                    'balance' => (float) $balance_after,
                );
                $callback_data = self::finalize_callback_payload($callback_data, $site['appkey']);
                self::dedupe_and_enqueue_callback('finance_deduct', $appid, $callback_url, $callback_data);
            }
        }

        // 统一扣款回调（历史）
        if (!empty($site['finance_callback_url'])) {
            $callback_url = (string) $site['finance_callback_url'];
            if (class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url') && Zibll_Oauth_Provider_Util::is_safe_callback_url($callback_url)) {
                $callback_data = array(
                    'appid' => $appid,
                    'openid' => $openid,
                    'order_no' => $order_no,
                    'trade_no' => $trade_no,
                    'product_name' => $product_name,
                    'amount' => (float) $amount,
                    'status' => $deduct_result ? 'success' : 'failed',
                );
                $callback_data = self::finalize_callback_payload($callback_data, $site['appkey']);
                self::dedupe_and_enqueue_callback('finance', $appid, $callback_url, $callback_data);
            }
        }
    }

    private static function callback_job_key($job_id)
    {
        return 'zibll_oauth_cbjob_' . md5((string) $job_id);
    }

    public static function finance_verify(WP_REST_Request $request)
    {
        $token = '';
        $auth = $request->get_header('authorization');
        if (is_string($auth) && stripos($auth, 'bearer ') === 0) {
            $token = trim(substr($auth, 7));
        }

        if ($token === '') {
            return new WP_Error('missing_token', '缺少 access_token（请使用 Authorization: Bearer <token>）', array('status' => 401));
        }

        $data = get_transient(self::token_key($token));
        if (!$data || !is_array($data)) {
            return new WP_Error('token_invalid', 'access_token 无效或已过期', array('status' => 401));
        }

        if (empty($data['appid'])) {
            return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 appid', array('status' => 401));
        }

        $appid = (string) $data['appid'];

        $trade_no = trim((string) $request->get_param('trade_no'));
        $order_no = trim((string) $request->get_param('order_no'));

        if ($trade_no === '' && $order_no === '') {
            return new WP_Error('missing_param', '缺少必要参数：trade_no 或 order_no', array('status' => 400));
        }

        global $wpdb;
        $deduct_table = $wpdb->prefix . 'zibll_oauth_deduct';

        // 应用 IP 白名单校验（若有配置）
        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if ($app_row) {
            $site = Zibll_Oauth_App_DB::to_site_array($app_row);
            $client_ip = Zibll_Oauth_Provider_Util::client_ip();
            if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
                return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403, 'ip' => $client_ip));
            }
        }

        $where = '';
        $params = array();
        if ($trade_no !== '') {
            $where = 'WHERE trade_no = %s';
            $params[] = $trade_no;
        } else {
            $where = 'WHERE order_no = %s';
            $params[] = $order_no;
        }

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$deduct_table} {$where} AND appid = %s LIMIT 1",
            array_merge($params, array($appid))
        ), ARRAY_A);

        if (!$row) {
            return new WP_Error('not_found', '扣款记录不存在', array('status' => 404));
        }

        if (isset($row['status']) && (int) $row['status'] === 0) {
            $id = !empty($row['id']) ? (int) $row['id'] : 0;
            if ($id > 0) {
                $buf = '';
                if (function_exists('ob_start')) {
                    ob_start();
                }
                self::cron_finance_deduct_process($id);
                if (function_exists('ob_get_clean')) {
                    $buf = (string) ob_get_clean();
                }
                if (trim($buf) !== '') {
                    error_log('[zibll-oauth] finance_verify buffered output: ' . substr(trim($buf), 0, 300));
                }
                $row2 = $wpdb->get_row($wpdb->prepare(
                    "SELECT * FROM {$deduct_table} WHERE id = %d LIMIT 1",
                    $id
                ), ARRAY_A);
                if ($row2 && is_array($row2)) {
                    $row = $row2;
                }
            }
        }

        $status_map = array(
            0 => 'processing',
            1 => 'success',
            2 => 'failed',
        );

        $status_code = (int) $row['status'];
        $status_text = isset($status_map[$status_code]) ? $status_map[$status_code] : 'unknown';

        $result = array(
            'trade_no' => (string) $row['trade_no'],
            'order_no' => (string) $row['order_no'],
            'product_name' => (string) $row['product_name'],
            'amount' => (float) $row['amount'],
            'status' => $status_text,
            'error_msg' => (string) $row['error_msg'],
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        );

		return new WP_REST_Response($result, 200);
	}

	public static function finance_sign_status(WP_REST_Request $request)
	{
		$token = '';
		$auth = $request->get_header('authorization');
		if (is_string($auth) && stripos($auth, 'bearer ') === 0) {
			$token = trim(substr($auth, 7));
		}

		if ($token === '') {
			return new WP_Error('missing_token', '缺少 access_token（请使用 Authorization: Bearer <token>）', array('status' => 401));
		}

		$data = get_transient(self::token_key($token));
		if (!$data || !is_array($data)) {
			return new WP_Error('token_invalid', 'access_token 无效或已过期', array('status' => 401));
		}

		if (empty($data['user_id'])) {
			return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 user_id', array('status' => 401));
		}

		$appid = !empty($data['appid']) ? (string) $data['appid'] : '';
		if ($appid === '') {
			return new WP_Error('token_invalid', 'access_token 数据不完整：缺少 appid', array('status' => 401));
		}

		$user_id = (int) $data['user_id'];

		$app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
		if (!$app_row) {
			return new WP_Error('invalid_appid', 'AppID 无效或未配置', array('status' => 403));
		}

		$site = Zibll_Oauth_App_DB::to_site_array($app_row);

		// 应用 IP 白名单校验（若有配置）
		$client_ip = Zibll_Oauth_Provider_Util::client_ip();
		if (!Zibll_Oauth_Provider_Util::is_ip_allowed_for_site($site, $client_ip)) {
			return new WP_Error('ip_not_allowed', '当前 IP 不在应用 IP 白名单中', array('status' => 403, 'ip' => $client_ip));
		}

		$openid = Zibll_Oauth_Provider_Util::get_openid($user_id, $appid);
		if ($openid === '') {
			return new WP_Error('openid_error', 'OpenID 生成失败', array('status' => 500));
		}

		$grant = Zibll_Oauth_Grant::get_by_appid_user($appid, $user_id);

		$is_signed = false;
		$scope = '';
		$finance_scope = 0;
		$status = 0;
		$created_at = '';
		$authorized_at = '';

		if ($grant && is_array($grant)) {
			$scope = !empty($grant['scope']) ? (string) $grant['scope'] : '';
			$finance_scope = !empty($grant['finance_scope']) ? (int) $grant['finance_scope'] : 0;
			$status = isset($grant['status']) ? (int) $grant['status'] : 0;
			$created_at = !empty($grant['created_at']) ? (string) $grant['created_at'] : '';
			// 判断是否已签约：状态有效且财务授权已开启
			$is_signed = ($status === 1 && $finance_scope === 1);
		}

		// 获取财务授权时间（从 finance_grant 日志中查找）
		if ($finance_scope === 1 && class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'get_log')) {
			$finance_log = Zibll_Oauth_Admin_Log::get_log($appid, $user_id, 'finance_grant');
			if ($finance_log && !empty($finance_log['created_at'])) {
				$authorized_at = (string) $finance_log['created_at'];
			}
		}

		return new WP_REST_Response(array(
			'openid' => $openid,
			'is_signed' => $is_signed,
			'scope' => $scope,
			'finance_scope' => $finance_scope,
			'status' => $status,
			'created_at' => $created_at,
			'authorized_at' => $authorized_at,
		), 200);
	}
}

/**
 * 扣除用户余额（直接调用 Zibll 主题原有余额更新函数）
 *
 * @param int    $user_id    用户ID
 * @param float  $amount     扣除金额（正数）
 * @param string $order_no   订单号（由接入方自行生成并传入，用于幂等与对账）
 * @param string $app_title  应用标题（自动查询对应应用名称，如"天云港应用"）
 * @return bool  扣款是否成功
 */
function zibpay_deduct_user_balance($user_id, $amount, $order_no, $app_title)
{
    // 基础参数校验（不改动主题原有逻辑，只做防御性检查）
    if ($user_id <= 0 || $amount <= 0 || empty($order_no)) {
        return false;
    }

    // 直接使用主题原有函数，不重新造轮子
    if (!function_exists('zibpay_update_user_balance')) {
        return false;
    }

    // 调用 Zibll 原有余额更新函数：
    // - order_num 使用接入方传入的订单号
    // - value 为负数表示扣款
    // - type 为应用标题+扣款（如"天云港应用扣款"）
    // - desc 为说明文案
    $result = zibpay_update_user_balance($user_id, array(
        'order_num' => (string) $order_no,
        'value'     => -$amount,
        'type'      => $app_title . '扣款',
        'desc'      => '第三方应用扣款',
    ));

    return $result !== false;
}
