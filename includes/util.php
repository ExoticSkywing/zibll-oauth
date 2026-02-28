<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Provider_Util
{
    const CACHE_GROUP = 'zibll_oauth';

    private static function debug_enabled()
    {
        return defined('ZIBLL_OAUTH_DEBUG') && ZIBLL_OAUTH_DEBUG;
    }

    private static function debug_log($action, $context = array())
    {
        if (!self::debug_enabled()) {
            return;
        }

        $action = trim((string) $action);
        if ($action === '') {
            $action = 'debug';
        }

        if (!is_array($context)) {
            $context = array('context' => (string) $context);
        }

        $payload = array_merge(array(
            'plugin' => 'zibll-oauth',
            'action' => $action,
            'time' => time(),
        ), $context);

        $line = wp_json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($line) || $line === '') {
            $line = '[zibll-oauth] ' . $action;
        }

        error_log('[zibll-oauth] ' . $line);
    }

    public static function random_token($length = 32)
    {
        $length = (int) $length;
        if ($length < 8) {
            $length = 8;
        }
        return wp_generate_password($length, false, false);
    }

    public static function send_html($html, $status = 200)
    {
        if (!headers_sent()) {
            status_header((int) $status);
            header('Content-Type: text/html; charset=UTF-8');
        }
        echo (string) $html;
        exit;
    }

    public static function redirect($url, $status = 302)
    {
        wp_safe_redirect((string) $url, (int) $status);
        exit;
    }

    public static function is_valid_redirect_uri($url)
    {
        $url = trim((string) $url);
        if ($url === '') {
            return false;
        }

        if (!function_exists('wp_parse_url')) {
            return false;
        }

        $p = wp_parse_url($url);
        if (!is_array($p)) {
            return false;
        }

        $scheme = !empty($p['scheme']) ? strtolower((string) $p['scheme']) : '';
        if (!in_array($scheme, array('http', 'https'), true)) {
            return false;
        }

        $host = !empty($p['host']) ? (string) $p['host'] : '';
        if ($host === '') {
            return false;
        }

        $host_l = strtolower((string) $host);
        if ($host_l === 'localhost' || substr($host_l, -10) === '.localhost') {
            return false;
        }

        if (!empty($p['user']) || !empty($p['pass'])) {
            return false;
        }

        $check_ip = function ($ip) {
            $ip = trim((string) $ip);
            if ($ip === '') {
                return false;
            }
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }
            return true;
        };

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $check_ip($host);
        }

        $resolved = gethostbyname($host);
        if (!is_string($resolved) || $resolved === '' || $resolved === $host) {
            return false;
        }
        if (!$check_ip($resolved)) {
            return false;
        }

        return true;
    }

    public static function render_zibll_error_fragment($message, $error_code = 'error', $ys = 'danger')
    {
        $message = (string) $message;
        $error_code = (string) $error_code;
        $ys = $ys ? (string) $ys : 'danger';

        if (function_exists('zib_get_ajax_error_html')) {
            $html = zib_get_ajax_error_html(array(
                'error' => $error_code,
                'ys' => $ys,
                'msg' => $message,
            ));

            $html = str_replace('<body><main>', '', $html);
            $html = str_replace('</main></body>', '', $html);
            return $html;
        }

        return '<div class="ajaxpager"><div class="ajax-item text-center text-' . esc_attr($ys) . '" style="padding:50px 0;">错误：' . esc_html($message) . '，错误代码：' . esc_html($error_code) . '</div></div>';
    }

    public static function render_zibll_theme_page($title, $content)
    {
        $title = (string) $title;
        $content = (string) $content;

        if (!function_exists('wp_head') || !function_exists('wp_footer')) {
            return $content;
        }

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
            wp_footer();
            echo '</body></html>';
        }

        return (string) ob_get_clean();
    }

    public static function generate_appid()
    {
        $rand = wp_generate_password(14, false, false);
        return 'zo_' . strtolower($rand);
    }

    public static function generate_appkey()
    {
        return wp_generate_password(32, false, false);
    }

    public static function get_openid($user_id, $appid)
    {
        $user_id = (int) $user_id;
        $appid_raw = trim((string) $appid);
        $appid = strtolower($appid_raw);
        if ($user_id <= 0 || $appid === '') {
            return '';
        }

        $cache_key = 'openid:' . md5($appid) . ':' . $user_id;
        $cached = wp_cache_get($cache_key, self::CACHE_GROUP);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $key = self::openid_meta_key($appid);
        $openid = (string) get_user_meta($user_id, $key, true);
        if ($openid !== '') {
            wp_cache_set($cache_key, $openid, self::CACHE_GROUP, 3600);
            return $openid;
        }

        if ($appid_raw !== '' && $appid_raw !== $appid) {
            $legacy_key = self::openid_meta_key($appid_raw);
            if ($legacy_key !== $key) {
                $legacy_openid = (string) get_user_meta($user_id, $legacy_key, true);
                if ($legacy_openid !== '') {
                    update_user_meta($user_id, $key, $legacy_openid);
                    wp_cache_set($cache_key, $legacy_openid, self::CACHE_GROUP, 3600);
                    return $legacy_openid;
                }
            }
        }

        $openid = 'oid_' . strtolower(wp_generate_password(28, false, false));
        $saved = update_user_meta($user_id, $key, $openid);
        if ($saved !== false) {
            wp_cache_set($cache_key, $openid, self::CACHE_GROUP, 3600);
            return $openid;
        }

        self::debug_log('openid_persist_failed', array(
            'user_id' => $user_id,
            'appid_raw' => $appid_raw,
            'appid_norm' => $appid,
            'meta_key' => $key,
        ));

        $fallback = self::deterministic_openid($appid, $user_id);
        wp_cache_set($cache_key, $fallback, self::CACHE_GROUP, 3600);
        return $fallback;
    }

    public static function deterministic_openid($appid, $user_id)
    {
        $appid = strtolower(trim((string) $appid));
        $user_id = (int) $user_id;
        if ($appid === '' || $user_id <= 0) {
            return '';
        }

        $salt = function_exists('wp_salt') ? (string) wp_salt('auth') : '';
        $hash = hash_hmac('sha256', $appid . '|' . (string) $user_id, $salt);
        return 'oid_' . substr(strtolower($hash), 0, 28);
    }

    private static function openid_meta_key($appid)
    {
        return 'zibll_oauth_openid_' . md5((string) $appid);
    }

    /**
     * 根据 AppID + OpenID 反查用户 ID
     *
     * - 不直接操作 MySQL，使用 WP_User_Query & 用户 meta
     * - 若未找到或参数非法，返回 0
     */
    public static function get_user_id_by_openid($appid, $openid)
    {
        $appid_raw = trim((string) $appid);
        $appid = strtolower($appid_raw);
        $openid = trim((string) $openid);
        if ($appid === '' || $openid === '') {
            return 0;
        }

        $meta_key = self::openid_meta_key($appid);

        if (!class_exists('WP_User_Query')) {
            return 0;
        }

        $query = new WP_User_Query(array(
            'number' => 1,
            'fields' => 'ids',
            'meta_query' => array(
                array(
                    'key' => $meta_key,
                    'value' => $openid,
                    'compare' => '=',
                ),
            ),
        ));

        $ids = $query->get_results();
        if (is_array($ids) && !empty($ids)) {
            return (int) $ids[0];
        }

        self::debug_log('openid_lookup_miss', array(
            'appid_raw' => $appid_raw,
            'appid_norm' => $appid,
            'meta_key' => $meta_key,
            'openid_prefix' => substr($openid, 0, 12),
        ));

        if ($appid_raw !== '' && $appid_raw !== $appid) {
            $legacy_key = self::openid_meta_key($appid_raw);
            if ($legacy_key !== $meta_key) {
                $legacy_query = new WP_User_Query(array(
                    'number' => 1,
                    'fields' => 'ids',
                    'meta_query' => array(
                        array(
                            'key' => $legacy_key,
                            'value' => $openid,
                            'compare' => '=',
                        ),
                    ),
                ));
                $legacy_ids = $legacy_query->get_results();
                if (is_array($legacy_ids) && !empty($legacy_ids)) {
                    return (int) $legacy_ids[0];
                }

                self::debug_log('openid_lookup_miss_legacy', array(
                    'appid_raw' => $appid_raw,
                    'appid_norm' => $appid,
                    'legacy_meta_key' => $legacy_key,
                    'openid_prefix' => substr($openid, 0, 12),
                ));
            }
        }

        return 0;
    }

    public static function canonical_query_string($params)
    {
        if (!is_array($params)) {
            $params = array();
        }

        if (isset($params['sign'])) {
            unset($params['sign']);
        }

        if (isset($params['sign2'])) {
            unset($params['sign2']);
        }

        ksort($params);

        $pairs = array();
        foreach ($params as $k => $v) {
            if (is_array($v) || is_object($v)) {
                $v = wp_json_encode($v);
            }
            $pairs[] = rawurlencode((string) $k) . '=' . rawurlencode((string) $v);
        }

        return implode('&', $pairs);
    }

    public static function sign_hmac_sha256_v2($params, $appkey)
    {
        if (!is_array($params)) {
            $params = array();
        }

        $timestamp = isset($params['timestamp']) ? (int) $params['timestamp'] : 0;
        $nonce = isset($params['nonce']) ? (string) $params['nonce'] : '';
        if ($timestamp <= 0 || trim($nonce) === '') {
            return '';
        }

        $canonical = self::canonical_query_string($params);
        if ($canonical === '') {
            return '';
        }

        return hash_hmac('sha256', $canonical, (string) $appkey);
    }

    public static function verify_sign_v2($params, $appkey, $sign)
    {
        $sign = strtolower(trim((string) $sign));
        if (!(strlen($sign) === 64 && ctype_xdigit($sign))) {
            return false;
        }

        $timestamp = isset($params['timestamp']) ? (int) $params['timestamp'] : 0;
        if ($timestamp <= 0) {
            return false;
        }

        $nonce = isset($params['nonce']) ? (string) $params['nonce'] : '';
        if (trim($nonce) === '') {
            return false;
        }

        $current_time = time();
        $time_diff = abs($current_time - $timestamp);
        if ($time_diff > 300) {
            return false;
        }

        $expected = self::sign_hmac_sha256_v2($params, $appkey);
        return $expected !== '' && hash_equals($expected, $sign);
    }

    public static function nonce_key($appid, $nonce)
    {
        $appid = trim((string) $appid);
        $nonce = trim((string) $nonce);
        if ($appid === '' || $nonce === '') {
            return '';
        }
        return 'zibll_oauth_nonce_' . md5($appid . '|' . $nonce);
    }

    public static function consume_nonce_once($appid, $nonce, $ttl)
    {
        $key = self::nonce_key($appid, $nonce);
        if ($key === '') {
            return false;
        }

        $used = get_transient($key);
        if (!empty($used)) {
            return false;
        }

        $ttl = (int) $ttl;
        if ($ttl <= 0) {
            $ttl = 300;
        }

        set_transient($key, 1, $ttl);
        return true;
    }

    public static function verify_sign($params, $appkey, $sign)
    {
        return self::verify_sign_v2($params, $appkey, $sign);
    }

    public static function is_safe_callback_url($url)
    {
        $url = trim((string) $url);
        if ($url === '') {
            return false;
        }

        if (function_exists('wp_http_validate_url')) {
            $v = wp_http_validate_url($url);
            if (!$v) {
                return false;
            }
        }

        if (!function_exists('wp_parse_url')) {
            return false;
        }

        $p = wp_parse_url($url);
        if (!is_array($p)) {
            return false;
        }

        $scheme = !empty($p['scheme']) ? strtolower((string) $p['scheme']) : '';
        if (!in_array($scheme, array('http', 'https'), true)) {
            return false;
        }

        $host = !empty($p['host']) ? strtolower((string) $p['host']) : '';
        if ($host === '' || $host === 'localhost' || substr($host, -10) === '.localhost') {
            return false;
        }

        if (!empty($p['user']) || !empty($p['pass'])) {
            return false;
        }

        $check_ip = function ($ip) {
            $ip = trim((string) $ip);
            if ($ip === '') {
                return false;
            }
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }
            return true;
        };

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $check_ip($host);
        }

        $resolved = gethostbyname($host);
        if (!is_string($resolved) || $resolved === '' || $resolved === $host) {
            return false;
        }
        if (!$check_ip($resolved)) {
            return false;
        }

        return true;
    }

    /**
     * 获取当前客户端 IP（尽量简洁，避免过度信任头部）
     */
    public static function client_ip()
    {
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            return (string) $_SERVER['REMOTE_ADDR'];
        }
        return '';
    }

    /**
     * 将应用配置中的 IP 白名单（多行文本）解析为数组
     */
    public static function parse_ip_whitelist($raw)
    {
        $raw = (string) $raw;
        if ($raw === '') {
            return array();
        }

        $lines = preg_split('/\r\n|\r|\n/', $raw);
        $ips = array();
        foreach ((array) $lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }
            $ips[$line] = true;
        }

        return array_keys($ips);
    }

    /**
     * 判断当前 IP 是否在应用 IP 白名单内
     *
     * - 若应用未配置白名单，则默认允许
     * - 当前版本仅支持精确匹配 IPv4/IPv6 字符串，不支持 CIDR
     */
    public static function is_ip_allowed_for_site($site, $ip)
    {
        $site = is_array($site) ? $site : array();
        $ip = trim((string) $ip);
        if ($ip === '') {
            return false;
        }

        $raw = !empty($site['ip_whitelist']) ? (string) $site['ip_whitelist'] : '';
        if ($raw === '') {
            // 未配置白名单，认为不限制
            return true;
        }

        $ips = self::parse_ip_whitelist($raw);
        if (empty($ips)) {
            // 配置为空时同样视为不限制
            return true;
        }

        return in_array($ip, $ips, true);
    }

    public static function scope_share_items($scope)
    {
        $scope = trim((string) $scope);
        if ($scope === '') {
            $scope = 'basic';
        }

        $scopes = preg_split('/[\s,]+/', $scope);
        $items = array(
            'openid' => 'OpenID（应用内用户标识）',
            'name' => '昵称/显示名称',
            'avatar' => '头像',
        );

        if (in_array('email', $scopes, true)) {
            $items['email'] = '邮箱';
        }

        if (in_array('profile', $scopes, true)) {
            $items['profile'] = '个人资料（简介等）';
        }

        if (in_array('phone', $scopes, true)) {
            $items['phone'] = '绑定手机号';
        }

        return $items;
    }

    public static function wp_userinfo_by_scope($user_id, $scope, $appid = '', $include_balance = false)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return new WP_Error('invalid_user', '无效的 user_id', array('status' => 400));
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new WP_Error('user_not_found', '用户不存在', array('status' => 404));
        }

        $scope = trim((string) $scope);
        if ($scope === '') {
            $scope = 'basic';
        }
        $scopes = preg_split('/[\s,]+/', $scope);

        $avatar_url = '';
        if (function_exists('zib_get_user_avatar_url')) {
            $avatar_url = (string) zib_get_user_avatar_url($user->ID);
        } elseif (function_exists('zib_get_user_meta')) {
            $avatar_url = (string) zib_get_user_meta($user->ID, 'custom_avatar', true);
        }
        if ($avatar_url === '') {
            $avatar_url = get_avatar_url($user->ID);
        }

        $openid = self::get_openid($user->ID, $appid);
        if ($openid === '') {
            return new WP_Error('openid_error', 'OpenID 生成失败', array('status' => 500));
        }

        $data = array(
            'openid' => $openid,
            'name' => (string) $user->display_name,
            'avatar' => $avatar_url,
        );

        if (in_array('email', $scopes, true)) {
            $data['email'] = (string) $user->user_email;
        }

        if (in_array('profile', $scopes, true)) {
            $data['description'] = (string) get_user_meta($user->ID, 'description', true);
        }

        if (in_array('phone', $scopes, true)) {
            $phone = '';
            if (function_exists('zib_get_user_phone_number')) {
                $p = zib_get_user_phone_number($user->ID, false);
                if ($p) {
                    $phone = (string) $p;
                }
            }
            if ($phone === '') {
                $phone = (string) get_user_meta($user->ID, 'phone_number', true);
            }
            $data['phone'] = $phone;
        }

        if ($include_balance && function_exists('zibpay_get_user_balance')) {
            $balance = zibpay_get_user_balance($user_id);
            $data['balance'] = (float) $balance;
        }

        return $data;
    }

    public static function render_consent_page($site, $share_items, $deny_url, $hidden_fields)
    {
        $page_title_base = '互联授权';
        $blog_title = function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '';
        $page_title = $blog_title ? ($blog_title . ' - ' . $page_title_base) : $page_title_base;
        $site_title = !empty($site['title']) ? (string) $site['title'] : (!empty($site['site_title']) ? (string) $site['site_title'] : '');
        $icon = !empty($site['icon']) ? (string) $site['icon'] : (!empty($site['site_icon']) ? (string) $site['site_icon'] : '');
        $developer_name = !empty($site['developer_name']) ? (string) $site['developer_name'] : '';

        $share_html = '';
        foreach ((array) $share_items as $k => $label) {
            $share_html .= '<li class="mb6">' . esc_html($label) . '</li>';
        }

        $html = '';
        $html .= '<style>.oauth-page{padding:18px 0}.oauth-site-ico{width:44px;height:44px;border-radius:12px;object-fit:cover}</style>';
        $html .= '<main role="main" class="container oauth-page">';
        $html .= '<div class="zib-widget">';
        $html .= '<div class="box-body">';

        $html .= '<div class="mb10 em12"><b>' . esc_html($page_title) . '</b></div>';

        $html .= '<div class="flex ac mb15">';
        if ($icon) {
            $html .= '<img class="oauth-site-ico" src="' . esc_url($icon) . '" alt="icon">';
        } else {
            $html .= '<span class="oauth-site-ico" style="background:rgba(0,0,0,.06);display:inline-block;"></span>';
        }
        $html .= '<div class="ml10">';
        $html .= '<div class="text-ellipsis"><b>' . esc_html($site_title) . '</b></div>';
        $html .= '<div class="muted-2-color em09">申请互联登录</div>';
        if ($developer_name !== '') {
            $html .= '<div class="muted-2-color em09">开发者：' . esc_html($developer_name) . '</div>';
        }
        $html .= '</div>';
        $html .= '</div>';

        $html .= '<div class="muted-2-color em09 mb10">该站点请求使用本站账号进行登录，同意后将共享以下信息（由授权范围 scope 控制，scope 越大共享越多）：</div>';
        $html .= '<ul class="mt10">' . $share_html . '</ul>';

        $ajax_url = admin_url('admin-ajax.php');
        $html .= '<form class="mt20" method="post" action="' . esc_url($ajax_url) . '">';
        $html .= '<input type="hidden" name="action" value="zibll_oauth_approve">';

        if (is_array($hidden_fields)) {
            foreach ($hidden_fields as $k => $v) {
                $html .= '<input type="hidden" name="' . esc_attr((string) $k) . '" value="' . esc_attr((string) $v) . '">';
            }
        }

        if (function_exists('zib_get_machine_verification_input')) {
            $html .= zib_get_machine_verification_input('zibll_oauth_approve', 'canvas_yz');
        } else {
            $html .= '<input type="hidden" name="captcha_mode" value="">';
        }

        $html .= '<div class="but-average radius">';
        $html .= '<a class="but c-red" href="' . esc_url($deny_url) . '">拒绝</a>';
        $html .= '<button type="submit" class="but c-blue wp-ajax-submit">同意</button>';
        $html .= '</div>';
        $html .= '</form>';

        $html .= '<div class="muted-2-color em09 mt15">拒绝后将尝试关闭当前页面（若浏览器限制自动关闭，请手动关闭）。</div>';

        $html .= '</div>';
        $html .= '</div>';
        $html .= '</main>';

        return $html;
    }

    public static function render_close_page($message)
    {
        $message = esc_html((string) $message);
        $html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        $html .= '<title>关闭</title></head><body>';
        $html .= '<div style="padding:20px;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;">' . $message . '</div>';
        $html .= '<script>try{window.close();}catch(e){};</script>';
        $html .= '</body></html>';
        return $html;
    }

    public static function render_finance_consent_page($site, $deny_url, $hidden_fields)
    {
        $page_title_base = '财务授权';
        $blog_title = function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '';
        $page_title = $blog_title ? ($blog_title . ' - ' . $page_title_base) : $page_title_base;
        $site_title = !empty($site['title']) ? (string) $site['title'] : '';
        $icon = !empty($site['icon']) ? (string) $site['icon'] : '';
        $developer_name = !empty($site['developer_name']) ? (string) $site['developer_name'] : '';

        $html = '';
        $html .= '<style>.oauth-page{padding:18px 0}.oauth-site-ico{width:44px;height:44px;border-radius:12px;object-fit:cover}</style>';
        $html .= '<main role="main" class="container oauth-page">';
        $html .= '<div class="zib-widget">';
        $html .= '<div class="box-body">';

        $html .= '<div class="mb10 em12"><b>' . esc_html($page_title) . '</b></div>';

        $html .= '<div class="flex ac mb15">';
        if ($icon) {
            $html .= '<img class="oauth-site-ico" src="' . esc_url($icon) . '" alt="icon">';
        } else {
            $html .= '<span class="oauth-site-ico" style="background:rgba(0,0,0,.06);display:inline-block;"></span>';
        }
        $html .= '<div class="ml10">';
        $html .= '<div class="text-ellipsis"><b>' . esc_html($site_title) . '</b></div>';
        $html .= '<div class="muted-2-color em09">开发者：' . esc_html($developer_name) . '</div>';
        $html .= '</div>';
        $html .= '</div>';

        $html .= '<div class="mb10"><b>' . esc_html($site_title) . '免密支付</b></div>';
        $html .= '<div class="mb10">开发者：' . esc_html($developer_name) . '</div>';
        $html .= '<div class="muted-2-color em09">' . esc_html($site_title) . '免密快速支付，提交订单之后根据订单金额实时扣费，便捷结账轻松支付，免密业务可随时取消。</div>';

        $ajax_url = admin_url('admin-ajax.php');
        $html .= '<form class="mt20" method="post" action="' . esc_url($ajax_url) . '">';
        $html .= '<input type="hidden" name="action" value="zibll_oauth_finance_approve">';

        if (is_array($hidden_fields)) {
            foreach ($hidden_fields as $k => $v) {
                $html .= '<input type="hidden" name="' . esc_attr((string) $k) . '" value="' . esc_attr((string) $v) . '">';
            }
        }

        if (function_exists('zib_get_machine_verification_input')) {
            $html .= zib_get_machine_verification_input('zibll_oauth_finance_approve', 'canvas_yz');
        }

        $html .= '<div class="but-average radius">';
        $html .= '<a class="but c-red" href="' . esc_url($deny_url) . '">拒绝</a>';
        $html .= '<button type="submit" class="but c-blue wp-ajax-submit">同意</button>';
        $html .= '</div>';
        $html .= '</form>';

        $html .= '<div class="muted-2-color em09 mt15">拒绝后将尝试关闭当前页面（若浏览器限制自动关闭，请手动关闭）。</div>';

        $html .= '</div>';
        $html .= '</div>';
        $html .= '</main>';

        return $html;
    }

    public static function render_error_page($message)
    {
        $message = esc_html((string) $message);
        $title = 'OAuth 登录失败';

        $primary = '#fd4c73';
        if (function_exists('zib_get_theme_colors')) {
            $colors = zib_get_theme_colors();
            if (!empty($colors['primary'])) {
                $primary = $colors['primary'];
            }
        }

        $html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        $html .= '<title>' . esc_html($title) . '</title>';
        $html .= '<style>';
        $html .= 'body{margin:0;background:#f7f7f7;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial}';
        $html .= '.wrap{max-width:720px;margin:8vh auto;padding:20px}';
        $html .= '.card{background:#fff;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.06);overflow:hidden}';
        $html .= '.hd{padding:18px 22px;background:' . esc_attr($primary) . ';color:#fff;font-size:18px;font-weight:600}';
        $html .= '.bd{padding:18px 22px;color:#333;line-height:1.6}';
        $html .= '.tip{margin-top:12px;color:#666;font-size:13px}';
        $html .= '</style></head><body>';
        $html .= '<div class="wrap"><div class="card"><div class="hd">' . esc_html($title) . '</div><div class="bd">';
        $html .= '<div>' . $message . '</div>';
        $html .= '<div class="tip">请返回发起登录的站点重新操作，或联系站点管理员检查 AppID/回调域名白名单/上游配置。</div>';
        $html .= '</div></div></div>';
        $html .= '</body></html>';
        return $html;
    }
}
