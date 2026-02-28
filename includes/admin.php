<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Admin
{
    private static $csf_registered = false;

    public static function register_csf_options()
    {
        if (self::$csf_registered) {
            return;
        }

        if (!class_exists('CSF')) {
            return;
        }

        if (!is_admin()) {
            return;
        }

        self::$csf_registered = true;

        CSF::createOptions('zibll_oauth_options', array(
            'menu_title'         => 'Zibll OAuth',
            'menu_slug'          => 'zibll-oauth',
            'framework_title'    => 'Zibll OAuth',
            'show_in_customizer' => false,
            'theme'              => 'light',
        ));

        CSF::createSection('zibll_oauth_options', array(
            'title'  => '基础设置',
            'icon'   => 'fa fa-fw fa-unlock-alt',
            'fields' => array(
                array(
                    'id'       => 'zibll_oauth_developer_whitelist',
                    'type'     => 'textarea',
                    'title'    => '开发者白名单',
                    'subtitle' => '允许申请/管理 OAuth 应用的用户',
                    'desc'     => '每行一个：用户ID或邮箱。例如：\n1\nuser@example.com\n2',
                    'default'  => '',
                    'attributes' => array(
                        'rows' => 6,
                    ),
                ),
                array(
                    'id'       => 'zibll_oauth_finance_whitelist',
                    'type'     => 'textarea',
                    'title'    => '财务权限白名单',
                    'subtitle' => '允许申请财务权限的用户（开发者白名单中的用户默认可申请）',
                    'desc'     => '每行一个：用户ID或邮箱。留空则只允许管理员拥有财务权限。例如：\n1\nuser@example.com\n2',
                    'default'  => '',
                    'attributes' => array(
                        'rows' => 6,
                    ),
                ),
                array(
                    'id'      => 'zibll_oauth_code_expires',
                    'type'    => 'spinner',
                    'title'   => '授权码有效期',
                    'default' => 300,
                    'min'     => 30,
                    'max'     => 3600,
                    'step'    => 10,
                    'unit'    => '秒',
                ),
                array(
                    'id'      => 'zibll_oauth_token_expires',
                    'type'    => 'spinner',
                    'title'   => 'Access Token 有效期',
                    'default' => 7200,
                    'min'     => 60,
                    'max'     => 86400,
                    'step'    => 60,
                    'unit'    => '秒',
                ),
            ),
        ));
    }

    public static function filter_csf_save($new_instance)
    {
        if (!is_array($new_instance)) {
            return $new_instance;
        }

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete('options:zibll_oauth_options', Zibll_Oauth_Options::CACHE_GROUP);
            if (class_exists('Zibll_Oauth_Options') && method_exists('Zibll_Oauth_Options', 'cache_delete')) {
                Zibll_Oauth_Options::cache_delete('developer_whitelist');
            }
        }

        return $new_instance;
    }

    public static function ajax_rotate_appkey()
    {
        if (!function_exists('current_user_can') || !current_user_can('manage_options')) {
            wp_send_json_error(array('msg' => '权限不足'));
        }

        $nonce = isset($_POST['_wpnonce']) ? (string) $_POST['_wpnonce'] : '';
        if (!function_exists('wp_verify_nonce') || !wp_verify_nonce($nonce, 'zibll_oauth_rotate_appkey')) {
            wp_send_json_error(array('msg' => '安全验证失败'));
        }

        $appid = isset($_POST['appid']) ? trim((string) $_POST['appid']) : '';
        if ($appid === '') {
            wp_send_json_error(array('msg' => '缺少 appid'));
        }

        $opt = get_option(Zibll_Oauth_Options::OPTIONS_KEY);
        $opt = is_array($opt) ? $opt : array();
        $sites = isset($opt['zibll_oauth_sites']) && is_array($opt['zibll_oauth_sites']) ? $opt['zibll_oauth_sites'] : array();

        $new_key = Zibll_Oauth_Provider_Util::generate_appkey();
        $found = false;

        foreach ($sites as $i => $site) {
            if (!is_array($site) || empty($site['appid'])) {
                continue;
            }
            if (hash_equals((string) $site['appid'], $appid)) {
                $sites[$i]['appkey'] = $new_key;
                $found = true;
                break;
            }
        }

        if (!$found) {
            wp_send_json_error(array('msg' => '未找到对应 AppID 的站点配置'));
        }

        $opt['zibll_oauth_sites'] = $sites;
        update_option(Zibll_Oauth_Options::OPTIONS_KEY, $opt);

        if (function_exists('wp_cache_delete')) {
            wp_cache_delete('options:' . Zibll_Oauth_Options::OPTIONS_KEY, Zibll_Oauth_Options::CACHE_GROUP);
            wp_cache_delete('sites', Zibll_Oauth_Options::CACHE_GROUP);
            wp_cache_delete('site:' . md5($appid), Zibll_Oauth_Options::CACHE_GROUP);
        }

        wp_send_json_success(array('appid' => $appid, 'appkey' => $new_key));
    }

    public static function enqueue_admin_assets($hook)
    {
        return;
    }
}
