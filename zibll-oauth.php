<?php
/**
 * Plugin Name: Zibll OAuth
 * Description: OAuth2 代理服务插件（参考 QQ Connect 的 OAuth 流程），向外部站点提供统一的授权/回调能力。
 * Version: 1.2.0
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/util.php';
require_once __DIR__ . '/includes/options.php';
require_once __DIR__ . '/includes/install.php';
require_once __DIR__ . '/includes/app-db.php';
require_once __DIR__ . '/includes/grant.php';
require_once __DIR__ . '/includes/ajax.php';
require_once __DIR__ . '/includes/user-center.php';
require_once __DIR__ . '/includes/admin.php';
require_once __DIR__ . '/includes/admin-audit.php';
require_once __DIR__ . '/includes/admin-log.php';
require_once __DIR__ . '/includes/service.php';
require_once __DIR__ . '/includes/rest.php';
require_once __DIR__ . '/includes/rest-points.php';
require_once __DIR__ . '/includes/rest-usermeta.php';

final class Zibll_OAuth_Plugin
{
    public static function init()
    {
        Zibll_Oauth_Install::init();
        Zibll_Oauth_Ajax::init();
        Zibll_Oauth_User_Center::init();
        Zibll_Oauth_Admin_Audit::init();
        Zibll_Oauth_Admin_Log::init();

        add_action('rest_api_init', array('Zibll_Oauth_Rest', 'register_routes'));
        add_action('wp_ajax_zibll_oauth_approve', array('Zibll_Oauth_Service', 'ajax_approve'));
        add_action('wp_ajax_nopriv_zibll_oauth_approve', array('Zibll_Oauth_Service', 'ajax_approve'));
        add_action('wp_ajax_zibll_oauth_finance_approve', array('Zibll_Oauth_Service', 'ajax_finance_approve'));
        add_action('wp_ajax_nopriv_zibll_oauth_finance_approve', array('Zibll_Oauth_Service', 'ajax_finance_approve'));

        add_action('zibll_oauth_finance_deduct_process', array('Zibll_Oauth_Service', 'cron_finance_deduct_process'), 10, 1);
        add_action('zibll_oauth_callback_send', array('Zibll_Oauth_Service', 'cron_callback_send'), 10, 1);

        add_action('zib_require_end', array('Zibll_Oauth_Admin', 'register_csf_options'), 20);
        add_action('admin_init', array('Zibll_Oauth_Admin', 'register_csf_options'), 20);
        add_filter('csf_zibll_oauth_options_save', array('Zibll_Oauth_Admin', 'filter_csf_save'));
    }
}

register_activation_hook(__FILE__, array('Zibll_Oauth_Install', 'activate'));

Zibll_OAuth_Plugin::init();
