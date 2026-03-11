<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Install
{
    public static function activate()
    {
        self::create_tables();
        if (function_exists('flush_rewrite_rules')) {
            flush_rewrite_rules();
        }
    }

    public static function init()
    {
        add_action('init', array(__CLASS__, 'maybe_upgrade'), 5);
    }

    public static function maybe_upgrade()
    {
        self::create_tables();
    }

    private static function create_tables()
    {
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $app_table = $wpdb->prefix . 'zibll_oauth_app';
        $sql_app = "CREATE TABLE {$app_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            title VARCHAR(191) NOT NULL DEFAULT '',
            icon TEXT NULL,
            redirect_uri TEXT NULL,
            default_scope VARCHAR(255) NOT NULL DEFAULT 'basic',
            appid VARCHAR(64) NOT NULL DEFAULT '',
            appkey VARCHAR(64) NOT NULL DEFAULT '',
            finance_enabled TINYINT(1) NOT NULL DEFAULT 0,
            finance_callback_url TEXT NULL,
            finance_deduct_callback_url TEXT NULL,
            revoke_callback_url TEXT NULL,
            ip_whitelist TEXT NULL,
            status TINYINT(3) NOT NULL DEFAULT 0,
            appkey_revealed TINYINT(1) NOT NULL DEFAULT 0,
            reject_reason TEXT NULL,
            created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            updated_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            PRIMARY KEY  (id),
            UNIQUE KEY appid (appid),
            KEY user_id (user_id),
            KEY status (status),
            KEY created_at (created_at)
        ) {$charset};";

        dbDelta($sql_app);

        $grant_table = $wpdb->prefix . 'zibll_oauth_grant';
        $sql_grant = "CREATE TABLE {$grant_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            app_post_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            appid VARCHAR(64) NOT NULL DEFAULT '',
            user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            scope VARCHAR(255) NOT NULL DEFAULT '',
            finance_scope TINYINT(1) NOT NULL DEFAULT 0,
            status TINYINT(1) NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            PRIMARY KEY  (id),
            KEY appid (appid),
            KEY user_id (user_id),
            KEY created_at (created_at),
            KEY app_user (appid, user_id),
            KEY status (status)
        ) {$charset};";

        dbDelta($sql_grant);

        $deduct_table = $wpdb->prefix . 'zibll_oauth_deduct';
        $sql_deduct = "CREATE TABLE {$deduct_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            appid VARCHAR(64) NOT NULL DEFAULT '',
            user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            openid VARCHAR(64) NOT NULL DEFAULT '',
            product_name VARCHAR(255) NOT NULL DEFAULT '',
            amount DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
            order_no VARCHAR(64) NOT NULL DEFAULT '',
            trade_no VARCHAR(64) NOT NULL DEFAULT '',
            trade_type VARCHAR(32) NOT NULL DEFAULT 'third_party',
            status TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0:待处理, 1:成功, 2:失败',
            error_msg TEXT NULL,
            created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            updated_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            PRIMARY KEY  (id),
            UNIQUE KEY trade_no (trade_no),
            KEY appid (appid),
            KEY user_id (user_id),
            KEY openid (openid),
            KEY order_no (order_no),
            KEY status (status),
            KEY created_at (created_at)
        ) {$charset};";

        dbDelta($sql_deduct);

        $audit_table = $wpdb->prefix . 'zibll_oauth_audit';
        $sql_audit = "CREATE TABLE {$audit_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            appid VARCHAR(64) NOT NULL DEFAULT '',
            user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            action VARCHAR(64) NOT NULL DEFAULT '',
            summary TEXT NULL,
            ip VARCHAR(64) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            PRIMARY KEY (id),
            KEY appid (appid),
            KEY user_id (user_id),
            KEY created_at (created_at)
        ) {$charset};";

        dbDelta($sql_audit);
    }
}
