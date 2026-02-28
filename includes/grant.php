<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Grant
{
    private static function cache_group()
    {
        if (class_exists('Zibll_Oauth_Options') && defined('Zibll_Oauth_Options::CACHE_GROUP')) {
            return Zibll_Oauth_Options::CACHE_GROUP;
        }
        return 'zibll_oauth';
    }

    private static function cache_key_user_grants($user_id)
    {
        return 'grants:user:' . (int) $user_id;
    }

    private static function cache_get($key, &$found = null)
    {
        if (function_exists('wp_cache_get')) {
            $f = false;
            $v = wp_cache_get((string) $key, self::cache_group(), false, $f);
            $found = $f;
            return $v;
        }
        $found = false;
        return null;
    }

    private static function cache_set($key, $value, $ttl = 120)
    {
        if (function_exists('wp_cache_set')) {
            wp_cache_set((string) $key, $value, self::cache_group(), (int) $ttl);
        }
    }

    private static function cache_delete($key)
    {
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete((string) $key, self::cache_group());
        }
    }

    public static function insert($appid, $user_id, $scope = '', $app_post_id = 0, $finance_scope = 0)
    {
        global $wpdb;

        $table = $wpdb->prefix . 'zibll_oauth_grant';
        $appid = trim((string) $appid);
        $user_id = (int) $user_id;
        $scope = trim((string) $scope);
        $app_post_id = (int) $app_post_id;
        $finance_scope = (int) $finance_scope;

        if ($appid === '' || $user_id <= 0) {
            return false;
        }

        // 检查是否已存在该用户对该应用的授权记录
        $existing = self::get_by_appid_user($appid, $user_id);

        if ($existing) {
            // 普通授权流程不应降低/清空已存在的财务签约状态
            // - 若原记录仍为有效授权（status=1），且本次未显式传入 finance_scope，则保留原值
            // - 若原记录已被撤销（status!=1），则避免普通授权自动恢复财务权限
            $finance_scope_to_save = $finance_scope;
            if ($finance_scope_to_save <= 0 && (int) $existing['status'] === 1) {
                $finance_scope_to_save = (int) $existing['finance_scope'];
            }
            if ($finance_scope_to_save < 0) {
                $finance_scope_to_save = 0;
            }

            // 如果存在记录，更新为授权状态
            $update_data = array(
                'scope' => $scope,
                'finance_scope' => (int) $finance_scope_to_save,
                'status' => 1,
                'created_at' => current_time('mysql'),
            );

            $update_format = array('%s', '%d', '%d', '%s');
            
            // 如果 app_post_id 不为 0，也更新该字段
            if ($app_post_id > 0) {
                $update_data['app_post_id'] = $app_post_id;
                $update_format[] = '%d';
            }

            $ok = $wpdb->update($table, $update_data, array(
                'appid' => $appid,
                'user_id' => $user_id,
            ), $update_format, array('%s', '%d'));

            if ($ok === false) {
                return false;
            }

            self::cache_delete(self::cache_key_user_grants($user_id));
            self::cache_delete(self::cache_key_user_grants($user_id) . '_active');
            return (int) $existing['id'];
        }

        // 如果不存在记录，插入新记录
        $data = array(
            'app_post_id' => $app_post_id,
            'appid' => $appid,
            'user_id' => $user_id,
            'scope' => $scope,
            'finance_scope' => $finance_scope,
            'status' => 1,
            'created_at' => current_time('mysql'),
        );

        $formats = array('%d', '%s', '%d', '%s', '%d', '%d', '%s');

        $ok = $wpdb->insert($table, $data, $formats);
        if ($ok === false) {
            return false;
        }

        self::cache_delete(self::cache_key_user_grants($user_id));
        self::cache_delete(self::cache_key_user_grants($user_id) . '_active');

        return (int) $wpdb->insert_id;
    }

    public static function list_by_user($user_id, $limit = 50)
    {
        $user_id = (int) $user_id;
        $limit = (int) $limit;
        if ($user_id <= 0) {
            return array();
        }
        if ($limit <= 0) {
            $limit = 50;
        }

        $cache_key = self::cache_key_user_grants($user_id);
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found && is_array($cached)) {
            return $cached;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'zibll_oauth_grant';

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE user_id = %d ORDER BY id DESC LIMIT %d",
            $user_id,
            $limit
        ), ARRAY_A);

        $rows = is_array($rows) ? $rows : array();
        self::cache_set($cache_key, $rows, 120);
        return $rows;
    }

    public static function get_by_appid_user($appid, $user_id)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'zibll_oauth_grant';
        $appid = trim((string) $appid);
        $user_id = (int) $user_id;

        if ($appid === '' || $user_id <= 0) {
            return null;
        }

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE appid = %s AND user_id = %d LIMIT 1",
            $appid,
            $user_id
        ), ARRAY_A);

        return is_array($row) ? $row : null;
    }

    public static function update_finance_scope($appid, $user_id, $finance_scope = 1)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'zibll_oauth_grant';
        $appid = trim((string) $appid);
        $user_id = (int) $user_id;
        $finance_scope = (int) $finance_scope;

        if ($appid === '' || $user_id <= 0) {
            return false;
        }

        $ok = $wpdb->update($table, array(
            'finance_scope' => $finance_scope,
        ), array(
            'appid' => $appid,
            'user_id' => $user_id,
        ), array('%d'), array('%s', '%d'));

        if ($ok === false) {
            return false;
        }

        self::cache_delete(self::cache_key_user_grants($user_id));
        self::cache_delete(self::cache_key_user_grants($user_id) . '_active');
        return true;
    }

    public static function revoke_grant($appid, $user_id)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'zibll_oauth_grant';
        $appid = trim((string) $appid);
        $user_id = (int) $user_id;

        if ($appid === '' || $user_id <= 0) {
            return false;
        }

        $ok = $wpdb->update($table, array(
            'status' => 0,
        ), array(
            'appid' => $appid,
            'user_id' => $user_id,
        ), array('%d'), array('%s', '%d'));

        if ($ok === false) {
            return false;
        }

        self::cache_delete(self::cache_key_user_grants($user_id));
        self::cache_delete(self::cache_key_user_grants($user_id) . '_active');
        return true;
    }

    public static function is_granted($appid, $user_id, $check_finance = false)
    {
        $grant = self::get_by_appid_user($appid, $user_id);
        if (!$grant) {
            return false;
        }

        if ((int) $grant['status'] !== 1) {
            return false;
        }

        if ($check_finance && (int) $grant['finance_scope'] !== 1) {
            return false;
        }

        return true;
    }

    public static function list_active_by_user($user_id, $limit = 50)
    {
        $user_id = (int) $user_id;
        $limit = (int) $limit;
        if ($user_id <= 0) {
            return array();
        }
        if ($limit <= 0) {
            $limit = 50;
        }

        $cache_key = self::cache_key_user_grants($user_id) . '_active';
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found && is_array($cached)) {
            return $cached;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'zibll_oauth_grant';

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE user_id = %d AND status = 1 ORDER BY id DESC LIMIT %d",
            $user_id,
            $limit
        ), ARRAY_A);

        $rows = is_array($rows) ? $rows : array();
        self::cache_set($cache_key, $rows, 120);
        return $rows;
    }
}
