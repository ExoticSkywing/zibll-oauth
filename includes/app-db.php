<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_App_DB
{
    const TABLE = 'zibll_oauth_app';
    const CACHE_GROUP = 'zibll_oauth';

    const STATUS_DRAFT = 0;
    const STATUS_PENDING = 1;
    const STATUS_APPROVED = 2;
    const STATUS_REJECTED = 3;

    public static function table_name()
    {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    private static function cache_get($key, &$found = null)
    {
        if (function_exists('wp_cache_get')) {
            $f = false;
            $v = wp_cache_get((string) $key, self::CACHE_GROUP, false, $f);
            $found = $f;
            return $v;
        }
        $found = false;
        return null;
    }

    private static function cache_set($key, $value, $ttl = 300)
    {
        if (function_exists('wp_cache_set')) {
            wp_cache_set((string) $key, $value, self::CACHE_GROUP, (int) $ttl);
        }
    }

    private static function cache_delete($key)
    {
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete((string) $key, self::CACHE_GROUP);
        }
    }

    private static function cache_key_appid($appid)
    {
        return 'appdb:appid:' . md5((string) $appid);
    }

    private static function cache_key_id($id)
    {
        return 'appdb:id:' . (int) $id;
    }

    private static function cache_key_user_list($user_id)
    {
        return 'appdb:user:' . (int) $user_id;
    }

    private static function invalidate($appid = '', $id = 0, $user_id = 0)
    {
        if ($appid !== '') {
            self::cache_delete(self::cache_key_appid($appid));
        }
        if ($id) {
            self::cache_delete(self::cache_key_id($id));
        }
        if ($user_id) {
            self::cache_delete(self::cache_key_user_list($user_id));
        }
    }

    public static function get_status_text($status)
    {
        $status = (int) $status;
        $map = array(
            self::STATUS_DRAFT => '草稿（未提交）',
            self::STATUS_PENDING => '待审核',
            self::STATUS_APPROVED => '已通过（上线）',
            self::STATUS_REJECTED => '已驳回（下线）',
        );
        return isset($map[$status]) ? $map[$status] : (string) $status;
    }

    public static function find_by_appid($appid)
    {
        $appid = trim((string) $appid);
        if ($appid === '') {
            return null;
        }

        $cache_key = self::cache_key_appid($appid);
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found) {
            return is_array($cached) ? $cached : null;
        }

        global $wpdb;
        $table = self::table_name();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE appid = %s LIMIT 1", $appid), ARRAY_A);

        if (!is_array($row)) {
            self::cache_set($cache_key, false, 60);
            return null;
        }

        self::cache_set($cache_key, $row, 300);
        self::cache_set(self::cache_key_id((int) $row['id']), $row, 300);
        return $row;
    }

    public static function get_by_id($id)
    {
        $id = (int) $id;
        if ($id <= 0) {
            return null;
        }

        $cache_key = self::cache_key_id($id);
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found) {
            return is_array($cached) ? $cached : null;
        }

        global $wpdb;
        $table = self::table_name();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d LIMIT 1", $id), ARRAY_A);

        if (!is_array($row)) {
            self::cache_set($cache_key, false, 60);
            return null;
        }

        self::cache_set($cache_key, $row, 300);
        self::cache_set(self::cache_key_appid((string) $row['appid']), $row, 300);
        return $row;
    }

    public static function list_by_user($user_id, $limit = 50)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return array();
        }
        $limit = (int) $limit;
        if ($limit <= 0) {
            $limit = 50;
        }

        $cache_key = self::cache_key_user_list($user_id);
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found && is_array($cached)) {
            return $cached;
        }

        global $wpdb;
        $table = self::table_name();
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE user_id = %d ORDER BY id DESC LIMIT %d",
            $user_id,
            $limit
        ), ARRAY_A);

        $rows = is_array($rows) ? $rows : array();
        self::cache_set($cache_key, $rows, 120);
        return $rows;
    }

    public static function to_site_array($row)
    {
        $row = is_array($row) ? $row : array();

        $user_id = !empty($row['user_id']) ? (int) $row['user_id'] : 0;
        $user = $user_id ? get_user_by('id', $user_id) : null;

        $status = isset($row['status']) ? (int) $row['status'] : self::STATUS_DRAFT;

        return array(
            'id' => !empty($row['id']) ? (int) $row['id'] : 0,
            'user_id' => $user_id,
            'developer_name' => ($user && !empty($user->display_name)) ? (string) $user->display_name : '',
            'title' => !empty($row['title']) ? (string) $row['title'] : '',
            'icon' => !empty($row['icon']) ? (string) $row['icon'] : '',
            'redirect_uri' => !empty($row['redirect_uri']) ? (string) $row['redirect_uri'] : '',
            'default_scope' => !empty($row['default_scope']) ? (string) $row['default_scope'] : 'basic',
            'appid' => !empty($row['appid']) ? (string) $row['appid'] : '',
            'appkey' => !empty($row['appkey']) ? (string) $row['appkey'] : '',
            'finance_enabled' => !empty($row['finance_enabled']) ? (int) $row['finance_enabled'] : 0,
            'finance_callback_url' => !empty($row['finance_callback_url']) ? (string) $row['finance_callback_url'] : '',
            'finance_deduct_callback_url' => !empty($row['finance_deduct_callback_url']) ? (string) $row['finance_deduct_callback_url'] : '',
            'revoke_callback_url' => !empty($row['revoke_callback_url']) ? (string) $row['revoke_callback_url'] : '',
            'ip_whitelist' => !empty($row['ip_whitelist']) ? (string) $row['ip_whitelist'] : '',
            'status' => $status,
            'status_text' => self::get_status_text($status),
            'reject_reason' => !empty($row['reject_reason']) ? (string) $row['reject_reason'] : '',
            'enabled' => $status === self::STATUS_APPROVED,
        );
    }

    public static function create($user_id, $title, $icon = '', $redirect_uri = '', $default_scope = 'basic')
    {
        $user_id = (int) $user_id;
        $title = trim((string) $title);
        if ($user_id <= 0 || $title === '') {
            return new WP_Error('invalid_param', '参数错误');
        }

        $appid = Zibll_Oauth_Provider_Util::generate_appid();
        $appkey = Zibll_Oauth_Provider_Util::generate_appkey();

        if ($redirect_uri !== '' && function_exists('remove_query_arg')) {
            $redirect_uri = (string) remove_query_arg(array('code', 'state'), $redirect_uri);
        }

        global $wpdb;
        $table = self::table_name();
        $now = current_time('mysql');

        $ok = $wpdb->insert($table, array(
            'user_id' => $user_id,
            'title' => $title,
            'icon' => $icon,
            'redirect_uri' => $redirect_uri,
            'default_scope' => $default_scope,
            'appid' => $appid,
            'appkey' => $appkey,
            'finance_enabled' => 0,
            'finance_callback_url' => '',
            'finance_deduct_callback_url' => '',
            'revoke_callback_url' => '',
            'ip_whitelist' => '',
            'status' => self::STATUS_DRAFT,
            'reject_reason' => '',
            'created_at' => $now,
            'updated_at' => $now,
        ), array('%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s'));

        if (!$ok) {
            return new WP_Error('db_error', '创建失败');
        }

        $id = (int) $wpdb->insert_id;
        self::invalidate($appid, $id, $user_id);
        return self::get_by_id($id);
    }

    public static function update_by_owner($id, $user_id, $fields)
    {
        $id = (int) $id;
        $user_id = (int) $user_id;
        if ($id <= 0 || $user_id <= 0 || !is_array($fields)) {
            return new WP_Error('invalid_param', '参数错误');
        }

        $row = self::get_by_id($id);
        if (!$row || (int) $row['user_id'] !== $user_id) {
            return new WP_Error('forbidden', '无权限');
        }

        $data = array();
        $format = array();

        if (isset($fields['title'])) {
            $data['title'] = trim((string) $fields['title']);
            $format[] = '%s';
        }
        if (array_key_exists('icon', $fields)) {
            $data['icon'] = trim((string) $fields['icon']);
            $format[] = '%s';
        }
        if (array_key_exists('redirect_uri', $fields)) {
            $r = trim((string) $fields['redirect_uri']);
            if ($r !== '' && function_exists('remove_query_arg')) {
                $r = (string) remove_query_arg(array('code', 'state'), $r);
            }
            $data['redirect_uri'] = $r;
            $format[] = '%s';
        }
        if (array_key_exists('default_scope', $fields)) {
            $data['default_scope'] = trim((string) $fields['default_scope']) ?: 'basic';
            $format[] = '%s';
        }

        if (array_key_exists('finance_enabled', $fields)) {
            $data['finance_enabled'] = (int) $fields['finance_enabled'] ? 1 : 0;
            $format[] = '%d';
        }

        if (array_key_exists('finance_callback_url', $fields)) {
            $data['finance_callback_url'] = trim((string) $fields['finance_callback_url']);
            $format[] = '%s';
        }

        if (array_key_exists('finance_deduct_callback_url', $fields)) {
            $data['finance_deduct_callback_url'] = trim((string) $fields['finance_deduct_callback_url']);
            $format[] = '%s';
        }

        if (array_key_exists('revoke_callback_url', $fields)) {
            $data['revoke_callback_url'] = trim((string) $fields['revoke_callback_url']);
            $format[] = '%s';
        }

        if (array_key_exists('ip_whitelist', $fields)) {
            $data['ip_whitelist'] = trim((string) $fields['ip_whitelist']);
            $format[] = '%s';
        }

        if (!$data) {
            return self::get_by_id($id);
        }

        $data['status'] = self::STATUS_DRAFT;
        $data['reject_reason'] = '';
        $data['updated_at'] = current_time('mysql');

        $format[] = '%d';
        $format[] = '%s';
        $format[] = '%s';

        global $wpdb;
        $table = self::table_name();
        $ok = $wpdb->update($table, $data, array('id' => $id), $format, array('%d'));
        if ($ok === false) {
            return new WP_Error('db_error', '保存失败');
        }

        self::invalidate((string) $row['appid'], $id, $user_id);
        return self::get_by_id($id);
    }

    public static function delete_by_owner($id, $user_id)
    {
        $id = (int) $id;
        $user_id = (int) $user_id;
        $row = self::get_by_id($id);
        if (!$row || (int) $row['user_id'] !== $user_id) {
            return new WP_Error('forbidden', '无权限');
        }

        global $wpdb;
        $table = self::table_name();
        $ok = $wpdb->delete($table, array('id' => $id), array('%d'));
        if (!$ok) {
            return new WP_Error('db_error', '删除失败');
        }

        self::invalidate((string) $row['appid'], $id, $user_id);
        return true;
    }

    public static function submit($id, $user_id)
    {
        $id = (int) $id;
        $user_id = (int) $user_id;
        $row = self::get_by_id($id);
        if (!$row || (int) $row['user_id'] !== $user_id) {
            return new WP_Error('forbidden', '无权限');
        }

        if (empty($row['redirect_uri'])) {
            return new WP_Error('invalid_redirect', '请先填写回调地址（redirect_uri）');
        }

        global $wpdb;
        $table = self::table_name();
        $ok = $wpdb->update($table, array(
            'status' => self::STATUS_PENDING,
            'updated_at' => current_time('mysql'),
        ), array('id' => $id), array('%d', '%s'), array('%d'));

        if ($ok === false) {
            return new WP_Error('db_error', '提交失败');
        }

        self::invalidate((string) $row['appid'], $id, $user_id);
        return self::get_by_id($id);
    }

    public static function audit($id, $status, $reject_reason = '')
    {
        $id = (int) $id;
        $status = (int) $status;
        if (!in_array($status, array(self::STATUS_APPROVED, self::STATUS_REJECTED), true)) {
            return new WP_Error('invalid_status', '状态错误');
        }

        $row = self::get_by_id($id);
        if (!$row) {
            return new WP_Error('not_found', '应用不存在');
        }

        global $wpdb;
        $table = self::table_name();
        $ok = $wpdb->update($table, array(
            'status' => $status,
            'reject_reason' => (string) $reject_reason,
            'updated_at' => current_time('mysql'),
        ), array('id' => $id), array('%d', '%s', '%s'), array('%d'));

        if ($ok === false) {
            return new WP_Error('db_error', '处理失败');
        }

        self::invalidate((string) $row['appid'], $id, (int) $row['user_id']);
        return self::get_by_id($id);
    }

    public static function rotate_appkey_by_owner($id, $user_id)
    {
        $id = (int) $id;
        $user_id = (int) $user_id;
        if ($id <= 0 || $user_id <= 0) {
            return new WP_Error('invalid_param', '参数错误');
        }

        $row = self::get_by_id($id);
        if (!$row || (int) $row['user_id'] !== $user_id) {
            return new WP_Error('forbidden', '无权限');
        }

        $new_key = Zibll_Oauth_Provider_Util::generate_appkey();

        global $wpdb;
        $table = self::table_name();
        $ok = $wpdb->update($table, array(
            'appkey' => $new_key,
            'updated_at' => current_time('mysql'),
        ), array('id' => $id), array('%s', '%s'), array('%d'));

        if ($ok === false) {
            return new WP_Error('db_error', '轮转失败');
        }

        self::invalidate((string) $row['appid'], $id, $user_id);
        return $new_key;
    }
}
