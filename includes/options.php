<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Options
{
    const OPTIONS_KEY = 'zibll_oauth_options';
    const CACHE_GROUP = 'zibll_oauth';

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

    public static function cache_delete($key)
    {
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete((string) $key, self::CACHE_GROUP);
        }
    }

    public static function get_options()
    {
        $cache_key = 'options:' . self::OPTIONS_KEY;
        $cached = wp_cache_get($cache_key, self::CACHE_GROUP);
        if (is_array($cached)) {
            return $cached;
        }

        $opt = get_option(self::OPTIONS_KEY);
        $opt = is_array($opt) ? $opt : array();
        wp_cache_set($cache_key, $opt, self::CACHE_GROUP, 300);
        return $opt;
    }

    public static function get($key, $default = null)
    {
        $opt = self::get_options();
        return array_key_exists($key, $opt) ? $opt[$key] : $default;
    }

    public static function require_sign()
    {
        return true;
    }

    public static function code_expires()
    {
        $v = (int) self::get('zibll_oauth_code_expires', 300);
        return max(30, $v);
    }

    public static function token_expires()
    {
        $v = (int) self::get('zibll_oauth_token_expires', 7200);
        return max(60, $v);
    }

    public static function developer_whitelist_raw()
    {
        return (string) self::get('zibll_oauth_developer_whitelist', '');
    }

    public static function developer_whitelist()
    {
        $cache_key = 'developer_whitelist';
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found && is_array($cached)) {
            return $cached;
        }

        $raw = self::developer_whitelist_raw();
        $lines = preg_split('/\r\n|\r|\n/', (string) $raw);

        $ids = array();
        $emails = array();

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            if (is_email($line)) {
                $emails[strtolower($line)] = true;
                continue;
            }

            if (ctype_digit($line)) {
                $ids[(int) $line] = true;
                continue;
            }
        }

        $data = array(
            'ids' => array_keys($ids),
            'emails' => array_keys($emails),
        );

        self::cache_set($cache_key, $data, 300);
        return $data;
    }

    public static function is_user_developer($user_id)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return false;
        }

        $wl = self::developer_whitelist();
        if (!empty($wl['ids']) && in_array($user_id, (array) $wl['ids'], true)) {
            return true;
        }

        $user = get_user_by('id', $user_id);
        $email = $user && !empty($user->user_email) ? strtolower((string) $user->user_email) : '';
        if ($email !== '' && !empty($wl['emails']) && in_array($email, (array) $wl['emails'], true)) {
            return true;
        }

        return false;
    }

    public static function finance_whitelist_raw()
    {
        return (string) self::get('zibll_oauth_finance_whitelist', '');
    }

    public static function finance_whitelist()
    {
        $cache_key = 'finance_whitelist';
        $found = false;
        $cached = self::cache_get($cache_key, $found);
        if ($found && is_array($cached)) {
            return $cached;
        }

        $raw = self::finance_whitelist_raw();
        $lines = preg_split('/\r\n|\r|\n/', (string) $raw);

        $ids = array();
        $emails = array();

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            if (is_email($line)) {
                $emails[strtolower($line)] = true;
                continue;
            }

            if (ctype_digit($line)) {
                $ids[(int) $line] = true;
                continue;
            }
        }

        $data = array(
            'ids' => array_keys($ids),
            'emails' => array_keys($emails),
        );

        self::cache_set($cache_key, $data, 300);
        return $data;
    }

    public static function is_user_finance_enabled($user_id)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return false;
        }

        if (user_can($user_id, 'manage_options')) {
            return true;
        }

        if (self::is_user_developer($user_id)) {
            return true;
        }

        $wl = self::finance_whitelist();
        if (!empty($wl['ids']) && in_array($user_id, (array) $wl['ids'], true)) {
            return true;
        }

        $user = get_user_by('id', $user_id);
        $email = $user && !empty($user->user_email) ? strtolower((string) $user->user_email) : '';
        if ($email !== '' && !empty($wl['emails']) && in_array($email, (array) $wl['emails'], true)) {
            return true;
        }

        return false;
    }
}
