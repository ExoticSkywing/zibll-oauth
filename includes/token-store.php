<?php
/**
 * OAuth 2.0 令牌持久化与会话家族管理模块
 *
 * 负责将 access_token 与 refresh_token 以 SHA-256 摘要形式持久化至数据库，
 * 提供刷新令牌原子轮换、重放检测（Family Revocation）、RFC 7009 吊销、
 * RFC 7662 令牌内省，以及对升级前遗留 transient 令牌的平滑兼容读取。
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Token_Store
{
    const ACCESS_TABLE = 'zibll_oauth_access_token';
    const REFRESH_TABLE = 'zibll_oauth_refresh_token';
    const REFRESH_TTL_DEFAULT = 15552000; // 180 天

    /**
     * 获取 access_token 表名
     *
     * @return string
     */
    public static function access_table()
    {
        global $wpdb;
        return $wpdb->prefix . self::ACCESS_TABLE;
    }

    /**
     * 获取 refresh_token 表名
     *
     * @return string
     */
    public static function refresh_table()
    {
        global $wpdb;
        return $wpdb->prefix . self::REFRESH_TABLE;
    }

    /**
     * 生成高熵安全随机字母数字令牌（CSPRNG）
     *
     * @param int $length 令牌长度
     * @return string 失败返回空字符串
     */
    public static function generate_opaque_token($length = 40)
    {
        $length = (int) $length;
        if ($length < 24) {
            $length = 24;
        }
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $max = strlen($alphabet) - 1;
        $out = '';
        try {
            for ($i = 0; $i < $length; $i++) {
                $out .= $alphabet[random_int(0, $max)];
            }
        } catch (Throwable $exception) {
            return '';
        }
        return $out;
    }

    /**
     * 生成 64 位会话家族 ID
     *
     * @return string
     */
    public static function generate_family_id()
    {
        try {
            return bin2hex(random_bytes(32));
        } catch (Throwable $exception) {
            return '';
        }
    }

    /**
     * 计算令牌的 SHA-256 摘要
     *
     * @param string $token 明文令牌
     * @return string
     */
    public static function hash_token($token)
    {
        return hash('sha256', (string) $token);
    }

    /**
     * 首次授权签发全新令牌对并建立会话家族
     *
     * @param string $appid
     * @param int    $user_id
     * @param string $scope
     * @param bool   $finance_grant
     * @param int    $access_ttl
     * @param int    $refresh_ttl
     * @return array|WP_Error
     */
    public static function issue_pair($appid, $user_id, $scope, $finance_grant, $access_ttl, $refresh_ttl = self::REFRESH_TTL_DEFAULT)
    {
        $family_id = self::generate_family_id();
        if ($family_id === '') {
            return new WP_Error('server_error', '生成会话标识失败', array('status' => 500));
        }

        return self::persist_pair(
            $family_id,
            0,
            $appid,
            $user_id,
            $scope,
            $finance_grant,
            $access_ttl,
            $refresh_ttl
        );
    }

    /**
     * 原子写入指定会话家族下的 access_token 与 refresh_token
     *
     * @param string $family_id
     * @param int    $parent_id
     * @param string $appid
     * @param int    $user_id
     * @param string $scope
     * @param bool   $finance_grant
     * @param int    $access_ttl
     * @param int    $refresh_ttl
     * @return array|WP_Error
     */
    private static function persist_pair($family_id, $parent_id, $appid, $user_id, $scope, $finance_grant, $access_ttl, $refresh_ttl)
    {
        global $wpdb;

        $access_token = self::generate_opaque_token(40);
        $refresh_token = self::generate_opaque_token(40);
        if ($access_token === '' || $refresh_token === '') {
            return new WP_Error('server_error', '生成安全令牌失败', array('status' => 500));
        }

        $now = time();
        $access_ttl = max(60, (int) $access_ttl);
        $refresh_ttl = max(300, (int) $refresh_ttl);

        $now_utc = gmdate('Y-m-d H:i:s', $now);
        $access_exp_utc = gmdate('Y-m-d H:i:s', $now + $access_ttl);
        $refresh_exp_utc = gmdate('Y-m-d H:i:s', $now + $refresh_ttl);

        $scope = trim((string) $scope);
        if ($scope === '') {
            $scope = 'basic';
        }
        $finance_flag = !empty($finance_grant) ? 1 : 0;

        $rt_inserted = $wpdb->insert(
            self::refresh_table(),
            array(
                'token_hash'    => self::hash_token($refresh_token),
                'family_id'     => (string) $family_id,
                'parent_id'     => (int) $parent_id,
                'appid'         => (string) $appid,
                'user_id'       => (int) $user_id,
                'scope'         => $scope,
                'finance_grant' => $finance_flag,
                'used'          => 0,
                'revoked'       => 0,
                'used_at'       => null,
                'expires_at'    => $refresh_exp_utc,
                'created_at'    => $now_utc,
            ),
            array('%s', '%s', '%d', '%s', '%d', '%s', '%d', '%d', '%d', '%s', '%s', '%s')
        );

        if ($rt_inserted !== 1) {
            return new WP_Error('server_error', '保存 refresh_token 失败', array('status' => 500));
        }

        $rt_id = (int) $wpdb->insert_id;

        $at_inserted = $wpdb->insert(
            self::access_table(),
            array(
                'token_hash'    => self::hash_token($access_token),
                'family_id'     => (string) $family_id,
                'appid'         => (string) $appid,
                'user_id'       => (int) $user_id,
                'scope'         => $scope,
                'finance_grant' => $finance_flag,
                'revoked'       => 0,
                'expires_at'    => $access_exp_utc,
                'created_at'    => $now_utc,
            ),
            array('%s', '%s', '%s', '%d', '%s', '%d', '%d', '%s', '%s')
        );

        if ($at_inserted !== 1) {
            // 访问令牌落盘失败时立即作废刚刚写入的刷新令牌，避免孤儿记录
            if ($rt_id > 0) {
                $wpdb->update(
                    self::refresh_table(),
                    array('revoked' => 1),
                    array('id' => $rt_id),
                    array('%d'),
                    array('%d')
                );
            }
            return new WP_Error('server_error', '保存 access_token 失败', array('status' => 500));
        }

        self::maybe_cleanup_expired();

        return array(
            'access_token'             => $access_token,
            'token_type'               => 'bearer',
            'expires_in'               => $access_ttl,
            'refresh_token'            => $refresh_token,
            'refresh_token_expires_in' => $refresh_ttl,
            'scope'                    => $scope,
            'user_id'                  => (int) $user_id,
            'family_id'                => (string) $family_id,
            'finance_grant'            => $finance_flag === 1,
        );
    }

    /**
     * 仅签发绑定至已有会话家族的 access_token（用于显式开启兼容不轮换模式）
     *
     * @param string $family_id
     * @param string $appid
     * @param int    $user_id
     * @param string $scope
     * @param bool   $finance_grant
     * @param int    $access_ttl
     * @return string|WP_Error
     */
    private static function persist_access_only($family_id, $appid, $user_id, $scope, $finance_grant, $access_ttl)
    {
        global $wpdb;

        $access_token = self::generate_opaque_token(40);
        if ($access_token === '') {
            return new WP_Error('server_error', '生成 access_token 失败', array('status' => 500));
        }

        $now = time();
        $access_ttl = max(60, (int) $access_ttl);
        $inserted = $wpdb->insert(
            self::access_table(),
            array(
                'token_hash'    => self::hash_token($access_token),
                'family_id'     => (string) $family_id,
                'appid'         => (string) $appid,
                'user_id'       => (int) $user_id,
                'scope'         => (string) $scope,
                'finance_grant' => !empty($finance_grant) ? 1 : 0,
                'revoked'       => 0,
                'expires_at'    => gmdate('Y-m-d H:i:s', $now + $access_ttl),
                'created_at'    => gmdate('Y-m-d H:i:s', $now),
            ),
            array('%s', '%s', '%s', '%d', '%s', '%d', '%d', '%s', '%s')
        );

        if ($inserted !== 1) {
            return new WP_Error('server_error', '保存 access_token 失败', array('status' => 500));
        }

        return $access_token;
    }

    /**
     * 刷新令牌：默认执行数据库原子轮换与重放检测
     *
     * @param string $refresh_token
     * @param string $client_id
     * @param int    $access_ttl
     * @param int    $refresh_ttl
     * @param bool   $rotate_requested 客户端是否请求轮换（true 表示轮换）
     * @param bool   $allow_legacy_no_rotate 系统是否允许不轮换兼容模式
     * @return array|WP_Error
     */
    public static function rotate_refresh_token(
        $refresh_token,
        $client_id,
        $access_ttl,
        $refresh_ttl = self::REFRESH_TTL_DEFAULT,
        $rotate_requested = true,
        $allow_legacy_no_rotate = false
    ) {
        global $wpdb;

        $refresh_token = (string) $refresh_token;
        $client_id = (string) $client_id;
        if (trim($refresh_token) === '' || trim($client_id) === '') {
            return new WP_Error('invalid_request', '缺少必要参数：client_id、refresh_token', array('status' => 400));
        }

        $rt_hash = self::hash_token($refresh_token);
        $rt_table = self::refresh_table();
        $now = time();
        $now_utc = gmdate('Y-m-d H:i:s', $now);

        $row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$rt_table} WHERE token_hash = %s LIMIT 1", $rt_hash),
            ARRAY_A
        );

        if ($wpdb->last_error !== '') {
            return new WP_Error('server_error', '读取 refresh_token 失败，请稍后重试', array('status' => 500));
        }

        // 若新表未命中，尝试平滑读取升级前的遗留 transient 令牌
        if (!$row || !is_array($row)) {
            return self::migrate_or_reject_legacy_refresh(
                $refresh_token,
                $client_id,
                $access_ttl,
                $refresh_ttl,
                $rotate_requested,
                $allow_legacy_no_rotate
            );
        }

        if ((string) $row['appid'] !== $client_id) {
            return new WP_Error('invalid_grant', 'refresh_token 与应用不匹配', array('status' => 400));
        }

        $user_id = (int) $row['user_id'];
        if ($user_id <= 0) {
            return new WP_Error('invalid_grant', 'refresh_token 数据不完整', array('status' => 400));
        }

        $family_id = (string) $row['family_id'];

        // 重放与已吊销检测：同一条家族链下发现已消费或已吊销令牌的再次提交，立即作废整条家族
        if ((int) $row['used'] === 1 || (int) $row['revoked'] === 1) {
            if ($family_id !== '') {
                self::revoke_family($family_id);
            }
            self::audit_replay($client_id, $user_id, '检测到已使用或已吊销 refresh_token 重放，已吊销整条会话家族');
            return new WP_Error('invalid_grant', 'refresh_token 已失效，请重新授权登录', array('status' => 400));
        }

        if ((string) $row['expires_at'] <= $now_utc) {
            return new WP_Error('invalid_grant', 'refresh_token 无效或已过期', array('status' => 400));
        }

        $finance_grant = !empty($row['finance_grant']);
        if (!Zibll_Oauth_Grant::is_granted($client_id, $user_id, $finance_grant)) {
            self::revoke_family($family_id);
            return new WP_Error('invalid_grant', '用户授权已失效', array('status' => 400));
        }

        $scope = !empty($row['scope']) ? (string) $row['scope'] : 'basic';
        $effective_rotate = $rotate_requested || !$allow_legacy_no_rotate;

        // 仅当系统明确开启兼容不轮换且客户端要求不轮换时，才续期原令牌并保留家族关系
        if (!$effective_rotate) {
            $new_exp_utc = gmdate('Y-m-d H:i:s', $now + max(300, (int) $refresh_ttl));
            $extended = $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$rt_table} SET expires_at = %s WHERE id = %d AND used = 0 AND revoked = 0 AND expires_at > %s",
                    $new_exp_utc,
                    (int) $row['id'],
                    $now_utc
                )
            );
            if ($extended !== 1) {
                return new WP_Error('invalid_grant', 'refresh_token 状态无效，请重新授权', array('status' => 400));
            }
            $new_at = self::persist_access_only($family_id, $client_id, $user_id, $scope, $finance_grant, $access_ttl);
            if (is_wp_error($new_at)) {
                return $new_at;
            }
            return array(
                'access_token'             => $new_at,
                'token_type'               => 'bearer',
                'expires_in'               => max(60, (int) $access_ttl),
                'refresh_token'            => $refresh_token,
                'refresh_token_expires_in' => max(300, (int) $refresh_ttl),
                'scope'                    => $scope,
                'user_id'                  => $user_id,
                'family_id'                => $family_id,
                'finance_grant'            => $finance_grant,
            );
        }

        // 原子标记当前 refresh_token 为已消费（并发刷新下最多只有一个请求能成功）
        $consumed = $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$rt_table} SET used = 1, used_at = %s WHERE id = %d AND used = 0 AND revoked = 0 AND expires_at > %s",
                $now_utc,
                (int) $row['id'],
                $now_utc
            )
        );

        if ($consumed === false) {
            return new WP_Error('server_error', '刷新令牌处理失败，请稍后重试', array('status' => 500));
        }

        if ($consumed !== 1) {
            // 并发竞态消费失败同样视为潜在令牌泄露或重放，吊销家族保护会话安全
            if ($family_id !== '') {
                self::revoke_family($family_id);
            }
            self::audit_replay($client_id, $user_id, '并发 refresh_token 竞争冲突，已吊销对应会话家族');
            return new WP_Error('invalid_grant', 'refresh_token 已被使用或失效，请重新授权', array('status' => 400));
        }

        return self::persist_pair(
            $family_id,
            (int) $row['id'],
            $client_id,
            $user_id,
            $scope,
            $finance_grant,
            $access_ttl,
            $refresh_ttl
        );
    }

    /**
     * 平滑迁出升级前旧版 wp_transient 存储的 refresh_token
     *
     * @param string $refresh_token
     * @param string $client_id
     * @param int    $access_ttl
     * @param int    $refresh_ttl
     * @param bool   $rotate_requested
     * @param bool   $allow_legacy_no_rotate
     * @return array|WP_Error
     */
    private static function migrate_or_reject_legacy_refresh(
        $refresh_token,
        $client_id,
        $access_ttl,
        $refresh_ttl,
        $rotate_requested,
        $allow_legacy_no_rotate
    ) {
        $legacy_key = self::legacy_refresh_key($refresh_token);
        $rt_data = get_transient($legacy_key);
        if (!$rt_data || !is_array($rt_data)) {
            return new WP_Error('invalid_grant', 'refresh_token 无效或已过期', array('status' => 400));
        }

        if (empty($rt_data['appid']) || (string) $rt_data['appid'] !== $client_id) {
            return new WP_Error('invalid_grant', 'refresh_token 与应用不匹配', array('status' => 400));
        }

        $user_id = !empty($rt_data['user_id']) ? (int) $rt_data['user_id'] : 0;
        if ($user_id <= 0) {
            return new WP_Error('invalid_grant', 'refresh_token 数据不完整', array('status' => 400));
        }

        $finance_grant = !empty($rt_data['finance_grant']);
        if (!Zibll_Oauth_Grant::is_granted($client_id, $user_id, $finance_grant)) {
            delete_transient($legacy_key);
            return new WP_Error('invalid_grant', '用户授权已失效', array('status' => 400));
        }

        $scope = !empty($rt_data['scope']) ? (string) $rt_data['scope'] : 'basic';
        // 删除旧 transient，防止遗留通道被二次利用
        delete_transient($legacy_key);

        $idx_key = self::legacy_refresh_index_key($client_id, $user_id);
        $current_idx = get_transient($idx_key);
        if (is_string($current_idx) && hash_equals(trim($current_idx), $refresh_token)) {
            delete_transient($idx_key);
        }

        // 升迁入库成全新会话家族，默认强制轮换返回新令牌
        if (!$rotate_requested && $allow_legacy_no_rotate) {
            global $wpdb;
            $family_id = self::generate_family_id();
            $now = time();
            $refresh_ttl = max(300, (int) $refresh_ttl);
            $inserted = $wpdb->insert(
                self::refresh_table(),
                array(
                    'token_hash'    => self::hash_token($refresh_token),
                    'family_id'     => $family_id,
                    'parent_id'     => 0,
                    'appid'         => $client_id,
                    'user_id'       => $user_id,
                    'scope'         => $scope,
                    'finance_grant' => $finance_grant ? 1 : 0,
                    'used'          => 0,
                    'revoked'       => 0,
                    'used_at'       => null,
                    'expires_at'    => gmdate('Y-m-d H:i:s', $now + $refresh_ttl),
                    'created_at'    => gmdate('Y-m-d H:i:s', $now),
                ),
                array('%s', '%s', '%d', '%s', '%d', '%s', '%d', '%d', '%d', '%s', '%s', '%s')
            );
            if ($inserted !== 1) {
                return new WP_Error('server_error', '迁移 refresh_token 失败', array('status' => 500));
            }
            $new_at = self::persist_access_only($family_id, $client_id, $user_id, $scope, $finance_grant, $access_ttl);
            if (is_wp_error($new_at)) {
                return $new_at;
            }
            return array(
                'access_token'             => $new_at,
                'token_type'               => 'bearer',
                'expires_in'               => max(60, (int) $access_ttl),
                'refresh_token'            => $refresh_token,
                'refresh_token_expires_in' => $refresh_ttl,
                'scope'                    => $scope,
                'user_id'                  => $user_id,
                'family_id'                => $family_id,
                'finance_grant'            => $finance_grant,
            );
        }

        return self::issue_pair($client_id, $user_id, $scope, $finance_grant, $access_ttl, $refresh_ttl);
    }

    /**
     * 解析有效的 access_token（优先查数据库表，未命中则兼容未过期旧 transient）
     *
     * @param string $access_token
     * @return array|null 无效或过期返回 null
     */
    public static function resolve_access_token($access_token)
    {
        global $wpdb;

        $access_token = trim((string) $access_token);
        if ($access_token === '') {
            return null;
        }

        $at_hash = self::hash_token($access_token);
        $at_table = self::access_table();
        $now_utc = gmdate('Y-m-d H:i:s');

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$at_table} WHERE token_hash = %s AND revoked = 0 AND expires_at > %s LIMIT 1",
                $at_hash,
                $now_utc
            ),
            ARRAY_A
        );

        if ($wpdb->last_error === '' && is_array($row) && !empty($row['user_id']) && !empty($row['appid'])) {
            $exp_ts = strtotime((string) $row['expires_at'] . ' UTC');
            $iat_ts = strtotime((string) $row['created_at'] . ' UTC');
            return array(
                'appid'         => (string) $row['appid'],
                'user_id'       => (int) $row['user_id'],
                'scope'         => !empty($row['scope']) ? (string) $row['scope'] : 'basic',
                'finance_grant' => !empty($row['finance_grant']),
                'family_id'     => !empty($row['family_id']) ? (string) $row['family_id'] : '',
                'created_at'    => $iat_ts ? (int) $iat_ts : time(),
                'expires_at'    => $exp_ts ? (int) $exp_ts : (time() + 60),
                'source'        => 'db',
            );
        }

        // 平滑过渡：若库中无记录，兼容仍在有效期内的遗留 transient 访问令牌
        $legacy = get_transient(self::legacy_access_key($access_token));
        if (is_array($legacy) && !empty($legacy['user_id']) && !empty($legacy['appid'])) {
            $created = !empty($legacy['created_at']) ? (int) $legacy['created_at'] : time();
            $ttl = class_exists('Zibll_Oauth_Options') ? Zibll_Oauth_Options::token_expires() : 7200;
            return array(
                'appid'         => (string) $legacy['appid'],
                'user_id'       => (int) $legacy['user_id'],
                'scope'         => !empty($legacy['scope']) ? (string) $legacy['scope'] : 'basic',
                'finance_grant' => !empty($legacy['finance_grant']),
                'family_id'     => '',
                'created_at'    => $created,
                'expires_at'    => $created + $ttl,
                'source'        => 'legacy_transient',
            );
        }

        return null;
    }

    /**
     * RFC 7662 令牌内省校验（仅限归属该应用且处于有效授权状态的令牌）
     *
     * @param string $client_id
     * @param string $token
     * @param string $hint
     * @return array
     */
    public static function introspect_token($client_id, $token, $hint = '')
    {
        global $wpdb;

        $client_id = trim((string) $client_id);
        $token = trim((string) $token);
        $hint = trim((string) $hint);

        if ($client_id === '' || $token === '') {
            return array('active' => false);
        }

        $check_access = function () use ($token, $client_id) {
            $data = self::resolve_access_token($token);
            if (!$data || (string) $data['appid'] !== $client_id) {
                return null;
            }
            if (!Zibll_Oauth_Grant::is_granted($client_id, (int) $data['user_id'], !empty($data['finance_grant']))) {
                return null;
            }
            return array('token_type' => 'Bearer', 'data' => $data);
        };

        $check_refresh = function () use ($wpdb, $token, $client_id) {
            $rt_hash = self::hash_token($token);
            $rt_table = self::refresh_table();
            $now_utc = gmdate('Y-m-d H:i:s');
            $row = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT * FROM {$rt_table} WHERE token_hash = %s AND appid = %s AND used = 0 AND revoked = 0 AND expires_at > %s LIMIT 1",
                    $rt_hash,
                    $client_id,
                    $now_utc
                ),
                ARRAY_A
            );
            if ($wpdb->last_error === '' && is_array($row) && !empty($row['user_id'])) {
                $user_id = (int) $row['user_id'];
                $fin = !empty($row['finance_grant']);
                if (!Zibll_Oauth_Grant::is_granted($client_id, $user_id, $fin)) {
                    return null;
                }
                $exp_ts = strtotime((string) $row['expires_at'] . ' UTC');
                $iat_ts = strtotime((string) $row['created_at'] . ' UTC');
                return array(
                    'token_type' => 'refresh_token',
                    'data'       => array(
                        'appid'         => $client_id,
                        'user_id'       => $user_id,
                        'scope'         => !empty($row['scope']) ? (string) $row['scope'] : 'basic',
                        'finance_grant' => $fin,
                        'created_at'    => $iat_ts ? (int) $iat_ts : time(),
                        'expires_at'    => $exp_ts ? (int) $exp_ts : (time() + 60),
                    ),
                );
            }
            return null;
        };

        $matched = null;
        if ($hint === 'refresh_token') {
            $matched = $check_refresh();
            if ($matched === null) {
                $matched = $check_access();
            }
        } else {
            $matched = $check_access();
            if ($matched === null) {
                $matched = $check_refresh();
            }
        }

        if (!$matched) {
            return array('active' => false);
        }

        $d = $matched['data'];
        $user_id = (int) $d['user_id'];
        $openid = Zibll_Oauth_Provider_Util::get_openid($user_id, $client_id);

        $resp = array(
            'active'     => true,
            'scope'      => (string) $d['scope'],
            'client_id'  => $client_id,
            'sub'        => $openid,
            'uid'        => $user_id,
            'token_type' => $matched['token_type'],
            'exp'        => (int) $d['expires_at'],
            'iat'        => (int) $d['created_at'],
        );

        $tg_uid = get_user_meta($user_id, '_xingxy_telegram_uid', true);
        if ($tg_uid !== '' && $tg_uid !== false) {
            $resp['tg_uid'] = (int) $tg_uid;
        }

        return $resp;
    }

    /**
     * 按 RFC 7009 吊销令牌（若为 refresh_token 则连带吊销其所属会话家族）
     *
     * @param string $client_id
     * @param string $token
     * @param string $hint
     * @return void
     */
    public static function revoke_token($client_id, $token, $hint = '')
    {
        global $wpdb;

        $client_id = trim((string) $client_id);
        $token = trim((string) $token);
        $hint = trim((string) $hint);
        if ($client_id === '' || $token === '') {
            return;
        }

        $token_hash = self::hash_token($token);

        if ($hint === 'access_token') {
            $wpdb->update(
                self::access_table(),
                array('revoked' => 1),
                array('token_hash' => $token_hash, 'appid' => $client_id),
                array('%d'),
                array('%s', '%s')
            );
            $legacy_at = get_transient(self::legacy_access_key($token));
            if (is_array($legacy_at) && isset($legacy_at['appid']) && (string) $legacy_at['appid'] === $client_id) {
                delete_transient(self::legacy_access_key($token));
            }
            return;
        }

        // 先尝试按 refresh_token 查找并吊销整条家族
        $rt_table = self::refresh_table();
        $rt_row = $wpdb->get_row(
            $wpdb->prepare("SELECT id, family_id, appid FROM {$rt_table} WHERE token_hash = %s AND appid = %s LIMIT 1", $token_hash, $client_id),
            ARRAY_A
        );

        if (is_array($rt_row) && !empty($rt_row['family_id'])) {
            self::revoke_family((string) $rt_row['family_id']);
            return;
        }

        // 若未传 hint 或在 refresh 表未找到，也检查一次 access_token 表防止误传 hint
        if ($hint === '') {
            $wpdb->update(
                self::access_table(),
                array('revoked' => 1),
                array('token_hash' => $token_hash, 'appid' => $client_id),
                array('%d'),
                array('%s', '%s')
            );
        }

        // 兜底清理遗留 transient 令牌
        $legacy_rt = get_transient(self::legacy_refresh_key($token));
        if (is_array($legacy_rt) && !empty($legacy_rt['appid']) && (string) $legacy_rt['appid'] === $client_id) {
            delete_transient(self::legacy_refresh_key($token));
            if (!empty($legacy_rt['user_id'])) {
                $idx_key = self::legacy_refresh_index_key($client_id, (int) $legacy_rt['user_id']);
                $current = get_transient($idx_key);
                if (is_string($current) && hash_equals(trim($current), $token)) {
                    delete_transient($idx_key);
                }
            }
        }
        $legacy_at = get_transient(self::legacy_access_key($token));
        if (is_array($legacy_at) && !empty($legacy_at['appid']) && (string) $legacy_at['appid'] === $client_id) {
            delete_transient(self::legacy_access_key($token));
        }
    }

    /**
     * 吊销指定会话家族内的全部刷新令牌与访问令牌
     *
     * @param string $family_id
     * @return void
     */
    public static function revoke_family($family_id)
    {
        global $wpdb;

        $family_id = trim((string) $family_id);
        if ($family_id === '') {
            return;
        }

        $rt_table = self::refresh_table();
        $at_table = self::access_table();

        $wpdb->query($wpdb->prepare("UPDATE {$rt_table} SET revoked = 1 WHERE family_id = %s AND revoked = 0", $family_id));
        $wpdb->query($wpdb->prepare("UPDATE {$at_table} SET revoked = 1 WHERE family_id = %s AND revoked = 0", $family_id));
    }

    /**
     * 吊销指定用户在指定应用下的全部活跃会话与令牌（用于用户中心取消授权）
     *
     * @param string $client_id
     * @param int    $user_id
     * @return void
     */
    public static function revoke_user_tokens($client_id, $user_id)
    {
        global $wpdb;

        $client_id = trim((string) $client_id);
        $user_id = (int) $user_id;
        if ($client_id === '' || $user_id <= 0) {
            return;
        }

        $rt_table = self::refresh_table();
        $at_table = self::access_table();

        $wpdb->query(
            $wpdb->prepare("UPDATE {$rt_table} SET revoked = 1 WHERE appid = %s AND user_id = %d AND revoked = 0", $client_id, $user_id)
        );
        $wpdb->query(
            $wpdb->prepare("UPDATE {$at_table} SET revoked = 1 WHERE appid = %s AND user_id = %d AND revoked = 0", $client_id, $user_id)
        );

        // 同时清理旧版 transient 索引
        $idx_key = self::legacy_refresh_index_key($client_id, $user_id);
        $rt = get_transient($idx_key);
        delete_transient($idx_key);
        if (is_string($rt) && trim($rt) !== '') {
            delete_transient(self::legacy_refresh_key($rt));
        }
    }

    /**
     * 低频限流清理过期超过 7 天的历史令牌记录
     *
     * @return void
     */
    public static function maybe_cleanup_expired()
    {
        try {
            if (random_int(1, 100) !== 1) {
                return;
            }
        } catch (Throwable $exception) {
            return;
        }

        global $wpdb;
        $threshold = gmdate('Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS);
        $at_table = self::access_table();
        $rt_table = self::refresh_table();

        $wpdb->query($wpdb->prepare("DELETE FROM {$at_table} WHERE expires_at < %s LIMIT 200", $threshold));
        $wpdb->query($wpdb->prepare("DELETE FROM {$rt_table} WHERE expires_at < %s LIMIT 200", $threshold));
    }

    private static function audit_replay($client_id, $user_id, $message)
    {
        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            Zibll_Oauth_Admin_Log::add_log($client_id, $user_id, 'token_replay_detected', $message);
        }
    }

    public static function legacy_access_key($token)
    {
        return 'zibll_oauth_token_' . md5((string) $token);
    }

    public static function legacy_refresh_key($token)
    {
        return 'zibll_oauth_refresh_' . md5((string) $token);
    }

    public static function legacy_refresh_index_key($client_id, $user_id)
    {
        return 'zibll_oauth_refresh_idx_' . md5((string) $client_id . '|' . (int) $user_id);
    }
}
