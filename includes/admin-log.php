<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Admin_Log
{
    const TABLE = 'zibll_oauth_audit';

    public static function init()
    {
        if (!is_admin()) {
            return;
        }

        add_action('admin_menu', array(__CLASS__, 'add_menu'), 60);
    }

    public static function table_name()
    {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    /**
     * 追加一条审计日志，并清理 15 天前的老数据
     *
     * @param string $appid
     * @param int    $user_id
     * @param string $action  简短动作标识，例如 token_issue / authorize_grant / finance_deduct 等
     * @param string $summary 人类可读摘要
     */
    public static function add_log($appid, $user_id, $action, $summary)
    {
        $appid = trim((string) $appid);
        $user_id = (int) $user_id;
        $action = trim((string) $action);
        $summary = trim((string) $summary);

        if ($appid === '' || $action === '' || $summary === '') {
            return;
        }

        global $wpdb;
        $table = self::table_name();

        $ip = function_exists('Zibll_Oauth_Provider_Util::client_ip') ? Zibll_Oauth_Provider_Util::client_ip() : '';
        if ($ip === '' && !empty($_SERVER['REMOTE_ADDR'])) {
            $ip = (string) $_SERVER['REMOTE_ADDR'];
        }

        $now = current_time('mysql');

        $wpdb->insert(
            $table,
            array(
                'appid' => $appid,
                'user_id' => $user_id,
                'action' => $action,
                'summary' => $summary,
                'ip' => $ip,
                'created_at' => $now,
            ),
            array('%s', '%d', '%s', '%s', '%s', '%s')
        );

        // 清理 15 天前的旧日志
        $threshold = gmdate('Y-m-d H:i:s', time() - 15 * DAY_IN_SECONDS);
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$table} WHERE created_at < %s",
                $threshold
            )
        );
    }

	/**
	 * 获取最近的日志（按时间倒序）
	 *
	 * @param string $appid
	 * @param int    $limit
	 * @return array
	 */
	public static function get_logs($appid = '', $limit = 200)
	{
		global $wpdb;
		$table = self::table_name();

		$limit = (int) $limit;
		if ($limit <= 0) {
			$limit = 200;
		}

		if ($appid !== '') {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$table} WHERE appid = %s ORDER BY created_at DESC LIMIT %d",
					$appid,
					$limit
				),
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d",
					$limit
				),
				ARRAY_A
			);
		}

		return is_array($rows) ? $rows : array();
	}

	/**
	 * 获取特定用户特定操作的日志
	 *
	 * @param string $appid
	 * @param int    $user_id
	 * @param string $action
	 * @return array|null
	 */
	public static function get_log($appid, $user_id, $action)
	{
		$appid = trim((string) $appid);
		$user_id = (int) $user_id;
		$action = trim((string) $action);

		if ($appid === '' || $user_id <= 0 || $action === '') {
			return null;
		}

		global $wpdb;
		$table = self::table_name();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE appid = %s AND user_id = %d AND action = %s ORDER BY created_at DESC LIMIT 1",
				$appid,
				$user_id,
				$action
			),
			ARRAY_A
		);

		return is_array($row) ? $row : null;
	}

    public static function add_menu()
    {
        add_submenu_page(
            'zibll-oauth',
            'OAuth 操作日志',
            '操作日志',
            'manage_options',
            'zibll_oauth_logs',
            array(__CLASS__, 'render_page')
        );
    }

    public static function render_page()
    {
        if (!current_user_can('manage_options')) {
            wp_die('权限不足');
        }

        $appid = isset($_GET['appid']) ? trim((string) $_GET['appid']) : '';
        $logs = self::get_logs($appid, 200);

        echo '<div class="wrap">';
        echo '<h1>OAuth 操作日志（近 15 天）</h1>';

        echo '<form method="get" class="mb10">';
        echo '<input type="hidden" name="page" value="zibll_oauth_logs" />';
        echo '<label>按 AppID 过滤：<input type="text" name="appid" value="' . esc_attr($appid) . '" class="regular-text" /></label> ';
        submit_button('筛选', 'secondary', '', false);
        echo '</form>';

        if (empty($logs)) {
            echo '<p>暂无日志记录。</p>';
            echo '</div>';
            return;
        }

        echo '<table class="widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th>时间</th>';
        echo '<th>AppID</th>';
        echo '<th>用户ID</th>';
        echo '<th>动作</th>';
        echo '<th>摘要</th>';
        echo '<th>IP</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($logs as $row) {
            echo '<tr>';
            echo '<td>' . esc_html($row['created_at']) . '</td>';
            echo '<td>' . esc_html($row['appid']) . '</td>';
            echo '<td>' . esc_html((string) $row['user_id']) . '</td>';
            echo '<td>' . esc_html($row['action']) . '</td>';
            echo '<td>' . esc_html($row['summary']) . '</td>';
            echo '<td>' . esc_html($row['ip']) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }
}

