<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_User_Center
{
    public static function init()
    {
        add_filter('user_center_page_sidebar', array(__CLASS__, 'inject_sidebar_section'), 58);
        add_filter('user_ctnter_main_tabs_array', array(__CLASS__, 'inject_tab'), 30);
        add_filter('main_user_tab_content_oauthapp', array(__CLASS__, 'render_tab_content_app'));
        add_filter('main_user_tab_content_oauthgrant', array(__CLASS__, 'render_tab_content_grant'));

        add_action('generate_rewrite_rules', array(__CLASS__, 'rewrite_rules'), 1);

        add_action('wp_enqueue_scripts', array(__CLASS__, 'enqueue_scripts'), 20);
    }

    public static function enqueue_scripts()
    {
        if (!function_exists('get_query_var') || !function_exists('wp_enqueue_script')) {
            return;
        }

        $type = get_query_var('user_center');
        if (empty($type)) {
            return;
        }

        
    }

    public static function rewrite_rules($wp_rewrite)
    {
        if (!get_option('permalink_structure')) {
            return;
        }

        $rewrite_slug = function_exists('_pz') ? trim((string) _pz('user_center_rewrite_slug', 'user')) : 'user';
        $rewrite_slug = $rewrite_slug ? $rewrite_slug : 'user';

        $new_rules = array();
        $new_rules[$rewrite_slug . '$']                   = 'index.php?user_center=1';
        $new_rules[$rewrite_slug . '/([A-Za-z_]+)$']      = 'index.php?user_center=$matches[1]';
        $new_rules[$rewrite_slug . '/([A-Za-z_]+)/$']     = 'index.php?user_center=$matches[1]';

        if (is_object($wp_rewrite) && isset($wp_rewrite->rules) && is_array($wp_rewrite->rules)) {
            $wp_rewrite->rules = $new_rules + $wp_rewrite->rules;
        }
    }

    public static function inject_sidebar_section($con)
    {
        if (!is_user_logged_in()) {
            return $con;
        }

        $icon_app = function_exists('zib_get_svg') ? zib_get_svg('security-color') : '';
        $icon_grant = function_exists('zib_get_svg') ? zib_get_svg('msg-color') : '';
        $icon_doc = function_exists('zib_get_svg') ? zib_get_svg('book-color') : '';
        $doc_url = 'https://cnb.cool/yungnet/zibll-oauth/-/blob/main/docs/%E5%BC%80%E5%8F%91%E6%96%87%E6%A1%A3.md';

        $html = '';
        $html .= '<div class="zib-widget padding-6 mb10-sm">';
        $html .= '<div class="padding-6 ml3">OAuth设置</div>';
        $html .= '<div class="flex ac hh text-center icon-but-box user-icon-but-box">';
        $html .= '<item class="icon-but-oauth-app" data-onclick="[data-target=\'#user-tab-oauthapp\']" ><div class="em16">' . $icon_app . '</div><div class="px12 muted-color mt3">应用管理</div></item>';
        $html .= '<item class="icon-but-oauth-grant" data-onclick="[data-target=\'#user-tab-oauthgrant\']" ><div class="em16">' . $icon_grant . '</div><div class="px12 muted-color mt3">授权记录</div></item>';
        $html .= '<item class="icon-but-oauth-doc"><a target="_blank" rel="noopener noreferrer" href="' . esc_url($doc_url) . '"><div class="em16">' . $icon_doc . '</div><div class="px12 muted-color mt3">开发文档</div></a></item>';
        $html .= '</div>';
        $html .= '</div>';

        return $con . $html;
    }

    public static function inject_tab($tabs_array)
    {
        if (!is_array($tabs_array)) {
            $tabs_array = array();
        }

        $loader = '<div class="zib-widget"><div class="mt10"><div class="placeholder k1 mb10"></div><div class="placeholder k1 mb10"></div><div class="placeholder s1"></div></div><p class="placeholder k1 mb30"></p><div class="placeholder t1 mb30"></div><p class="placeholder k1 mb30"></p><p style="height: 120px;" class="placeholder t1"></p></div>';

        $tabs_array['oauthapp'] = array(
            'title' => '应用管理',
            'nav_attr' => 'drawer-title="应用管理"',
            'content_class' => 'author-user-con',
            'loader' => $loader,
        );

        $tabs_array['oauthgrant'] = array(
            'title' => '授权记录',
            'nav_attr' => 'drawer-title="授权记录"',
            'content_class' => 'author-user-con',
            'loader' => $loader,
        );

        return $tabs_array;
    }

    private static function render_no_permission_app()
    {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return '';
        }

        if (!Zibll_Oauth_Options::is_user_developer($user_id)) {
            $html = '<div class="zib-widget"><div class="box-body">'
                . '<div class="title-h-left"><b>OAuth设置</b></div>'
                . '<div class="muted-2-color mb20">您无此权限，权限申请需联系sunshijie@yungnet.cn</div>'
                . '</div></div>';

            if (function_exists('zib_get_ajax_ajaxpager_one_centent')) {
                return zib_get_ajax_ajaxpager_one_centent($html);
            }
            return $html;
        }

        return null;
    }

    public static function render_tab_content_grant()
    {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return '';
        }

        $nonce = wp_create_nonce(Zibll_Oauth_Ajax::NONCE_ACTION);

        $rows = Zibll_Oauth_Grant::list_active_by_user($user_id, 50);

        // 按应用分组，只保留每个应用的最后一条记录
        $grouped_grants = array();
        foreach ((array) $rows as $r) {
            $appid = !empty($r['appid']) ? (string) $r['appid'] : '';
            if ($appid === '') {
                continue;
            }

            if (!isset($grouped_grants[$appid])) {
                $grouped_grants[$appid] = $r;
            } else {
                // 比较授权时间，保留最新的一条
                $existing_time = !empty($grouped_grants[$appid]['created_at']) ? strtotime($grouped_grants[$appid]['created_at']) : 0;
                $current_time = !empty($r['created_at']) ? strtotime($r['created_at']) : 0;
                if ($current_time > $existing_time) {
                    $grouped_grants[$appid] = $r;
                }
            }
        }

        $grants_html = '';
        foreach ($grouped_grants as $r) {
            $appid = !empty($r['appid']) ? (string) $r['appid'] : '';
            $app_row = $appid ? Zibll_Oauth_App_DB::find_by_appid($appid) : null;
            $site = $app_row ? Zibll_Oauth_App_DB::to_site_array($app_row) : null;
            $title = $site ? (string) $site['title'] : '';
            $icon = $site ? (string) $site['icon'] : '';
            $time = !empty($r['created_at']) ? (string) $r['created_at'] : '';
            $status = isset($r['status']) ? (int) $r['status'] : 0;

            $ico_html = $icon ? '<span class="avatar-img avatar-sm mr6" style="--this-size: 22px;"><img src="' . esc_url($icon) . '" alt="icon"></span>' : '';
            $revoke_btn = '';
            if ($status === 1 && $appid !== '') {
                $ajaxurl = admin_url('admin-ajax.php');
                $revoke_btn = '<form class="ml10 zibll-oauth-revoke-form" method="post" action="' . esc_url($ajaxurl) . '">'
                    . '<input type="hidden" name="action" value="zibll_oauth_revoke_grant">'
                    . '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">'
                    . '<input type="hidden" name="appid" value="' . esc_attr($appid) . '">'
                    . '<button type="button" class="but c-red hollow em09 wp-ajax-submit zibll-oauth-revoke-btn">取消授权</button>'
                    . '</form>';
            }

            $grants_html .= '<div class="mb10"><div class="flex ac jsb muted-box">'
                . '<div class="flex ac">' . $ico_html . '<div><div><b>' . esc_html($title) . '</b></div><div class="muted-2-color em09">AppID：' . esc_html($appid) . '</div><div class="muted-2-color em09">授权时间：' . esc_html($time) . '</div></div></div>'
                . '<div class="flex ac">' . $revoke_btn . '</div>'
                . '</div></div>';
        }

        if ($grants_html === '') {
            $grants_html = '<div class="ajaxpager"><div class="ajax-item text-center muted-2-color" style="padding:40px 0;">暂无授权记录</div></div>';
        }

        $html = '<div class="zib-widget"><div class="box-body"'
            . ' data-cache-key="' . esc_attr('oauth_grant_' . $user_id . '_' . time()) . '"'
            . '>'
            . '<div class="title-h-left"><b>授权记录</b></div>'
            . $grants_html
            . '</div></div>';

        if (function_exists('zib_get_ajax_ajaxpager_one_centent')) {
            return zib_get_ajax_ajaxpager_one_centent($html);
        }
        return $html;
    }

    public static function render_tab_content_app()
    {
        $no = self::render_no_permission_app();
        if ($no !== null) {
            return $no;
        }

        $user_id = get_current_user_id();

        $nonce = wp_create_nonce(Zibll_Oauth_Ajax::NONCE_ACTION);

        $create_modal = '';
        $create_modal = '<a class="but c-blue" href="javascript:;" data-toggle="RefreshModal" data-class="modal-mini" mobile-bottom="true" data-height="420" data-action="zibll_oauth_app_modal&nonce=' . esc_attr($nonce) . '">创建应用</a>';

        $apps_html = '';
        $rows = Zibll_Oauth_App_DB::list_by_user($user_id, 50);
        foreach ((array) $rows as $row) {
            $site = Zibll_Oauth_App_DB::to_site_array($row);
            $status_text = !empty($site['status_text']) ? (string) $site['status_text'] : (string) $site['status'];

            $icon = !empty($site['icon']) ? (string) $site['icon'] : '';
            $ico_html = $icon ? '<span class="avatar-img avatar-sm mr10" style="--this-size: 34px;"><img src="' . esc_url($icon) . '" alt="icon"></span>' : '';

            $appid = !empty($site['appid']) ? (string) $site['appid'] : '';
            $appkey = !empty($site['appkey']) ? (string) $site['appkey'] : '';
            $appkey_revealed = !empty($site['appkey_revealed']) ? (int) $site['appkey_revealed'] : 0;
            $is_approved = (isset($site['status']) && (int) $site['status'] === Zibll_Oauth_App_DB::STATUS_APPROVED);

            // 首次展示逻辑：审核通过且从未展示过 -> 展示完整密钥并标记
            $show_full_key = false;
            if ($is_approved && $appkey !== '' && $appkey_revealed === 0) {
                $show_full_key = true;
                // 立即标记为已展示，下次加载时将只显示脱敏版本
                Zibll_Oauth_App_DB::mark_appkey_revealed((int) $site['id']);
            }

            $appkey_display = '';
            if ($appkey !== '') {
                if ($show_full_key) {
                    $appkey_display = $appkey;
                } else {
                    // 脱敏展示
                    if (strlen($appkey) > 10) {
                        $appkey_display = substr($appkey, 0, 4) . '****' . substr($appkey, -4);
                    } else {
                        $appkey_display = $appkey;
                    }
                }
            }

            $cred_html = '';
            if ($appid !== '' || $appkey !== '') {
                $cred_html .= '<div class="muted-2-color em09 mt6">';
                if ($appid !== '') {
                    $cred_html .= 'AppID：' . esc_html($appid) . ' ';
                }
                if ($appkey_display !== '') {
                    $cred_html .= 'AppKey：' . esc_html($appkey_display);
                }
                $cred_html .= '</div>';
                // 首次展示时追加醒目的安全提示
                if ($show_full_key) {
                    $cred_html .= '<div class="em09 mt6" style="color:#e74c3c;font-weight:bold;">⚠️ 请立即复制保存以上 AppKey，此密钥仅展示一次！刷新后将被隐藏。</div>';
                }
            }

            $updated_at = !empty($row['updated_at']) ? (string) $row['updated_at'] : '';
            $updated_html = $updated_at ? ('<div class="muted-2-color em09 mt6">更新时间：' . esc_html($updated_at) . '</div>') : '';

            $edit_link = '';
            $edit_link = '<a class="but c-blue hollow mr10" href="javascript:;" data-toggle="RefreshModal" data-class="modal-mini" mobile-bottom="true" data-height="420" data-action="zibll_oauth_app_modal&id=' . (int) $site['id'] . '&nonce=' . esc_attr($nonce) . '">编辑</a>';

            $delete_link = '';
            $delete_link = '<a class="but c-red hollow" href="javascript:;" data-toggle="RefreshModal" data-class="modal-mini" mobile-bottom="true" data-height="520" data-action="zibll_oauth_app_delete_confirm_modal&id=' . (int) $site['id'] . '&nonce=' . esc_attr($nonce) . '">删除</a>';

            $rotate_link = '';
            if (!empty($site['id'])) {
                $rotate_link = '<a class="but c-yellow hollow mr10" href="javascript:;" data-toggle="RefreshModal" data-class="modal-mini" mobile-bottom="true" data-height="560" data-action="zibll_oauth_appkey_rotate_modal&id=' . (int) $site['id'] . '&nonce=' . esc_attr($nonce) . '">轮转密钥</a>';
            }

            $submit_link = '';
            $status = isset($site['status']) ? (int) $site['status'] : 0;
            if (in_array($status, array(Zibll_Oauth_App_DB::STATUS_DRAFT, Zibll_Oauth_App_DB::STATUS_REJECTED), true)) {
                $submit_link = '<a class="but c-blue hollow mr10" href="javascript:;" data-toggle="RefreshModal" data-class="modal-mini" mobile-bottom="true" data-height="420" data-action="zibll_oauth_app_submit_modal&id=' . (int) $site['id'] . '&nonce=' . esc_attr($nonce) . '">提交审核</a>';
            }

            $apps_html .= '<div class="zib-widget mb15"><div class="box-body">';
            $apps_html .= '<div class="flex ac jsb">';
            $apps_html .= '<div class="flex ac">' . $ico_html . '<div><div><b>' . esc_html((string) $site['title']) . '</b></div><div class="muted-2-color em09">状态：' . esc_html($status_text) . '</div>' . $cred_html . $updated_html . '</div></div>';
            $apps_html .= '<div class="shrink0">' . $submit_link . $rotate_link . $edit_link . $delete_link . '</div>';
            $apps_html .= '</div>';
            $apps_html .= '</div></div>';
        }

        if ($apps_html === '') {
            $apps_html = '<div class="ajaxpager"><div class="ajax-item text-center muted-2-color" style="padding:40px 0;">暂无应用</div></div>';
        }

        $html = '<div class="zib-widget"><div class="box-body">'
            . '<div class="flex ac jsb">'
            . '<div class="title-h-left"><b>应用管理</b></div>'
            . '<div>' . $create_modal . '</div>'
            . '</div>'
            . '</div></div>'
            . $apps_html;

        if (function_exists('zib_get_ajax_ajaxpager_one_centent')) {
            return zib_get_ajax_ajaxpager_one_centent($html);
        }
        return $html;
    }
}
