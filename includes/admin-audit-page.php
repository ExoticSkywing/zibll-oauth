<?php

if (!defined('ABSPATH')) {
    exit;
}

if (!is_user_logged_in()) {
    exit;
}

if (!current_user_can('manage_options')) {
    wp_die('权限不足');
}

$action = !empty($_REQUEST['action']) ? (string) $_REQUEST['action'] : '';

if ($action === 'process_submit') {
    check_admin_referer('zibll_oauth_app_audit');

    $process_id = isset($_REQUEST['process_id']) ? (int) $_REQUEST['process_id'] : 0;
    $process = isset($_REQUEST['process']) ? (int) $_REQUEST['process'] : 0;
    $msg = isset($_REQUEST['msg']) ? trim((string) $_REQUEST['msg']) : '';

    $before = Zibll_Oauth_App_DB::get_by_id($process_id);
    $new_status = $process === 2 ? Zibll_Oauth_App_DB::STATUS_REJECTED : Zibll_Oauth_App_DB::STATUS_APPROVED;

    $result = Zibll_Oauth_App_DB::audit($process_id, $new_status, $msg);
    if (is_wp_error($result)) {
        echo '<div class="updated notice-alt"><h4 style="color:#ed2273;">处理失败：' . esc_html($result->get_error_message()) . '</h4></div>';
    } else {
        echo '<div class="updated notice-alt"><h4 style="color:#0aaf19;">申请处理成功</h4></div>';
        if ($before) {
            Zibll_Oauth_Admin_Audit::notify_audit_result($before, $new_status, $msg);
        }
    }
}

$page_url = add_query_arg('page', Zibll_Oauth_Admin_Audit::PAGE_SLUG, admin_url('admin.php'));
$s = !empty($_REQUEST['s']) ? (string) $_REQUEST['s'] : '';

$where_sql = '1=1';
$where_args = array();

$status = isset($_REQUEST['status']) ? (int) $_REQUEST['status'] : -1;
if ($status >= 0) {
    $where_sql .= ' AND status = %d';
    $where_args[] = $status;
}

if ($s !== '') {
    $where_sql .= " AND (title LIKE %s OR appid LIKE %s OR redirect_uri LIKE %s)";
    $like = '%' . $s . '%';
    $where_args[] = $like;
    $where_args[] = $like;
    $where_args[] = $like;
}

global $wpdb;
$table = Zibll_Oauth_App_DB::table_name();

$all_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
$all_count = $where_args ? (int) $wpdb->get_var($wpdb->prepare($all_sql, $where_args)) : (int) $wpdb->get_var($all_sql);

$ice_perpage = 20;
$page = isset($_REQUEST['paged']) ? max(1, (int) $_REQUEST['paged']) : 1;
$offset = $ice_perpage * ($page - 1);

$order = !empty($_REQUEST['orderby']) ? (string) $_REQUEST['orderby'] : 'id';
$desc = !empty($_REQUEST['desc']) ? (string) $_REQUEST['desc'] : 'DESC';
$desc = strtoupper($desc) === 'ASC' ? 'ASC' : 'DESC';

$allowed_order = array('id', 'status', 'user_id', 'created_at', 'updated_at');
if (!in_array($order, $allowed_order, true)) {
    $order = 'id';
}

$list_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$order} {$desc} LIMIT %d,%d";
$args = $where_args;
$args[] = $offset;
$args[] = $ice_perpage;

$list = $args ? $wpdb->get_results($wpdb->prepare($list_sql, $args), ARRAY_A) : $wpdb->get_results($wpdb->prepare($list_sql, $offset, $ice_perpage), ARRAY_A);

$process_id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
$is_process = ($action === 'process' && $process_id);

?>
<style>
.table-box>table{min-width:1000px;}
</style>
<div class="wrap">
  <h2>OAuth 应用审核管理</h2>
  <?php echo $s ? '<div>"' . esc_attr($s) . '" 的搜索结果</div>' : ''; ?>
  <div class="">
    <ul class="subsubsub">
      <li class="all"><a href="<?php echo esc_url($page_url); ?>">全部</a> |</li>
      <li class="all"><a href="<?php echo esc_url(add_query_arg('status', Zibll_Oauth_App_DB::STATUS_PENDING, $page_url)); ?>">待审核</a> |</li>
      <li class="all"><a href="<?php echo esc_url(add_query_arg('status', Zibll_Oauth_App_DB::STATUS_APPROVED, $page_url)); ?>">已通过</a> |</li>
      <li class="all"><a href="<?php echo esc_url(add_query_arg('status', Zibll_Oauth_App_DB::STATUS_REJECTED, $page_url)); ?>">已驳回</a></li>
    </ul>
    <div class="order-header" style="margin:6px 0 12px;float:right;">
      <form class="form-inline form-order" method="get" action="<?php echo esc_url(admin_url('admin.php')); ?>">
        <input type="hidden" name="page" value="<?php echo esc_attr(Zibll_Oauth_Admin_Audit::PAGE_SLUG); ?>">
        <div class="form-group">
          <input type="text" class="form-control" name="s" placeholder="搜索应用" value="<?php echo esc_attr($s); ?>">
          <button type="submit" class="button button-primary">提交</button>
        </div>
      </form>
      <?php if ($is_process) { echo '<a href="' . esc_url($page_url) . '">查看全部</a>'; } ?>
    </div>
  </div>

  <div class="table-box" style="overflow-y:auto;width:100%;">
    <table class="widefat fixed striped posts">
      <thead>
        <tr>
          <?php
          $theads = array();
          $theads[] = array('width' => '8%', 'orderby' => 'status', 'name' => '状态');
          $theads[] = array('width' => '10%', 'orderby' => 'user_id', 'name' => '开发者');
          $theads[] = array('width' => '16%', 'orderby' => '', 'name' => '应用名称');
          $theads[] = array('width' => '18%', 'orderby' => '', 'name' => 'AppID');
          $theads[] = array('width' => '24%', 'orderby' => '', 'name' => '回调地址');
          $theads[] = array('width' => '8%', 'orderby' => 'created_at', 'name' => '提交时间');
          $theads[] = array('width' => '8%', 'orderby' => 'updated_at', 'name' => '更新时间');

          foreach ($theads as $thead) {
              $orderby = '';
              if ($thead['orderby']) {
                  $orderby_url = add_query_arg('orderby', $thead['orderby'], $page_url);
                  $orderby .= '<a title="降序" href="' . esc_url(add_query_arg('desc', 'ASC', $orderby_url)) . '"><span class="dashicons dashicons-arrow-up"></span></a>';
                  $orderby .= '<a title="升序" href="' . esc_url(add_query_arg('desc', 'DESC', $orderby_url)) . '"><span class="dashicons dashicons-arrow-down"></span></a>';
                  $orderby = '<span class="orderby-but">' . $orderby . '</span>';
              }
              echo '<th width="' . esc_attr($thead['width']) . '">' . esc_html($thead['name']) . $orderby . '</th>';
          }
          ?>
        </tr>
      </thead>
      <tbody>
        <?php
        if ($list) {
            foreach ($list as $row) {
                $uid = !empty($row['user_id']) ? (int) $row['user_id'] : 0;
                $u = $uid ? get_userdata($uid) : null;
                $user_name = $u ? $u->display_name : '用户不存在';

                $status_but = Zibll_Oauth_App_DB::get_status_text((int) $row['status']);
                if ((int) $row['status'] === Zibll_Oauth_App_DB::STATUS_APPROVED) {
                    $status_but = '<span style="color:#0989fd;">已通过</span>';
                } elseif ((int) $row['status'] === Zibll_Oauth_App_DB::STATUS_REJECTED) {
                    $status_but = '<span style="color:#fb4444;">已驳回</span>';
                } elseif ((int) $row['status'] === Zibll_Oauth_App_DB::STATUS_PENDING) {
                    $status_but = '<a class="button" href="' . esc_url(add_query_arg(array('action' => 'process', 'id' => (int) $row['id']), $page_url)) . '">立即处理</a>';
                }

                if ($is_process && $process_id === (int) $row['id']) {
                    $status_but = '<span style="color:#fb4444;">正在处理</span>';
                }

                $appid = !empty($row['appid']) ? (string) $row['appid'] : '';
                $redirect_uri = !empty($row['redirect_uri']) ? (string) $row['redirect_uri'] : '';

                echo '<tr>';
                echo '<td>' . $status_but . '</td>';
                echo '<td>' . esc_html($user_name) . '</td>';
                echo '<td>' . esc_html((string) $row['title']) . '</td>';
                echo '<td><code>' . esc_html($appid) . '</code></td>';
                echo '<td style="word-break:break-all;">' . esc_html($redirect_uri) . '</td>';
                echo '<td>' . esc_html((string) $row['created_at']) . '</td>';
                echo '<td>' . esc_html((string) $row['updated_at']) . '</td>';
                echo '</tr>';

                if ($is_process && $process_id === (int) $row['id']) {
                    $html = '';
                    $html .= '<tr><th>应用名称</th><td><input style="width:95%;max-width:500px;" name="name" type="text" value="' . esc_attr((string) $row['title']) . '" readonly></td></tr>';
                    $html .= '<tr><th>回调地址</th><td><input style="width:95%;max-width:500px;" name="redirect" type="text" value="' . esc_attr($redirect_uri) . '" readonly></td></tr>';
                    $html .= '<tr><th>处理留言</th><td><input style="width:95%;max-width:500px;" name="msg" type="text" value="" placeholder="给开发者留言（驳回请填写原因）"></td></tr>';

                    $process = '';
                    $process .= '<p><input type="radio" name="process" id="process_1" value="1" checked="checked"><label for="process_1" style="color:#036ee2;">批准申请</label></p>';
                    $process .= '<p><input type="radio" name="process" id="process_2" value="2"><label for="process_2" style="color:#eb1b65;">拒绝申请</label></p>';
                    $process .= '<input name="process_id" type="hidden" value="' . (int) $row['id'] . '">';
                    $process .= '<input name="action" type="hidden" value="process_submit">';

                    $html .= '<tr><th></th><td>' . $process . '</td></tr>';
                    $html .= '<tr><th></th><td><p><button type="submit" class="button button-primary process-submit">确认提交</button></p></td></tr>';

                    echo '<form action="' . esc_url($page_url) . '" method="post">';
                    wp_nonce_field('zibll_oauth_app_audit');
                    echo '<table class="form-table"><tbody>' . $html . '</tbody></table>';
                    echo '</form>';
                }
            }
        } else {
            echo '<tr><td colspan="7" align="center"><strong>暂无申请记录</strong></td></tr>';
        }
        ?>
      </tbody>
    </table>
  </div>

  <?php
  if (function_exists('zibpay_admin_pagenavi')) {
      echo zibpay_admin_pagenavi($all_count, $ice_perpage);
  }
  ?>
</div>
