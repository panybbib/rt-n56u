<!DOCTYPE html>
<html>
<head>
<title><#Web_Title#> - <#menu5_36#></title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="-1">

<link rel="shortcut icon" href="images/favicon.ico">
<link rel="icon" href="images/favicon.png">
<link rel="stylesheet" type="text/css" href="/bootstrap/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="/bootstrap/css/main.css">
<link rel="stylesheet" type="text/css" href="/bootstrap/css/engage.itoggle.css">

<script type="text/javascript" src="/jquery.js"></script>
<script type="text/javascript" src="/bootstrap/js/bootstrap.min.js"></script>
<script type="text/javascript" src="/bootstrap/js/engage.itoggle.min.js"></script>
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/itoggle.js"></script>
<script type="text/javascript" src="/client_function.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/help_b.js"></script>

<script>
var $j = jQuery.noConflict();
<% aliyundrive_status(); %>
<% disk_pool_mapping_info(); %>
$j(document).ready(function() {
	init_itoggle('aliyundrive_enable');
	init_itoggle('aliyun_wan');
	init_itoggle('ald_skip_upload');
	init_itoggle('ald_no_trash');
	init_itoggle('ald_read_only');
	init_itoggle('ald_domain_id');
});
</script>

<script>
<% login_state_hook(); %>

function initial(){
	show_banner(2);
	show_menu(5,22,0);
	show_footer();
	show_aliyundrive_dir();
	fill_status(aliyundrive_status());
	var o1 = document.form.aliyundrive_dir;
	o1.value = '<% nvram_get_x("","aliyundrive_dir"); %>';
	if (!login_safe())
		textarea_scripts_enabled(0);
}

function textarea_scripts_enabled(v){
	inputCtrl(document.form['scripts.aliyundrive_script.sh'], v);
}

function fill_status(status_code){
	var stext = "Unknown";
	if (status_code == 0)
		stext = "<#Stopped#>";
	else if (status_code == 1)
		stext = "<#Running#>";
	$("aliyundrive_status").innerHTML = '<span class="label label-' + (status_code != 0 ? 'success' : 'warning') + '">' + stext + '</span>';
}
function applyRule(){
	showLoading();
	
	document.form.action_mode.value = " Restart ";
	document.form.current_page.value = "/Advanced_aliyundrive.asp";
	document.form.next_page.value = "";
	
	document.form.submit();
}

function done_validating(action){
	refreshpage();
}

function show_aliyundrive_dir(){
	var code ='<option value="/tmp" >/tmp/aliyun</option>';
	if(pool_names().length == 0)
		code +='<option value="non" >未发现存储设备</option>';
	else{
		for(var i = 0; i < pool_names().length; ++i){
			code +='<option value="/media/'+ pool_names()[i] +'" >/media/'+ pool_names()[i] + '/aliyun</option>';
		}
	}
	$("aliyundrive_dir").innerHTML = code;
}

</script>
</head>

<body onload="initial();" onunLoad="return unload_body();">

<div id="Loading" class="popup_bg"></div>

<div class="wrapper">
	<div class="container-fluid" style="padding-right: 0px">
		<div class="row-fluid">
			<div class="span3"><center><div id="logo"></div></center></div>
			<div class="span9" >
				<div id="TopBanner"></div>
			</div>
		</div>
	</div>

	<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

	<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">

	<input type="hidden" name="current_page" value="Advanced_aliyundrive.asp">
	<input type="hidden" name="next_page" value="">
	<input type="hidden" name="next_host" value="">
	<input type="hidden" name="sid_list" value="ALDRIVER;">
	<input type="hidden" name="group_id" value="">
	<input type="hidden" name="action_mode" value="">
	<input type="hidden" name="action_script" value="">


	<div class="container-fluid">
		<div class="row-fluid">
			<div class="span3">
				<!--Sidebar content-->
				<!--=====Beginning of Main Menu=====-->
				<div class="well sidebar-nav side_nav" style="padding: 0px;">
					<ul id="mainMenu" class="clearfix"></ul>
					<ul class="clearfix">
						<li>
							<div id="subMenu" class="accordion"></div>
						</li>
					</ul>
				</div>
			</div>

			<div class="span9">
				<!--Body content-->
				<div class="row-fluid">
					<div class="span12">
						<div class="box well grad_colour_dark_blue">
							<h2 class="box_head round_top"><#menu5_36#></h2>
							<div class="round_bottom">
								<div>
                            	<ul class="nav nav-tabs" style="margin-bottom: 10px;">
									<li class="active">
                                    	<a href="Advanced_aliyundrive.asp">阿里云盘</a>
                                	</li>
                            	</ul>
							</div>
							<div class="row-fluid">
								<div id="tabMenu" class="submenuBlock"></div>
									<div class="alert alert-info" style="margin: 10px;">阿里云盘 WebDAV<br>
									获取 refresh token：登录阿里云盘 <a href="https://www.aliyundrive.com/drive">https://www.aliyundrive.com/drive</a>，通过[F12]进入控制台执行"JSON.parse(localStorage.token).refresh_token"
									</div>

								<table width="100%" cellpadding="4" cellspacing="0" class="table">
									<tr>
									<th><#running_status#></th>
										<td id="aliyundrive_status" colspan="2">
										</td>
									</tr>

									<tr>
									<th width="30%" style="border-top: 0 none;">启用阿里云盘 WebDAV</th>
										<td style="border-top: 0 none;">
											<div class="main_itoggle">
												<div id="aliyundrive_enable_on_of">
													<input type="checkbox" id="aliyundrive_enable_fake" <% nvram_match_x("", "aliyundrive_enable", "1", "value=1 checked"); %><% nvram_match_x("", "aliyundrive_enable", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="aliyundrive_enable" id="aliyundrive_enable_1" class="input" value="1" <% nvram_match_x("", "aliyundrive_enable", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="aliyundrive_enable" id="aliyundrive_enable_0" class="input" value="0" <% nvram_match_x("", "aliyundrive_enable", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>

									<tr>
									<th>使用说明</th>
										<td>
											<input type="button" class="btn btn-success" value="查看使用说明" onclick="window.open('https://github.com/messense/aliyundrive-webdav')" size="0">
										</td>
									</tr>

									<tr>
									<th>Refresh Token</th>
										<td>
											<input type="text" class="input" name="ald_refresh_token" id="ald_refresh_token" style="width: 200px" value="<% nvram_get_x("","ald_refresh_token"); %>" />
										</td>
									</tr>

									<tr>
									<th>云盘App存放目录</th>
										<td colspan="2">
											<select name="aliyundrive_dir" id="aliyundrive_dir" class="input">
											</select>
										</td>
									</tr>

									<tr>
									<th>云盘根目录</th>
										<td>
											<input type="text" class="input" name="ald_root" id="ald_root" style="width: 200px" value="<% nvram_get_x("","ald_root"); %>" />
										</td>
									</tr>

									<tr>
									<th>监听主机</th>
										<td>
											<input type="text" class="input" name="ald_host" id="ald_host" style="width: 200px" value="<% nvram_get_x("","ald_host"); %>" />
											<div><span style="color:#888;">"0.0.0.0"或"::"表示所有IP(IPv4/IPv6)</span></div>
										</td>
									</tr>

									<tr>
									<th>监听端口</th>
										<td>
											<input type="text" class="input" name="ald_port" id="ald_port" style="width: 200px" value="<% nvram_get_x("","ald_port"); %>" />
											&nbsp;<span style="color:#888;">[80..65535]</span>
										</td>
									</tr>

									<tr>
									<th>WAN 访问开关</th>
										<td>
											<div class="main_itoggle">
												<div id="aliyun_wan_on_of">
													<input type="checkbox" id="aliyun_wan_fake" <% nvram_match_x("", "aliyun_wan", "1", "value=1 checked"); %><% nvram_match_x("", "aliyun_wan", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="aliyun_wan" id="aliyun_wan_1" class="input" value="1" <% nvram_match_x("", "aliyun_wan", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="aliyun_wan" id="aliyun_wan_0" class="input" value="0" <% nvram_match_x("", "aliyun_wan", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>

									<tr>
									<th>用户名</th>
										<td>
											<input type="text" class="input" name="ald_auth_user" id="ald_auth_user" style="width: 200px" value="<% nvram_get_x("","ald_auth_user"); %>" />
											<div><span style="color:#888;">无需用户名和密码登录请留空</span></div>
										</td>
									</tr>

									<tr>
									<th>密码</th>
										<td>
											<input type="text" class="input" name="ald_auth_password" id="ald_auth_password" style="width: 200px" value="<% nvram_get_x("","ald_auth_password"); %>" />
											<button style="margin-left: -5px;" class="btn" type="button" onclick="passwordShowHide('ald_auth_password')"><i class="icon-eye-close"></i></button>
										</td>
									</tr>

									<tr>
									<th>下载缓冲大小(bytes)</th>
										<td>
											<input type="text" class="input" name="ald_read_buffer_size" id="ald_read_buffer_size" style="width: 200px" value="<% nvram_get_x("","ald_read_buffer_size"); %>" />
										</td>
									</tr>

									<tr>
									<th>目录缓存大小</th>
										<td>
											<input type="text" class="input" name="ald_cache_size" id="ald_cache_size" style="width: 200px" value="<% nvram_get_x("","ald_cache_size"); %>" />
										</td>
									</tr>

									<tr>
									<th>目录缓存过期时间（单位为秒）</th>
										<td>
											<input type="text" class="input" name="ald_cache_ttl" id="ald_cache_ttl" style="width: 200px" value="<% nvram_get_x("","ald_cache_ttl"); %>" />
										</td>
									</tr>

									<tr>
									<th>上传缓冲大小(bytes)</th>
										<td>
											<input type="text" class="input" name="ald_upload_buffer_size" id="ald_upload_buffer_size" style="width: 200px" value="<% nvram_get_x("","ald_upload_buffer_size"); %>" />
										</td>
									</tr>

									<tr>
									<th width="30%" style="border-top: 0 none;">上传时忽略大小相同文件</th>
										<td style="border-top: 0 none;">
											<div class="main_itoggle">
												<div id="ald_skip_upload_on_of">
													<input type="checkbox" id="ald_skip_upload_fake" <% nvram_match_x("", "ald_skip_upload", "1", "value=1 checked"); %><% nvram_match_x("", "ald_skip_upload", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="ald_skip_upload" id="ald_skip_upload_1" class="input" value="1" <% nvram_match_x("", "ald_skip_upload", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="ald_skip_upload" id="ald_skip_upload_0" class="input" value="0" <% nvram_match_x("", "ald_skip_upload", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>

									<tr>
									<th width="30%" style="border-top: 0 none;">禁止上传、修改和删除文件操作</th>
										<td style="border-top: 0 none;">
											<div class="main_itoggle">
												<div id="ald_no_trash_on_of">
													<input type="checkbox" id="ald_no_trash_fake" <% nvram_match_x("", "ald_no_trash", "1", "value=1 checked"); %><% nvram_match_x("", "ald_no_trash", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="ald_no_trash" id="ald_no_trash_1" class="input" value="1" <% nvram_match_x("", "ald_no_trash", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="ald_no_trash" id="ald_no_trash_0" class="input" value="0" <% nvram_match_x("", "ald_no_trash", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>

									<tr>
									<th width="30%" style="border-top: 0 none;">启用只读模式</th>
										<td style="border-top: 0 none;">
											<div class="main_itoggle">
												<div id="ald_read_only_on_of">
													<input type="checkbox" id="ald_read_only_fake" <% nvram_match_x("", "ald_read_only", "1", "value=1 checked"); %><% nvram_match_x("", "ald_read_only", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="ald_read_only" id="ald_read_only_1" class="input" value="1" <% nvram_match_x("", "ald_read_only", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="ald_read_only" id="ald_read_only_0" class="input" value="0" <% nvram_match_x("", "ald_read_only", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>

									<!--
									<tr>
									<th width="30%" style="border-top: 0 none;">阿里云相册与云盘服务 domainId</th>
										<td style="border-top: 0 none;">
											<div class="main_itoggle">
												<div id="ald_domain_id_on_of">
													<input type="checkbox" id="ald_domain_id_fake" <% nvram_match_x("", "ald_domain_id", "1", "value=1 checked"); %><% nvram_match_x("", "ald_domain_id", "0", "value=0"); %>  />
												</div>
											</div>
											<div style="position: absolute; margin-left: -10000px;">
												<input type="radio" value="1" name="ald_domain_id" id="ald_domain_id_1" class="input" value="1" <% nvram_match_x("", "ald_domain_id", "1", "checked"); %> /><#checkbox_Yes#>
												<input type="radio" value="0" name="ald_domain_id" id="ald_domain_id_0" class="input" value="0" <% nvram_match_x("", "ald_domain_id", "0", "checked"); %> /><#checkbox_No#>
											</div>
										</td>
									</tr>-->

									<tr id="row_post_wan_script">
										<td colspan="2">
											<i class="icon-hand-right"></i> <a href="javascript:spoiler_toggle('script2')"><span>Aliyundrive脚本</span></a>
											<div id="script2">
												<textarea rows="10" wrap="off" spellcheck="false" maxlength="314571" class="span12" name="scripts.aliyundrive_script.sh" style="font-family:'Courier New'; font-size:12px;"><% nvram_dump("scripts.aliyundrive_script.sh",""); %></textarea>
											</div>
										</td>
									</tr>

									<tr>
										<td colspan="4" style="border-top: 0 none;">
											<br />
											<center><input class="btn btn-primary" style="width: 219px" type="button" value="<#CTL_apply#>" onclick="applyRule()" /></center>
										</td>
									</tr>
									</table>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>

	</form>

	<div id="footer"></div>
</div>
</body>
</html>
