<?php
/**
 * Plugin Name: Access Guard
 * Plugin URI: https://neebplugins.com/access-guard
 * Description: Enhance access protection, control user permissions, and provide IP banning functionality.
 * Version: 1.0.1
 * Author: NeeB Plugins
 * Author URI: https://neebplugins.com
 * Text Domain: access-guard
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 6.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

defined( 'ACCESS_GUARD_VERSION' ) or define( 'ACCESS_GUARD_VERSION', '1.0.0' );

class Access_Guard {

	private $ip_block_list;
	private $custom_ban_messages;
	private $access_control_rules;
	private $instance;

	public function get_instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new Access_Guard();
		}
		return self::$instance;
	}

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'wp', array( $this, 'check_access' ) );
		add_filter( 'the_content', array( $this, 'restrict_content' ) );
	}

	public function add_admin_page() {
		add_menu_page(
			__( 'Access Guard', 'access-guard' ),
			__( 'Access Guard', 'access-guard' ),
			'manage_options',
			'access-guard',
			array( $this, 'render_admin_page' ),
			'dashicons-lock'
		);
	}

	public function render_admin_page() {
		?>
		<div class="wrap">
			<h1><?php __( 'Access Guard', 'access-guard' ); ?></h1>
			<p><?php __( 'Configure access protection settings here.', 'access-guard' ); ?></p>
			
			<form method="post" action="options.php">
				<?php
				settings_fields( 'access_guard_options' );
				do_settings_sections( 'access-guard' );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	public function register_settings() {
		// Register plugin settings
		register_setting( 'access_guard_options', 'access_guard_ip_block_list' );
		register_setting( 'access_guard_options', 'access_guard_custom_ban_messages' );
		register_setting( 'access_guard_options', 'access_guard_access_control_rules' );

		add_settings_section(
			'access_guard_settings_section',
			__( 'Access Protection Settings', 'access-guard' ),
			array( $this, 'access_guard_settings_section_callback' ),
			'access-guard'
		);

		add_settings_field(
			'access_guard_ip_block_list',
			__( 'IP Block List', 'access-guard' ),
			array( $this, 'access_guard_ip_block_list_callback' ),
			'access-guard',
			'access_guard_settings_section'
		);

		add_settings_field(
			'access_guard_custom_ban_messages',
			__( 'Custom Ban Messages', 'access-guard' ),
			array( $this, 'access_guard_custom_ban_messages_callback' ),
			'access-guard',
			'access_guard_settings_section'
		);

		add_settings_field(
			'access_guard_access_control_rules',
			__( 'Access Control Rules', 'access-guard' ),
			array( $this, 'access_guard_access_control_rules_callback' ),
			'access-guard',
			'access_guard_settings_section'
		);
	}

	public function access_guard_settings_section_callback() {
		echo wp_kses_post( __( '<p>Configure the access protection settings below:</p>', 'access-guard' ) );
	}

	public function access_guard_ip_block_list_callback() {
		$ip_block_list = get_option( 'access_guard_ip_block_list' );
		echo '<textarea name="access_guard_ip_block_list" rows="5" cols="50">' . esc_textarea( $ip_block_list ) . '</textarea>';
		echo wp_kses_post( __( '<p class="description">Enter the IP addresses or ranges to block, one per line.</p>', 'access-guard' ) );
	}

	public function access_guard_custom_ban_messages_callback() {
		$custom_ban_messages = get_option( 'access_guard_custom_ban_messages' );
		echo '<textarea name="access_guard_custom_ban_messages" rows="5" cols="50">' . esc_textarea( $custom_ban_messages ) . '</textarea>';
		echo wp_kses_post( __( '<p class="description">Enter the custom ban message to display to blocked users.</p>', 'access-guard' ) );
	}

	public function access_guard_access_control_rules_callback() {
		$banned_user_roles = get_option( 'access_guard_access_control_rules', array() );
		$banned_user_roles = ! empty( $banned_user_roles ) ? $banned_user_roles : array();
		$user_roles        = wp_roles()->get_names();

		foreach ( $user_roles as $role_value => $role_label ) {
			$checked = in_array( $role_value, $banned_user_roles, true ) ? 'checked' : '';

			echo '<label>';
			echo '<input type="checkbox" name="access_guard_access_control_rules[]" value="' . esc_attr( $role_value ) . '" ' . esc_attr( $checked ) . '>';
			echo esc_html( $role_label );
			echo '</label><br>';
		}

		echo '<p class="description">Select the user roles to ban.</p>';
	}

	public function check_access() {
		if ( $this->check_ip_ban() ) {
			$this->display_ban_message();
			exit;
		}

		if ( $this->is_restricted_content() ) {
			if ( ! $this->has_access() ) {
				$this->display_ban_message();
				exit;
			}
		}

		if ( $this->is_role_banned() ) {
			$this->display_ban_message();
			exit;
		}
	}

	public function check_ip_ban() {
		$user_ip       = $this->get_user_ip();
		$ip_block_list = explode( "\n", get_option( 'access_guard_ip_block_list' ) );

		foreach ( $ip_block_list as $ip ) {
			$ip = trim( $ip );
			if ( $ip && $this->is_ip_in_range( $user_ip, $ip ) ) {
				return true;
			}
		}
	}

	public function is_role_banned() {
		if ( is_user_logged_in() ) {

			$user  = wp_get_current_user();
			$roles = (array) $user->roles;

			$banned_user_roles = get_option( 'access_guard_access_control_rules', array() );

			if ( empty( $banned_user_roles ) ) {
				return false;
			}

			return array_intersect( $banned_user_roles, $roles ) ? true : false;

		}
	}

	private function is_ip_in_range( $user_ip, $ip ) {
		if ( ! strpos( $ip, '-' ) ) {
			if ( $user_ip === $ip ) {
				return true;
			}
		} else {
			$ip_range = explode( '-', $ip );
			$start_ip = ip2long( $ip_range[0] );
			$end_ip   = ip2long( $ip_range[1] );
			$user_ip  = ip2long( $user_ip );

			if ( $user_ip >= $start_ip && $user_ip <= $end_ip ) {
				return true;
			}
		}

		return false;
	}

	public function restrict_content( $content ) {
		global $post;
		$restricted = get_post_meta( $post->ID, 'access_guard_restricted', true );

		if ( $restricted && ! current_user_can( 'read' ) ) {
			return __( 'This content is restricted. Please contact the administrator for access.', 'access-guard' );
		}

		return $content;
	}

	private function is_restricted_content() {
		global $post;
		$restricted = get_post_meta( $post->ID, 'access_guard_restricted', true );

		return $restricted ? true : false;
	}

	private function get_user_ip() {
		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			//ip from share internet
			$ip = sanitize_text_field( $_SERVER['HTTP_CLIENT_IP'] );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) { //phpcs:ignore
			//ip pass from proxy
			$ip = sanitize_text_field( $_SERVER['HTTP_X_FORWARDED_FOR'] ); //phpcs:ignore
		} else {
			$ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ); //phpcs:ignore
		}
		return $ip;
	}

	private function display_ban_message() {
		$custom_ban_messages = get_option( 'access_guard_custom_ban_messages' );
		$tailwind_css        = plugins_url( '/assets/css/tailwind.min.css', __FILE__ );
		?>
		
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title><?php esc_html_e( 'Access Guard', 'access-guard' ); ?></title>
			<link href="<?php echo esc_url( $tailwind_css );?>" rel="stylesheet"> <?php // phpcs:ignore ?>
		</head>
		<body class="bg-gray-100">
			<div class="flex items-center justify-center h-screen">
				<div class="w-auto bg-white p-8 rounded-lg shadow">
					<h1 class="text-2xl font-bold mb-4 text-red-500 text-center">
					<?php esc_html_e( 'Access Guard', 'access-guard' ); ?> </h1>
					<p class ="mb-4 text-center"> <?php echo wp_kses_post( $custom_ban_messages ); ?></p>
				</div>
			</div>
		</body>
		</html>
		<?php
	}

}

new Access_Guard();
