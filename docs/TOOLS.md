# MCP tool reference

Generated from the registered source functions. Refer to source signatures for parameters and defaults. API permissions and firmware determine availability.

All responses are secret-redacted (`<REDACTED>`); requests containing `<REDACTED>` are refused.

## diagnostics (7 tools, SSH)

Need SSH set up with `ssh_setup.py`. CPU is read before each debug/capture (debug refused at ≥ 95 %, capture at ≥ 90 %). Output is redacted and limited to 2000 lines.

### `cpu_usage`
Current CPU % and which debug/capture limits apply right now.

### `diag_command`
One read-only CLI command from an allowlist (`get system status`, `get router info ...`, `diagnose sys session list`, `diagnose vpn tunnel list`, `diagnose vpn ike gateway list`, `execute ping`, ...). `| grep` allowed; no chaining, no config, no debug.

### `debug_flow`
`diagnose debug flow` with at least one filter (`addr`, `saddr`, `daddr`, `port`, `dport`, `proto`), up to 100 packets and 120 s. Always ends with trace stop, filter clear, debug disable and reset.

### `debug_ike`
IKE debug filtered by `rem_addr4` or `tunnel_name` (`diagnose vpn ike log filter ...`), up to 120 s. Always ends with `diagnose debug application ike 0`, IKE filter clear, debug disable and reset.

### `debug_application`
`diagnose debug application <app> -1` for an allowlist (fnbamd, authd, fssod, update, forticldd, csfd, fgfmd, dnsproxy, wad, httpsd, dhcps, dhcpc, sslvpn). Always ends with level 0, debug disable and reset.

### `packet_capture`
`diagnose sniffer packet <intf> '<filter>' <verbose> <count> l` with a required BPF filter. Max 10 packets, 100 when CPU < 50 %; refused at ≥ 90 %. Verbose 1/4 by default; payload levels need `include_payload=true`. Stopped with Ctrl-C at the end; no capture file is stored.

### `debug_reset`
Stops any flow trace, clears debug and IKE filters, disables and resets debug. Works at any CPU.

## extended (8 tools)

### `device_info`

Live identity of the connected FortiGate: hostname, model, serial, FortiOS version and build, read from `/api/v2/monitor/system/status`. Use this instead of assuming a firmware version.

### `cmdb_schema`

Field schema of a CMDB endpoint as reported by the device (`GET /api/v2/cmdb/{path}?action=schema`): field names, types, options, sizes and defaults for its exact model and FortiOS version. Optional `field` returns one field's full schema; unknown field names return suggestions.

### `cmdb_patch`

Change only the given fields of one CMDB object. Reads the current object, rejects unknown fields, returns the diff (`dry_run=true`, default). With `dry_run=false` it writes only the changed fields, reads the object back and returns `verification` with `verified`, `not_applied` and `unexpected_changes`. Secret values are never shown and `<REDACTED>` cannot be written.

### `cmdb_exists`

Return `exists: true/false` for one CMDB object without returning its content (a 404 means false).

### `cmdb_move`

Reorder any ordered CMDB table (firewall policies, local-in policies, policy routes, SD-WAN rules) with `PUT ?action=move&before|after=<key>`. The key field is read from the schema. Dry run by default (shows current positions); with `dry_run=false` it moves and reads the order back to verify.

### `cmdb_clone`

Copy an object to a new key with `POST ?action=clone&nkey=<new_key>`. Checks that the source exists and the new key is free; dry run by default; verifies the copy exists after writing.

### `api_directory`

`GET /api/v2/{section}/{path}` for `cmdb`, `monitor`, `log` or `service`, to discover endpoints on the device when no dedicated tool exists. The response format depends on the FortiOS version.

### `log_search`

`POST /api/v2/log/{log_path}` with a JSON body for log endpoints that take one. For simple filtered reads use `log_get`. Output is redacted.

### `cmdb_get` / `cmdb_list` `params`

Optional JSON object of read options: `datasource`, `with_meta`, `with_contents_hash`, `skip`, `exclude-default-values`, `scope`, `key`, `pattern`, `format`, `filter`, `start`, `count`, `action` (`default`/`meta`/`schema`/`revision`). Other keys are refused.

## firewall (37 tools)

### `firewall_policy_list`

List IPv4 firewall policies with optional filters.

Returns policy ID, name, source/destination interfaces and zones,
source/destination addresses, services, action, and status.

### `firewall_policy_get`

Get a specific IPv4 firewall policy by its ID.

### `firewall_policy_create`

Create a new IPv4 firewall policy.

### `firewall_policy_update`

Update fields of an existing IPv4 firewall policy.

### `firewall_policy_delete`

Delete an IPv4 firewall policy.

### `firewall_policy_move`

Move a firewall policy (change its order in the policy table).

### `firewall_policy6_list`

List all IPv6 firewall policies.

### `firewall_address_list`

List all IPv4 firewall address objects.

### `firewall_address_get`

Get a specific IPv4 firewall address object.

### `firewall_address_create`

Create a new IPv4 firewall address object.

### `firewall_address_update`

Update an IPv4 firewall address object.

### `firewall_address_delete`

Delete an IPv4 firewall address object.

### `firewall_addrgrp_list`

List all IPv4 firewall address groups.

### `firewall_addrgrp_get`

Get a specific IPv4 address group and its members.

### `firewall_addrgrp_create`

Create a new IPv4 address group.

### `firewall_addrgrp_delete`

Delete an IPv4 address group.

### `firewall_service_list`

List all custom firewall service objects.

### `firewall_service_get`

Get a specific custom firewall service object.

### `firewall_service_create`

Create a new custom service object.

### `firewall_service_grp_list`

List all firewall service groups.

### `firewall_vip_list`

List all Virtual IP (DNAT) objects.

### `firewall_vip_get`

Get a specific Virtual IP (DNAT) object.

### `firewall_vip_create`

Create a new Virtual IP (DNAT/port-forward) object.

### `firewall_vip_delete`

Delete a Virtual IP object.

### `firewall_vipgrp_list`

List all VIP groups.

### `firewall_ippool_list`

List all IP pool (source NAT) objects.

### `firewall_ippool_create`

Create a new IP pool (source NAT pool) object.

### `firewall_schedule_one_time_list`

List all one-time schedules.

### `firewall_schedule_recurring_list`

List all recurring schedules.

### `firewall_central_snat_list`

List all central SNAT (outgoing NAT) rules.

### `firewall_ssl_ssh_profile_list`

List all SSL/SSH deep inspection profiles.

### `firewall_shaping_policy_list`

List all traffic shaping policies.

### `monitor_firewall_session_list`

List active firewall sessions with optional filters.

### `monitor_firewall_session_close`

Close a specific active firewall session.

### `monitor_firewall_policy_stats`

Get hit counts, bytes, and packet statistics per firewall policy.

### `monitor_firewall_address_dynamic`

Get resolved IPs for all dynamic/FQDN firewall address objects.

### `monitor_firewall_ip_list`

List active banned/exempt IPs in the firewall.

## generic (9 tools)

### `cmdb_list`

List all objects of a CMDB resource type.

Covers any GET on /api/v2/cmdb/{resource_path}.
Returns the full FortiOS JSON response including results array and metadata.

### `cmdb_get`

Get a single CMDB configuration object by its primary key.

Covers any GET on /api/v2/cmdb/{resource}/{key}.

### `cmdb_create`

Create a new CMDB configuration object (POST).

Covers any POST on /api/v2/cmdb/{resource_path}.

### `cmdb_update`

Update/replace a CMDB configuration object (PUT).

Covers any PUT on /api/v2/cmdb/{resource_path}/{key}.

### `cmdb_delete`

Delete a CMDB configuration object.

Covers any DELETE on /api/v2/cmdb/{resource_path}/{key}.

### `monitor_get`

Retrieve real-time operational data from any monitor endpoint.

Covers any GET on /api/v2/monitor/{monitor_path}.

### `monitor_action`

Trigger a monitor action (POST) on any monitor endpoint.

Covers any POST on /api/v2/monitor/{monitor_path}.

### `log_get`

Retrieve log entries from disk, memory, FortiAnalyzer, or FortiCloud.

Covers any GET on /api/v2/log/{log_path}.

### `service_call`

Call any FortiOS Service API endpoint.

Covers all GET/POST on /api/v2/service/{service_path}.

## log (16 tools)

### `log_query`

Query logs from FortiOS with flexible filtering.

Returns log entries from the specified backend and type.
Results include timestamps, sources, destinations, actions, and UTM verdicts.

### `log_traffic_forward`

Query forward traffic logs with optional per-field filters.

### `log_traffic_local`

Query local traffic logs (traffic to/from the FortiGate itself).

### `log_event_system`

Query system event logs (admin logins, config changes, system alerts).

### `log_event_vpn`

Query VPN event logs (IPsec SA negotiations, SSL VPN logins/logouts).

### `log_event_user`

Query user authentication event logs.

### `log_virus`

Query antivirus threat logs.

### `log_webfilter`

Query web filter (URL category/block) logs.

### `log_ips_attack`

Query IPS intrusion detection/prevention attack logs.

### `log_app_ctrl`

Query Application Control logs.

### `log_dns`

Query DNS filter logs.

### `log_disk_filter_get`

Get the disk log filter settings (which log types are enabled).

### `log_disk_setting_get`

Get the disk logging settings (log level, max log size, etc.).

### `log_memory_setting_get`

Get the memory logging settings.

### `log_fortianalyzer_setting_get`

Get FortiAnalyzer logging configuration (server, port, status).

### `log_fortianalyzer_setting_update`

Update FortiAnalyzer logging settings.

## monitor (21 tools)

### `monitor_network_arp_list`

Get the ARP table (IP-to-MAC address mappings).

### `monitor_network_lldp_neighbors`

Get LLDP neighbor information discovered on all interfaces.

### `monitor_interface_dhcp_status`

Get DHCP lease status on an interface (client side).

### `monitor_fortiview_top_sources`

Get FortiView top sources (most active source IPs by session count).

### `monitor_fortiview_top_destinations`

Get FortiView top destinations (most accessed destination IPs).

### `monitor_fortiview_top_applications`

Get FortiView top applications by bandwidth or session count.

### `monitor_fortiview_top_threat_map`

Get FortiView threat map data (geo-blocking source countries).

### `monitor_license_status`

Get FortiGuard license and subscription status for all services.

### `monitor_license_forticare_resellers`

Get FortiCare reseller and support contract information.

### `monitor_endpoint_summary`

Get endpoint control (FortiClient) summary statistics.

### `monitor_endpoint_record_list`

List registered endpoint (FortiClient) records.

### `monitor_ips_anomaly`

Get IPS anomaly detection statistics.

### `monitor_utm_app_categories`

Get UTM application category statistics.

### `monitor_switch_controller_managed_switch`

Get status of all FortiSwitch managed switches.

### `monitor_switch_controller_port_stats`

Get per-port traffic statistics for managed FortiSwitch devices.

### `monitor_security_rating_summary`

Get the Security Rating summary score and findings.

### `monitor_system_config_backup`

Trigger a configuration backup and get the backup data (base64-encoded).

### `monitor_system_process_list`

List running FortiOS processes with CPU and memory usage.

### `monitor_interface_stats`

Get real-time interface traffic statistics (bytes in/out, errors, drops).

### `monitor_network_ping`

Ping a remote host from the FortiGate device.

### `monitor_geoip_lookup`

Look up the geographic location (country, coordinates) of an IP address.

## router (24 tools)

### `router_static_list`

List all IPv4 static routes.

### `router_static_get`

Get a specific static route by sequence number.

### `router_static_create`

Create a new static route.

### `router_static_update`

Update an existing static route.

### `router_static_delete`

Delete a static route.

### `router_static6_list`

List all IPv6 static routes.

### `router_policy_list`

List all policy-based routing rules.

### `router_ospf_get`

Get OSPF routing configuration (areas, networks, neighbors, redistribute).

### `router_ospf6_get`

Get OSPFv3 (IPv6) routing configuration.

### `router_bgp_get`

Get BGP routing configuration (ASN, peers, networks, redistribute).

### `router_bgp_update`

Update BGP global configuration (AS number, router ID).

### `router_rip_get`

Get RIPv1/v2 routing configuration.

### `router_prefix_list_list`

List all IPv4 prefix lists (used in route filtering).

### `router_route_map_list`

List all route-maps (used for route filtering and attribute modification).

### `router_community_list_list`

List all BGP community lists.

### `router_access_list_list`

List all router access lists (ACL for routing).

### `router_sdwan_get`

Get the SD-WAN (virtual-WAN) configuration.

### `monitor_router_ipv4`

Get the active IPv4 routing table (all routes in the FIB).

### `monitor_router_ipv6`

Get the active IPv6 routing table.

### `monitor_router_lookup`

Perform a route lookup — find the best route for a destination IP.

### `monitor_router_lookup6`

Perform an IPv6 route lookup.

### `monitor_router_statistics`

Get routing protocol statistics (BGP, OSPF, RIP adjacencies/neighbors).

### `monitor_sdwan_health_check`

Get SD-WAN performance SLA health check results.

### `monitor_sdwan_members`

Get SD-WAN member interface status and bandwidth usage.

## security (35 tools)

### `ips_sensor_list`

List all IPS sensor profiles.

### `ips_sensor_get`

Get a specific IPS sensor profile.

### `ips_sensor_create`

Create a new IPS sensor profile.

### `ips_sensor_delete`

Delete an IPS sensor profile.

### `ips_custom_list`

List all custom IPS signatures.

### `antivirus_profile_list`

List all antivirus profiles.

### `antivirus_profile_get`

Get a specific antivirus profile.

### `antivirus_profile_create`

Create a new antivirus profile.

### `antivirus_settings_get`

Get antivirus engine settings (scan cache, exclusions).

### `webfilter_profile_list`

List all web filter profiles.

### `webfilter_profile_get`

Get a specific web filter profile.

### `webfilter_urlfilter_list`

List all URL filter tables (custom URL block/allow lists).

### `webfilter_override_list`

List all web filter category override rules.

### `webfilter_content_list`

List all web content filter (keyword) tables.

### `application_list_profiles`

List all Application Control profiles.

### `application_list_get`

Get a specific Application Control profile.

### `application_group_list`

List all application groups.

### `dlp_sensor_list`

List all DLP sensors.

### `dlp_dictionary_list`

List all DLP data dictionaries.

### `dlp_filepattern_list`

List all DLP file pattern tables.

### `emailfilter_profile_list`

List all email filter profiles.

### `emailfilter_bwl_list`

List email filter block/allow lists.

### `dnsfilter_profile_list`

List all DNS filter profiles.

### `dnsfilter_domain_filter_list`

List DNS domain filter tables (custom domain block/allow).

### `file_filter_profile_list`

List all file filter profiles.

### `icap_server_list`

List all ICAP server configurations.

### `icap_profile_list`

List all ICAP profiles.

### `ssh_filter_profile_list`

List all SSH filter profiles.

### `waf_profile_list`

List all WAF profiles.

### `waf_signature_list`

List all WAF signature configurations.

### `voip_profile_list`

List all VoIP (SIP/SCCP) inspection profiles.

### `virtual_patch_profile_list`

List all Virtual Patch profiles (inline IPS pre-patching).

### `automation_setting_get`

Get global automation settings.

### `ztna_server_list`

List all ZTNA access proxy (application gateway) servers.

### `ztna_tag_policy_list`

List all ZTNA EMS tag (posture check) policies.

## system (33 tools)

### `system_status`

Get the FortiOS system status (firmware version, hostname, serial number,
uptime, HA state, etc.).

### `system_resource_usage`

Get real-time resource usage: CPU, memory, disk, sessions.

### `system_performance_status`

Get performance statistics (CPU usage per core, memory, network throughput).

### `system_ha_status`

Get High Availability (HA) cluster status.

### `system_firmware_list`

List available firmware versions for upgrade.

### `system_time_get`

Get the current system time and timezone.

### `system_global_get`

Get FortiOS global settings (hostname, admin timeout, language, etc.).

### `system_global_update`

Update FortiOS global settings (partial update — only specified fields change).

### `system_interface_list`

List all network interfaces (physical, VLAN, loopback, aggregate, tunnel).

### `system_interface_get`

Get the configuration of a specific interface.

### `system_interface_create`

Create a new network interface.

### `system_interface_update`

Update an existing network interface (only specified fields are changed).

### `system_interface_delete`

Delete a network interface.

### `system_dns_get`

Get DNS server configuration (primary, secondary, search domains).

### `system_dns_update`

Update DNS configuration.

### `system_ntp_get`

Get NTP synchronization configuration.

### `system_ntp_update`

Update NTP configuration.

### `system_admin_list`

List all administrator accounts.

### `system_admin_get`

Get a specific administrator account configuration.

### `system_admin_create`

Create a new administrator account.

### `system_admin_delete`

Delete an administrator account.

### `system_dhcp_server_list`

List all DHCP server instances.

### `system_dhcp_server_get`

Get a specific DHCP server configuration.

### `system_dhcp_server_create`

Create a new DHCP server.

### `system_snmp_sysinfo_get`

Get SNMP system info (contact, location, description, trap thresholds).

### `system_snmp_community_list`

List SNMP v1/v2c communities.

### `system_snmp_user_list`

List SNMPv3 users.

### `system_fortiguard_status`

Get FortiGuard service registration and update status.

### `system_autoupdate_schedule_get`

Get the FortiGuard auto-update schedule.

### `certificate_local_list`

List local (device) certificates.

### `certificate_ca_list`

List trusted CA certificates.

### `system_vdom_list`

List all configured VDOMs.

### `log_syslogd_get`

Get the primary Syslog server configuration.

## user (19 tools)

### `user_local_list`

List all local user accounts.

### `user_local_get`

Get a specific local user account.

### `user_local_create`

Create a new local user account.

### `user_local_update`

Update a local user account.

### `user_local_delete`

Delete a local user account.

### `user_group_list`

List all user groups.

### `user_group_get`

Get a specific user group and its members.

### `user_group_create`

Create a new user group.

### `user_group_delete`

Delete a user group.

### `user_radius_list`

List all RADIUS authentication server configurations.

### `user_radius_get`

Get a specific RADIUS server configuration.

### `user_radius_create`

Create a new RADIUS server configuration.

### `user_ldap_list`

List all LDAP authentication server configurations.

### `user_ldap_create`

Create a new LDAP server configuration.

### `user_tacacs_list`

List all TACACS+ authentication server configurations.

### `user_saml_list`

List all SAML identity provider configurations.

### `monitor_user_firewall`

List authenticated firewall users and their session information.

### `monitor_user_fortitoken_list`

List FortiToken hardware/software tokens and their status.

### `monitor_user_disconnect`

Disconnect an authenticated firewall user session.

## vpn (26 tools)

### `vpn_ipsec_phase1_list`

List all IPsec VPN Phase 1 (IKE gateway) interfaces.

### `vpn_ipsec_phase1_get`

Get a specific IPsec Phase 1 interface configuration.

### `vpn_ipsec_phase1_create`

Create a new IPsec VPN Phase 1 interface (IKEv1/IKEv2 gateway).

### `vpn_ipsec_phase1_update`

Update an existing IPsec Phase 1 interface.

### `vpn_ipsec_phase1_delete`

Delete an IPsec Phase 1 tunnel interface.

### `vpn_ipsec_phase2_list`

List all IPsec VPN Phase 2 (SA / child SA) selectors.

### `vpn_ipsec_phase2_get`

Get a specific IPsec Phase 2 selector configuration.

### `vpn_ipsec_phase2_create`

Create a new IPsec VPN Phase 2 selector.

### `vpn_ipsec_phase2_delete`

Delete an IPsec Phase 2 selector.

### `vpn_ssl_settings_get`

Get SSL VPN global settings (port, certificates, idle timeout, etc.).

### `vpn_ssl_settings_update`

Update SSL VPN global settings.

### `vpn_ssl_portal_list`

List all SSL VPN portals.

### `vpn_ssl_portal_get`

Get a specific SSL VPN portal configuration.

### `vpn_ssl_portal_create`

Create a new SSL VPN portal.

### `vpn_ssl_portal_delete`

Delete an SSL VPN portal.

### `vpn_ssl_web_host_check_software_list`

List SSL VPN host check software (endpoint compliance) rules.

### `vpn_certificate_ca_list`

List all VPN CA certificates.

### `vpn_certificate_local_list`

List all VPN local (device) certificates.

### `vpn_certificate_remote_list`

List all remote (peer) VPN certificates.

### `vpn_certificate_ocsp_server_list`

List OCSP server configurations for certificate revocation checking.

### `monitor_vpn_ipsec`

Get status of all IPsec VPN tunnels (up/down, bytes transferred, SAs).

### `monitor_vpn_ipsec_tunnel_up`

Bring up (activate) an IPsec VPN tunnel.

### `monitor_vpn_ipsec_tunnel_down`

Bring down (deactivate) an IPsec VPN tunnel.

### `monitor_vpn_ssl_list`

List active SSL VPN sessions.

### `monitor_vpn_ssl_delete_user`

Terminate (disconnect) an active SSL VPN user session.

### `monitor_vpn_certificate_valid`

Check validity status of all VPN-related certificates.

## wireless (20 tools)

### `wifi_wtp_profile_list`

List all WTP (Wireless Termination Point / AP) profiles.

### `wifi_wtp_profile_get`

Get a specific AP (WTP) profile configuration.

### `wifi_wtp_list`

List all registered WTPs (Access Points) with their configuration.

### `wifi_wtp_get`

Get configuration for a specific WTP (Access Point).

### `wifi_wtp_deauthorize`

Deauthorize (remove) a WTP (Access Point) from the controller.

### `wifi_vap_list`

List all VAPs (Virtual APs / SSIDs).

### `wifi_vap_get`

Get a specific VAP (SSID) configuration.

### `wifi_vap_create`

Create a new VAP (SSID) wireless network.

### `wifi_vap_delete`

Delete a VAP (SSID) wireless network.

### `wifi_vap_group_list`

List all VAP groups (SSID bundles).

### `wifi_controller_setting_get`

Get wireless controller global settings.

### `wifi_qos_profile_list`

List all wireless QoS profiles.

### `wifi_rf_analysis_get`

Get wireless RF analysis settings.

### `wifi_hotspot20_profile_list`

List all Hotspot 2.0 (Passpoint) profiles.

### `monitor_wifi_managed_ap`

Get detailed status of all managed Access Points (online/offline, channel, clients).

### `monitor_wifi_client_list`

List all connected WiFi clients with their associated AP and signal strength.

### `monitor_wifi_rogue_ap`

Get list of detected rogue (unauthorized) Access Points.

### `monitor_wifi_spectrum_analysis`

Get RF spectrum analysis data from APs that support it.

### `monitor_wifi_ap_status`

Get operational status (up/down, channel, TX power) for APs.

### `monitor_wifi_interfering_ap`

Get list of interfering (neighbor) Access Points detected on RF scan.
