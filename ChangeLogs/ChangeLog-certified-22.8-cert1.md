
## Change Log for Release asterisk-certified-22.8-cert1

### Links:

 - [Full ChangeLog](https://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-certified-22.8-cert1.html)  
 - [GitHub Diff](https://github.com/asterisk/asterisk/compare/certified-20.7-cert9...certified-22.8-cert1)  
 - [Tarball](https://downloads.asterisk.org/pub/telephony/certified-asterisk/asterisk-certified-22.8-cert1.tar.gz)  
 - [Downloads](https://downloads.asterisk.org/pub/telephony/certified-asterisk)  

### Summary:

- Commits: 853
- Commit Authors: 110
- Issues Resolved: 590
- Security Advisories Resolved: 13
  - [GHSA-2grh-7mhv-fcfw](https://github.com/asterisk/asterisk/security/advisories/GHSA-2grh-7mhv-fcfw): Using malformed From header can forge identity with ";" or NULL in name portion
  - [GHSA-33x6-fj46-6rfh](https://github.com/asterisk/asterisk/security/advisories/GHSA-33x6-fj46-6rfh): Path traversal via AMI ListCategories allows access to outside files
  - [GHSA-64qc-9x89-rx5j](https://github.com/asterisk/asterisk/security/advisories/GHSA-64qc-9x89-rx5j): A specifically malformed Authorization header in an incoming SIP request can cause Asterisk to crash
  - [GHSA-85x7-54wr-vh42](https://github.com/asterisk/asterisk/security/advisories/GHSA-85x7-54wr-vh42): Asterisk xml.c uses unsafe XML_PARSE_NOENT leading to potential XXE Injection
  - [GHSA-c4cg-9275-6w44](https://github.com/asterisk/asterisk/security/advisories/GHSA-c4cg-9275-6w44): Write=originate, is sufficient permissions for code execution / System() dialplan
  - [GHSA-c7p6-7mvq-8jq2](https://github.com/asterisk/asterisk/security/advisories/GHSA-c7p6-7mvq-8jq2): cli_permissions.conf: deny option does not work for disallowing shell commands
  - [GHSA-hxj9-xwr8-w8pq](https://github.com/asterisk/asterisk/security/advisories/GHSA-hxj9-xwr8-w8pq): Asterisk susceptible to Denial of Service via DTLS Hello packets during call initiation
  - [GHSA-mrq5-74j5-f5cr](https://github.com/asterisk/asterisk/security/advisories/GHSA-mrq5-74j5-f5cr): Remote DoS and possible RCE in asterisk/res/res_stir_shaken/verification.c
  - [GHSA-rvch-3jmx-3jf3](https://github.com/asterisk/asterisk/security/advisories/GHSA-rvch-3jmx-3jf3): ast_coredumper running as root sources ast_debug_tools.conf from /etc/asterisk; potentially leading to privilege escalation
  - [GHSA-v428-g3cw-7hv9](https://github.com/asterisk/asterisk/security/advisories/GHSA-v428-g3cw-7hv9): A malformed Contact or Record-Route URI in an incoming SIP request can cause Asterisk to crash when res_resolver_unbound is used
  - [GHSA-v6hp-wh3r-cwxh](https://github.com/asterisk/asterisk/security/advisories/GHSA-v6hp-wh3r-cwxh): The Asterisk embedded web server's /httpstatus page echos user supplied values(cookie and query string) without sanitization
  - [GHSA-v9q8-9j8m-5xwp](https://github.com/asterisk/asterisk/security/advisories/GHSA-v9q8-9j8m-5xwp): Uncontrolled Search-Path Element in safe_asterisk script may allow local privilege escalation.
  - [GHSA-xpc6-x892-v83c](https://github.com/asterisk/asterisk/security/advisories/GHSA-xpc6-x892-v83c): ast_coredumper runs as root, and writes gdb init file to world writeable folder; leading to potential privilege escalation 

### User Notes:

- #### ast_coredumper: check ast_debug_tools.conf permissions
  ast_debug_tools.conf must be owned by root and not be
  writable by other users or groups to be used by ast_coredumper or
  by ast_logescalator or ast_loggrabber when run as root.

- #### chan_websocket.conf.sample: Fix category name.
  The category name in the chan_websocket.conf.sample file was
  incorrect.  It should be "global" instead of "general".

- #### cli.c: Allow 'channel request hangup' to accept patterns.
  The 'channel request hangup' CLI command now accepts
  multiple channel names, POSIX Extended Regular Expressions, glob-like
  patterns, or a combination of all of them. See the CLI command 'core
  show help channel request hangup' for full details.

- #### res_sorcery_memory_cache: Reduce cache lock time for sorcery memory cache populate command
  The AMI command sorcery memory cache populate will now
  return an error if there is an internal error performing the populate.
  The CLI command will display an error in this case as well.

- #### res_geolocation:  Fix multiple issues with XML generation.
  Geolocation: Two new optional profile parameters have been added.
  * `pidf_element_id` which sets the value of the `id` attribute on the top-level
    PIDF-LO `device`, `person` or `tuple` elements.
  * `device_id` which sets the content of the `<deviceID>` element.
  Both parameters can include channel variables.

- #### res_pjsip_messaging: Add support for following 3xx redirects
  A new pjsip endpoint option follow_redirect_methods was added.
  This option is a comma-delimited, case-insensitive list of SIP methods
  for which SIP 3XX redirect responses are followed. An alembic upgrade
  script has been added for adding this new option to the Asterisk
  database.

- #### taskprocessors: Improve logging and add new cli options
  New CLI command has been added -
  core show taskprocessor name <taskprocessor-name>

- #### ccss:  Add option to ccss.conf to globally disable it.
  A new "enabled" parameter has been added to ccss.conf.  It defaults
  to "yes" to preserve backwards compatibility but CCSS is rarely used so
  setting "enabled = no" in the "general" section can save some unneeded channel
  locking operations and log message spam.  Disabling ccss will also prevent
  the func_callcompletion and chan_dahdi modules from loading.

- #### Makefile: Add module-list-* targets.
  Try "make module-list-deprecated" to see what modules
  are on their way out the door.

- #### app_mixmonitor: Add 's' (skip) option to delay recording.
  This change introduces a new 's(<seconds>)' (skip) option to the MixMonitor
  application. Example:
    MixMonitor(${UNIQUEID}.wav,s(3))
  This skips recording for the first 3 seconds before writing audio to the file.
  Existing MixMonitor behavior remains unchanged when the 's' option is not used.

- #### app_queue.c: Only announce to head caller if announce_to_first_user
  When announce_to_first_user is false, no announcements are played to the head caller

- #### res_stir_shaken: Add STIR_SHAKEN_ATTESTATION dialplan function.
  The STIR_SHAKEN_ATTESTATION dialplan function has been added
  which will allow suppressing attestation on a call-by-call basis
  regardless of the profile attached to the outgoing endpoint.

- #### func_channel: Allow R/W of ADSI CPE capability setting.
  CHANNEL(adsicpe) can now be read or written to change
  the channels' ADSI CPE capability setting.

- #### func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()
  Added a new option to HANGUPCAUSE to access additional
  information about hangup reason. Reason headers from pjsip
  could be read using 'tech_extended' cause type.

- #### func_math: Add DIGIT_SUM function.
  The DIGIT_SUM function can be used to return the digit sum of
  a number.

- #### app_sf: Add post-digit timer option to ReceiveSF.
  The 't' option for ReceiveSF now allows for a timer since
  the last digit received, in addition to the number-wide timeout.

- #### app_dial: Allow fractional seconds for dial timeouts.
  The answer and progress dial timeouts now have millisecond
  precision, instead of having to be whole numbers.

- #### chan_dahdi: Add DAHDI_CHANNEL function.
  The DAHDI_CHANNEL function allows for getting/setting
  certain properties about DAHDI channels from the dialplan.

- #### app_queue.c: Add new global 'log_unpause_on_reason_change'
  Add new global option 'log_unpause_on_reason_change' that
  is default disabled. When enabled cause addition of UNPAUSE event on
  every re-PAUSE with reason changed.

- #### pbx_builtins: Allow custom tone for WaitExten.
  The tone used while waiting for digits in WaitExten
  can now be overridden by specifying an argument for the 'd'
  option.

- #### res_tonedetect: Add option for TONE_DETECT detection to auto stop.
  The 'e' option for TONE_DETECT now allows detection to
  be disabled automatically once the desired number of matches have
  been fulfilled, which can help prevent race conditions in the
  dialplan, since TONE_DETECT does not need to be disabled after
  a hit.

- #### sorcery: Prevent duplicate objects and ensure missing objects are created on update
  Users relying on Sorcery multiple writable backends configurations
  (e.g., astdb + realtime) may now enable update_or_create_on_update_miss = yes
  in sorcery.conf to ensure missing objects are recreated after temporary backend
  failures. Default behavior remains unchanged unless explicitly enabled.

- #### chan_websocket: Allow additional URI parameters to be added to the outgoing URI.
  A new WebSocket channel driver option `v` has been added to the
  Dial application that allows you to specify additional URI parameters on
  outgoing connections. Run `core show application Dial` from the Asterisk CLI
  to see how to use it.

- #### app_chanspy: Add option to not automatically answer channel.
  ChanSpy and ExtenSpy can now be configured to not
  automatically answer the channel by using the 'N' option.

- #### cel: Add STREAM_BEGIN, STREAM_END and DTMF event types.
  Enabling the tracking of the
  STREAM_BEGIN and the STREAM_END event
  types in cel.conf will log media files and
  music on hold played to each channel.
  The STREAM_BEGIN event's extra field will
  contain a JSON with the file details (path,
  format and language), or the class name, in
  case of music on hold is played. The DTMF
  event's extra field will contain a JSON with
  the digit and the duration in milliseconds.

- #### res_srtp: Add menuselect options to enable AES_192, AES_256 and AES_GCM
  Options are now available in the menuselect "Resource Modules"
  category that allow you to enable the AES_192, AES_256 and AES_GCM
  cipher suites in res_srtp. Of course, libsrtp and OpenSSL must support
  them but modern versions do.  Previously, the only way to enable them was
  to set the CFLAGS environment variable when running ./configure.
  The default setting is to disable them preserving existing behavior.

- #### cdr: add CANCEL dispostion in CDR
  A new CDR option "canceldispositionenabled" has been added
  that when set to true, the NO ANSWER disposition will be split into
  two dispositions: CANCEL and NO ANSWER. The default value is 'no'

- #### func_curl: Allow auth methods to be set.
  The httpauth field in CURLOPT now allows the authentication
  methods to be set.

- #### Media over Websocket Channel Driver
  A new channel driver "chan_websocket" is now available. It can
  exchange media over both inbound and outbound websockets and will both frame
  and re-time the media it receives.
  See http://s.asterisk.net/mow for more information.
  The ARI channels/externalMedia API now includes support for the
- #### res_stir_shaken.so: Handle X5U certificate chains.
  The STIR/SHAKEN verification process will now load a full
  certificate chain retrieved via the X5U URL instead of loading only
  the end user cert.

- #### res_stir_shaken: Add "ignore_sip_date_header" config option.
  A new STIR/SHAKEN verification option "ignore_sip_date_header" has
  been added that when set to true, will cause the verification process to
  not consider a missing or invalid SIP "Date" header to be a failure.  This
  will make the IAT the sole "truth" for Date in the verification process.
  The option can be set in the "verification" and "profile" sections of
  stir_shaken.conf.
  Also fixed a bug in the port match logic.
  Resolves: #1251
  Resolves: #1271

- #### app_record: Add RECORDING_INFO function.
  The RECORDING_INFO function can now be used
  to retrieve the duration of a recording.

- #### app_queue: queue rules – Add support for QUEUE_RAISE_PENALTY=rN to raise penalties only for members within min/max range
  This change introduces QUEUE_RAISE_PENALTY=rN, allowing selective penalty raises
  only for members whose current penalty is within the [min_penalty, max_penalty] range.
  Members with lower or higher penalties are unaffected.
  This behavior is backward-compatible with existing queue rule configurations.

- #### res_odbc: cache_size option to limit the cached connections.
  New cache_size option for res_odbc to on a per class basis limit the
  number of cached connections. Please reference the sample configuration
  for details.

- #### res_odbc: cache_type option for res_odbc.
  When using res_odbc it should be noted that back-end
  connections to the underlying database can now be configured to re-use
  the cached connections in a round-robin manner rather than repeatedly
  re-using the same connection.  This helps to keep connections alive, and
  to purge dead connections from the system, thus more dynamically
  adjusting to actual load.  The downside is that one could keep too many
  connections active for a longer time resulting in resource also begin
  consumed on the database side.

- #### ARI Outbound Websockets
  Asterisk can now establish websocket sessions _to_ your ARI applications
  as well as accepting websocket sessions _from_ them.
  Full details: http://s.asterisk.net/ari-outbound-ws

- #### res_websocket_client: Create common utilities for websocket clients.
  A new module "res_websocket_client" and config file
  "websocket_client.conf" have been added to support several upcoming new
  capabilities that need common websocket client configuration.

- #### asterisk.c: Add option to restrict shell access from remote consoles.
  A new asterisk.conf option 'disable_remote_console_shell' has
  been added that, when set, will prevent remote consoles from executing
  shell commands using the '!' prefix.
  Resolves: #GHSA-c7p6-7mvq-8jq2

- #### sig_analog: Add Call Waiting Deluxe support.
  Call Waiting Deluxe can now be enabled for FXS channels
  by enabling its corresponding option.

- #### stasis/control.c: Set Hangup Cause to No Answer on Dial timeout
  A Dial timeout on POST /channels/{channelId}/dial will now result in a
  CANCEL and ChannelDestroyed with cause 19 / User alerting, no answer.  Previously
  no explicit cause was set, resulting in a cause of 16 / Normal Call Clearing.

- #### contrib: Add systemd service and timer files for malloc trim.
  Service and timer files for systemd have been added to the
  contrib/systemd/ directory. If you are experiencing memory issues,
  install these files to have "malloc trim" periodically run on the
  system.

- #### Add log-caller-id-name option to log Caller ID Name in queue log
  This patch adds a global configuration option, log-caller-id-name, to queues.conf
  to control whether the Caller ID name is logged as parameter 4 when a call enters a queue.
  When log-caller-id-name=yes, the Caller ID name is included in the queue log,
  Any '|' characters in the caller ID name will be replaced with '_'.
  (provided it’s allowed by the existing log_restricted_caller_id rules).
  When log-caller-id-name=no (the default), the Caller ID name is omitted.

- #### asterisk.c: Add "pre-init" and "pre-module" capability to cli.conf.
  In cli.conf, you can now define startup commands that run before
  core initialization and before module initialization.

- #### audiosocket: added support for DTMF frames
  The AudioSocket protocol now forwards DTMF frames with
  payload type 0x03. The payload is a 1-byte ascii representing the DTMF
  digit (0-9,*,#...).

- #### ari/pjsip: Make it possible to control transfers through ARI
  Call transfers on the PJSIP channel can now be controlled by
  ARI. This can be enabled by using the PJSIP_TRANSFER_HANDLING(ari-only)
  dialplan function.

- #### sig_analog: Add Last Number Redial feature.
  Users can now redial the last number
  called if the lastnumredial setting is set to yes.
  Resolves: #437

- #### Add SHA-256 and SHA-512-256 as authentication digest algorithms
  The SHA-256 and SHA-512-256 algorithms are now available
  for authentication as both a UAS and a UAC.

- #### Upgrade bundled pjproject to 2.15.1 Resolves: asterisk#1016
  Bundled pjproject has been upgraded to 2.15.1. For more
  information visit pjproject Github page: https://github.com/pjsip/pjproject/releases/tag/2.15.1

- #### res_pjsip: Add new AOR option "qualify_2xx_only"
  The pjsip.conf AOR section now has a "qualify_2xx_only"
  option that can be set so that only 2XX responses to OPTIONS requests
  used to qualify a contact will mark the contact as available.

- #### app_queue: allow dynamically adding a queue member in paused state.
  use the p option of AddQueueMember() for paused member state.
  Optionally, use the r(reason) option to specify a custom reason for the pause.

- #### manager.c: Add Processed Call Count to CoreStatus output
  The current processed call count is now returned as CoreProcessedCalls from the
  CoreStatus AMI Action.

- #### func_curl.c: Add additional CURL options for SSL requests
  The following new configuration options are now available
  in the res_curl.conf file, and the CURL() function: 'ssl_verifyhost'
  (CURLOPT_SSL_VERIFYHOST), 'ssl_cainfo' (CURLOPT_CAINFO), 'ssl_capath'
  (CURLOPT_CAPATH), 'ssl_cert' (CURLOPT_SSLCERT), 'ssl_certtype'
  (CURLOPT_SSLCERTTYPE), 'ssl_key' (CURLOPT_SSLKEY), 'ssl_keytype',
  (CURLOPT_SSLKEYTYPE) and 'ssl_keypasswd' (CURLOPT_KEYPASSWD). See the
  libcurl documentation for more details.

- #### res_stir_shaken: Allow sending Identity headers for unknown TNs
  You can now set the "unknown_tn_attest_level" option
  in the attestation and/or profile objects in stir_shaken.conf to
  enable sending Identity headers for callerid TNs not explicitly
  configured.

- #### manager.c: Restrict ListCategories to the configuration directory.
  The ListCategories AMI action now restricts files to the
  configured configuration directory.

- #### res_pjsip: Add new endpoint option "suppress_moh_on_sendonly"
  The new "suppress_moh_on_sendonly" endpoint option
  can be used to prevent playing MOH back to a caller if the remote
  end sends "sendonly" or "inactive" (hold) to Asterisk in an SDP.

- #### app_mixmonitor: Add 'D' option for dual-channel audio.
  The MixMonitor application now has a new 'D' option which
  interleaves the recorded audio in the output frames. This allows for
  stereo recording output with one channel being the transmitted audio and
  the other being the received audio. The 't' and 't' options are
  compatible with this.

- #### manager.c: Restrict ModuleLoad to the configured modules directory.
  The ModuleLoad AMI action now restricts modules to the
  configured modules directory.

- #### manager: Enhance event filtering for performance
  You can now perform more granular filtering on events
  in manager.conf using expressions like
  `eventfilter(name(Newchannel),header(Channel),method(starts_with)) = PJSIP/`
  This is much more efficient than
  `eventfilter = Event: Newchannel.*Channel: PJSIP/`
  Full syntax guide is in configs/samples/manager.conf.sample.

- #### db.c: Remove limit on family/key length
  The `ast_db_*()` APIs have had the 253 byte limit on
  "/family/key" removed and will now accept families and keys with a
  total length of up to SQLITE_MAX_LENGTH (currently 1e9!).  This
  affects the `DB*` dialplan applications, dialplan functions,
  manager actions and `databse` CLI commands.  Since the
  media_cache also uses the `ast_db_*()` APIs, you can now store
  resources with URIs longer than 253 bytes.

- #### res_pjsip_notify: add dialplan application
  A new dialplan application PJSIPNotify is now available
  which can send SIP NOTIFY requests from the dialplan.
  The pjsip send notify CLI command has also been enhanced to allow
  sending NOTIFY messages to a specific channel. Syntax:
  pjsip send notify <option> channel <channel>

- #### channel: Add multi-tenant identifier.
  tenantid has been added to channels. It can be read in
  dialplan via CHANNEL(tenantid), and it can be set using
  Set(CHANNEL(tenantid)=My tenant ID). In pjsip.conf, it is recommended to
  use the new tenantid option for pjsip endpoints (e.g., tenantid=My
  tenant ID) so that it will show up in Newchannel events. You can set it
  like any other channel variable using set_var in pjsip.conf as well, but
  note that this will NOT show up in Newchannel events. Tenant ID is also
  available in CDR and can be accessed with CDR(tenantid). The peer tenant
  ID can also be accessed with CDR(peertenantid). CEL includes tenant ID
  as well if it has been set.

- #### feat: ARI "ChannelToneDetected" event
  Setting the TONE_DETECT dialplan function on a channel
  in ARI will now cause a ChannelToneDetected ARI event to be raised
  when the specified tone is detected.

- #### res_pjsip_config_wizard.c: Refactor load process
  The res_pjsip_config_wizard.so module can now be reloaded.

- #### app_voicemail_odbc: Allow audio to be kept on disk
  This commit adds a new voicemail.conf option
  'odbc_audio_on_disk' which when set causes the ODBC variant of
  app_voicemail_odbc to leave the message and greeting audio files
  on disk and only store the message metadata in the database.
  Much more information can be found in the voicemail.conf.sample
  file.

- #### app_queue:  Add option to not log Restricted Caller ID to queue_log
  Add a Queue option log-restricted-caller-id to control whether the Restricted Caller ID
  will be stored in the queue log.
  If log-restricted-caller-id=no then the Caller ID will be stripped if the Caller ID is restricted.

- #### pbx.c: expand fields width of "core show hints"
  The fields width of "core show hints" were increased.
  The width of "extension" field to 30 characters and
  the width of the "device state id" field to 60 characters.

- #### rtp_engine: add support for multirate RFC2833 digits
  No change in configuration is required in order to enable this
  feature. Endpoints configured to use RFC2833 will automatically have this
  enabled. If the endpoint does not support this, it should not include it in
  the SDP offer/response.
  Resolves: #699

- #### res_pjsip_logger: Preserve logging state on reloads.
  Issuing "pjsip reload" will no longer disable
  logging if it was previously enabled from the CLI.

- #### loader.c: Allow dependent modules to be unloaded recursively.
  In certain circumstances, modules with dependency relations
  can have their dependents automatically recursively unloaded and loaded
  again using the "module refresh" CLI command or the ModuleLoad AMI command.

- #### tcptls/iostream:  Add support for setting SNI on client TLS connections
  Secure websocket client connections now send SNI in
  the TLS client hello.

- #### res_pjsip_endpoint_identifier_ip: Endpoint identifier request URI
  this new feature let users match endpoints based on the
  indound SIP requests' URI. To do so, add 'request_uri' to the
  endpoint's 'identify_by' option. The 'match_request_uri' option of
  the identify can be an exact match for the entire request uri, or a
  regular expression (between slashes). It's quite similar to the
  header identifer.
  Fixes: #599

- #### res_pjsip_refer.c: Allow GET_TRANSFERRER_DATA
  the GET_TRANSFERRER_DATA dialplan variable can now be used also in pjsip.

- #### manager.c: Add new parameter 'PreDialGoSub' to Originate AMI action
  When using the Originate AMI Action, we now can pass the PreDialGoSub parameter, instructing the asterisk to perform an subrouting at channel before call start. With this parameter an call initiated by AMI can request the channel to start the call automaticaly, adding a SIP header to using GoSUB, instructing to autoanswer the channel, and proceeding the outbuound extension executing. Exemple of an context to perform the previus indication:
  [addautoanswer]
  exten => _s,1,Set(PJSIP_HEADER(add,Call-Info)=answer-after=0)
  exten => _s,n,Set(PJSIP_HEADER(add,Alert-Info)=answer-after=0)
  exten => _s,n,Return()

- #### manager.c: Add CLI command to kick AMI sessions.
  The "manager kick session" CLI command now
  allows kicking a specified AMI session.

- #### chan_dahdi: Allow specifying waitfordialtone per call.
  "waitfordialtone" may now be specified for DAHDI
  trunk channels on a per-call basis using the CHANNEL function.

- #### Upgrade bundled pjproject to 2.14.1
  Bundled pjproject has been upgraded to 2.14.1. For more
  information visit pjproject Github page: https://github.com/pjsip/pjproject/releases/tag/2.14.1

- #### app_dial: Add dial time for progress/ringing.
  The timeout argument to Dial now allows
  specifying the maximum amount of time to dial if
  early media is not received.

- #### app_voicemail: Allow preventing mark messages as urgent.
  The leaveurgent mailbox option can now be used to
  control whether callers may leave messages marked as 'Urgent'.

- #### Stir/Shaken Refactor
  Asterisk's stir-shaken feature has been refactored to
  correct interoperability, RFC compliance, and performance issues.
  See https://docs.asterisk.org/Deployment/STIR-SHAKEN for more
  information.

- #### Upgrade bundled pjproject to 2.14.
  Bundled pjproject has been upgraded to 2.14. For more
  information on what all is included in this change, check out the
  pjproject Github page: https://github.com/pjsip/pjproject/releases

- #### app_speech_utils.c: Allow partial speech results.
  The SpeechBackground dialplan application now supports a 'p'
  option that will return partial results from speech engines that
  provide them when a timeout occurs.

- #### res_pjsip_outbound_registration.c: Add User-Agent header override
  PJSIP outbound registrations now support a per-registration
  User-Agent header

- #### app_chanspy: Add 'D' option for dual-channel audio
  The ChanSpy application now accepts the 'D' option which
  will interleave the spied audio within the outgoing frames. The
  purpose of this is to allow the audio to be read as a Dual channel
  stream with separate incoming and outgoing audio. Setting both the
  'o' option and the 'D' option and results in the 'D' option being
  ignored.

- #### app_voicemail_odbc: remove macrocontext from voicemail_messages table
  The fix requires removing the macrocontext column from the
  voicemail_messages table in the voicemail database via alembic upgrade.

- #### chan_dahdi: Allow MWI to be manually toggled on channels.
  The 'dahdi set mwi' now allows MWI on channels
  to be manually toggled if needed for troubleshooting.
  Resolves: #440

- #### app_dial: Add option "j" to preserve initial stream topology of caller
  The option "j" is now available for the Dial application which
  uses the initial stream topology of the caller to create the outgoing
  channels.

- #### logger: Add channel-based filtering.
  The console log can now be filtered by
  channels or groups of channels, using the
  logger filter CLI commands.

- #### chan_pjsip: Add PJSIPHangup dialplan app and manager action
  A new dialplan app PJSIPHangup and AMI action allows you
  to hang up an unanswered incoming PJSIP call with a specific SIP
  response code in the 400 -> 699 range.

- #### app_voicemail: Add AMI event for mailbox PIN changes.
  The VoicemailPasswordChange event is
  now emitted whenever a mailbox password is updated,
  containing the mailbox information and the new
  password.
  Resolves: #398

- #### res_speech: allow speech to translate input channel
  res_speech now supports translation of an input channel
  to a format supported by the speech provider, provided a translation
  path is available between the source format and provider capabilites.

- #### res_pjsip: Expanding PJSIP endpoint ID and relevant resource length to 255 characters
  With this update, the PJSIP realm lengths have been extended
  to support up to 255 characters.

- #### res_stasis: signal when new command is queued
  Call setup times should be significantly improved
  when using ARI.

- #### lock.c: Separate DETECT_DEADLOCKS from DEBUG_THREADS
  You no longer need to select DEBUG_THREADS to use
  DETECT_DEADLOCKS.  This removes a significant amount of overhead
  if you just want to detect possible deadlocks vs needing full
  lock tracing.

- #### file.c: Add ability to search custom dir for sounds
  A new option "sounds_search_custom_dir" has been added to
  asterisk.conf that allows asterisk to search
  AST_DATA_DIR/sounds/custom for sounds files before searching the
  standard AST_DATA_DIR/sounds/<lang> directory.

- #### make_buildopts_h, et. al.  Allow adding all cflags to buildopts.h
  The "Build Options" entry in the "core show settings"
  CLI command has been renamed to "ABI related Build Options" and
  a new entry named "All Build Options" has been added that shows
  both breaking and non-breaking options.

- #### chan_rtp: Implement RTP glue for UnicastRTP channels
  The dial string option 'g' was added to the UnicastRTP channel
  which enables RTP glue and therefore native RTP bridges with those
  channels.

- #### variables: Add additional variable dialplan functions.
  Four new dialplan functions have been added.
  GLOBAL_DELETE and DELETE have been added which allows
  the deletion of global and channel variables.
  GLOBAL_EXISTS and VARIABLE_EXISTS have been added
  which checks whether a global or channel variable has
  been set.

- #### sig_analog: Add Called Subscriber Held capability.
  Called Subscriber Held is now supported for analog
  FXS channels, using the calledsubscriberheld option. This allows
  a station  user to go on hook when receiving an incoming call
  and resume from another phone on the same line by going on hook,
  without disconnecting the call.

- #### res_pjsip_header_funcs: Make prefix argument optional.
  The prefix argument to PJSIP_HEADERS is now
  optional. If not specified, all header names will be
  returned.

- #### core/ari/pjsip: Add refer mechanism
  There is a new ARI endpoint `/endpoints/refer` for referring
  an endpoint to some URI or endpoint.

- #### chan_dahdi: Allow autoreoriginating after hangup.
  The autoreoriginate setting now allows for kewlstart FXS
  channels to automatically reoriginate and provide dial tone to the
  user again after all calls on the line have cleared. This saves users
  from having to manually hang up and pick up the receiver again before
  making another call.

- #### sig_analog: Allow three-way flash to time out to silence.
  The threewaysilenthold option now allows the three-way
  dial tone to time out to silence, rather than continuing forever.

- #### res_pjsip: Enable TLS v1.3 if present.
  res_pjsip now allows TLS v1.3 to be enabled if supported by
  the underlying PJSIP library. The bundled version of PJSIP supports
  TLS v1.3.

- #### app_queue: Add support for applying caller priority change immediately.
  The 'queue priority caller' CLI command and
  'QueueChangePriorityCaller' AMI action now have an 'immediate'
  argument which allows the caller priority change to be reflected
  immediately, causing the position of a caller to move within the
  queue depending on the priorities of the other callers.

- #### Adds manager actions to allow move/remove/forward individual messages in a particular mailbox folder. The forward command can be used to copy a message within a mailbox or to another mailbox. Also adds a VoicemailBoxSummarry, required to retrieve message ID's.
  The following manager actions have been added
  VoicemailBoxSummary - Generate message list for a given mailbox
  VoicemailRemove - Remove a message from a mailbox folder
  VoicemailMove - Move a message from one folder to another within a mailbox
  VoicemailForward - Copy a message from one folder in one mailbox
  to another folder in another or the same mailbox.

- #### app_voicemail: add CLI commands for message manipulation
  The following CLI commands have been added to app_voicemail
  voicemail show mailbox <mailbox> <context>
  Show contents of mailbox <mailbox>@<context>
  voicemail remove <mailbox> <context> <from_folder> <messageid>
  Remove message <messageid> from <from_folder> in mailbox <mailbox>@<context>
  voicemail move <mailbox> <context> <from_folder> <messageid> <to_folder>
  Move message <messageid> in mailbox <mailbox>&<context> from <from_folder> to <to_folder>
  voicemail forward <from_mailbox> <from_context> <from_folder> <messageid> <to_mailbox> <to_context> <to_folder>
  Forward message <messageid> in mailbox <mailbox>@<context> <from_folder> to
  mailbox <mailbox>@<context> <to_folder>

- #### sig_analog: Allow immediate fake ring to be suppressed.
  The immediatering option can now be set to no to suppress
  the fake audible ringback provided when immediate=yes on FXS channels.

- #### AMI: Add parking position parameter to Park action
  New ParkingSpace parameter has been added to AMI action Park.

- #### res_musiconhold: Add option to loop last file.
  The loop_last option in musiconhold.conf now
  allows the last file in the directory to be looped once reached.

- #### AMI: Add CoreShowChannelMap action.
  New AMI action CoreShowChannelMap has been added.

- #### sig_analog: Add fuller Caller ID support.
  Additional Caller ID properties are now supported on
  incoming calls to FXS stations, namely the
  redirecting reason and call qualifier.

- #### res_stasis.c: Add new type 'sdp_label' for bridge creation.
  When creating a bridge using the ARI the 'type' argument now
  accepts a new value 'sdp_label' which will configure the bridge to add
  labels for each stream in the SDP with the corresponding channel id.

- #### app_queue: Preserve reason for realtime queues
  Make paused reason in realtime queues persist an
  Asterisk restart. This was fixed for non-realtime
  queues in ASTERISK_25732.

- #### cel: add local optimization begin event (#54)
  The new AST_CEL_LOCAL_OPTIMIZE_BEGIN can be used
  by itself or in conert with the existing
  AST_CEL_LOCAL_OPTIMIZE to book-end local channel optimizaion.

- #### chan_dahdi: Add dialmode option for FXS lines.
  A "dialmode" option has been added which allows
  specifying, on a per-channel basis, what methods of
  subscriber dialing (pulse and/or tone) are permitted.
  Additionally, this can be changed on a channel
  at any point during a call using the CHANNEL
  function.


### Upgrade Notes:

- #### http.c: Change httpstatus to default disabled and sanitize output.
  To prevent possible security issues, the `/httpstatus` page
  served by the internal web server is now disabled by default.  To explicitly
  enable it, set `enable_status=yes` in http.conf.

- #### res_geolocation:  Fix multiple issues with XML generation.
  Geolocation: In order to correct bugs in both code and
  documentation, the following changes to the parameters for GML geolocation
  locations are now in effect:
  * The documented but unimplemented `crs` (coordinate reference system) element
    has been added to the location_info parameter that indicates whether the `2d`
    or `3d` reference system is to be used. If the crs isn't valid for the shape
    specified, an error will be generated. The default depends on the shape
    specified.
  * The Circle, Ellipse and ArcBand shapes MUST use a `2d` crs.  If crs isn't
    specified, it will default to `2d` for these shapes.
    The Sphere, Ellipsoid and Prism shapes MUST use a `3d` crs. If crs isn't
    specified, it will default to `3d` for these shapes.
    The Point and Polygon shapes may use either crs.  The default crs is `2d`
    however so if `3d` positions are used, the crs must be explicitly set to `3d`.
  * The `geoloc show gml_shape_defs` CLI command has been updated to show which
    coordinate reference systems are valid for each shape.
  * The `pos3d` element has been removed in favor of allowing the `pos` element
    to include altitude if the crs is `3d`.  The number of values in the `pos`
    element MUST be 2 if the crs is `2d` and 3 if the crs is `3d`.  An error
    will be generated for any other combination.
  * The angle unit-of-measure for shapes that use angles should now be included
    in the respective parameter.  The default is `degrees`. There were some
    inconsistent references to `orientation_uom` in some documentation but that
    parameter never worked and is now removed.  See examples below.
  Examples...
  ```
    location_info = shape="Sphere", pos="39.0 -105.0 1620", radius="20"
    location_info = shape="Point", crs="3d", pos="39.0 -105.0 1620"
    location_info = shape="Point", pos="39.0 -105.0"
    location_info = shape=Ellipsoid, pos="39.0 -105.0 1620", semiMajorAxis="20"
                  semiMinorAxis="10", verticalAxis="0", orientation="25 degrees"
    pidf_element_id = ${CHANNEL(name)}-${EXTEN}
    device_id = mac:001122334455
    Set(GEOLOC_PROFILE(pidf_element_id)=${CHANNEL(name)}/${EXTEN})
  ```

- #### app_directed_pickup.c: Change some log messages from NOTICE to VERBOSE.
  In an effort to reduce log spam, two normal progress
  "pickup attempted" log messages from app_directed_pickup have been changed
  from NOTICE to VERBOSE(3).  This puts them on par with other normal
  dialplan progress messages.

- #### app_queue.c: Fix error in Queue parameter documentation.
  As part of Asterisk 21, macros were removed from Asterisk.
  This resulted in argument order changing for the Queue dialplan
  application since the macro argument was removed. Upgrade notice was
  missed when this was done, so this upgrade note has been added to
  provide a record of such and a notice to users who may have not upgraded
  yet.

- #### res_audiosocket: add message types for all slin sample rates
  New audiosocket message types 0x11 - 0x18 has been added
  for slin12, slin16, slin24, slin32, slin44, slin48, slin96, and
  slin192 audio. External applications using audiosocket may need to be
  updated to support these message types if the audiosocket channel is
  created with one of these audio formats.

- #### taskpool: Add taskpool API, switch Stasis to using it.
  The threadpool_* options in stasis.conf have now been deprecated
  though they continue to be read and used. They have been replaced with taskpool
  options that give greater control over the underlying taskpool used for stasis.

- #### safe_asterisk: Add ownership checks for /etc/asterisk/startup.d and its files.
  The safe_asterisk script now checks that, if it was run by the
  root user, the /etc/asterisk/startup.d directory and all the files it contains
  are owned by root.  If the checks fail, safe_asterisk will exit with an error
  and Asterisk will not be started.  Additionally, the default logging
  destination is now stderr instead of tty "9" which probably won't exist
  in modern systems.

- #### jansson: Upgrade version to jansson 2.14.1
  jansson has been upgraded to 2.14.1. For more
  information visit jansson Github page: https://github.com/akheron/jansson/releases/tag/v2.14.1

- #### Alternate Channel Storage Backends
  With this release, you can now select an alternate channel
  storage backend based on C++ Maps.  Using the new backend may increase
  performance and reduce the chances of deadlocks on heavily loaded systems.
  For more information, see http://s.asterisk.net/dc679ec3

- #### ARI: REST over Websocket
  This commit adds the ability to make ARI REST requests over the same
  websocket used to receive events.
  See https://docs.asterisk.org/Configuration/Interfaces/Asterisk-REST-Interface-ARI/ARI-REST-over-WebSocket/

- #### alembic: Database updates required.
  Two commits in this release...
  'Add SHA-256 and SHA-512-256 as authentication digest algorithms'
  'res_pjsip: Add new AOR option "qualify_2xx_only"'
  ...have modified alembic scripts for the following database tables: ps_aors,
  ps_contacts, ps_auths, ps_globals. If you don't use the scripts to update
  your database, reads from those tables will succeeed but inserts into the
  ps_contacts table by res_pjsip_registrar will fail.

- #### channel: Add multi-tenant identifier.
  A new versioned struct (ast_channel_initializers) has been
  added that gets passed to __ast_channel_alloc_ap. The new function
  ast_channel_alloc_with_initializers should be used when creating
  channels that require the use of this struct. Currently the only value
  in the struct is for tenantid, but now more fields can be added to the
  struct as necessary rather than the __ast_channel_alloc_ap function. A
  new option (tenantid) has been added to endpoints in pjsip.conf as well.
  CEL has had its version bumped to include tenant ID.

- #### app_queue:  Add option to not log Restricted Caller ID to queue_log
  Add a new column to the queues table:
  queue_log_option_log_restricted ENUM('0','1','off','on','false','true','no','yes')
  to control whether the Restricted Caller ID will be stored in the queue log.

- #### pbx_variables.c: Prevent SEGV due to stack overflow.
  The maximum amount of dialplan recursion
  using variable substitution (such as by using EVAL_EXTEN)
  is capped at 15.

- #### Stir/Shaken Refactor
  The stir-shaken refactor is a breaking change but since
  it's not working now we don't think it matters. The
  stir_shaken.conf file has changed significantly which means that
  existing ones WILL need to be changed.  The stir_shaken.conf.sample
  file in configs/samples/ has quite a bit more information.  This is
  also an ABI breaking change since some of the existing objects
  needed to be changed or removed, and new ones added.  Additionally,
  if res_stir_shaken is enabled in menuselect, you'll need to either
  have the development package for libjwt v1.15.3 installed or use
  the --with-libjwt-bundled option with ./configure.

- #### app_voicemail_odbc: remove macrocontext from voicemail_messages table
  The fix requires that the voicemail database be upgraded via
  alembic. Upgrading to the latest voicemail database via alembic will
  remove the macrocontext column from the voicemail_messages table.

- #### app.c: Allow ampersands in playback lists to be escaped.
  Ampersands in URLs passed to the `Playback()`,
  `Background()`, `SpeechBackground()`, `Read()`, `Authenticate()`, or
  `Queue()` applications as filename arguments can now be escaped by
  single quoting the filename. Additionally, this is also possible when
  using the `CONFBRIDGE` dialplan function, or configuring various
  features in `confbridge.conf` and `queues.conf`.

- #### pjsip_configuration.c: Disable DTLS renegotiation if WebRTC is enabled.
  The dtls_rekey will be disabled if webrtc support is
  requested on an endpoint. A warning will also be emitted.

- #### res_pjsip: Expanding PJSIP endpoint ID and relevant resource length to 255 characters
  As part of this update, the maximum allowable length
  for PJSIP endpoints and relevant resources has been increased from
  40 to 255 characters. To take advantage of this enhancement, it is
  recommended to run the necessary procedures (e.g., Alembic) to
  update your schemas.

- #### users.conf: Deprecate users.conf configuration.
  The users.conf config is now deprecated
  and will be removed in a future version of Asterisk.

- #### app_queue: Preserve reason for realtime queues
  Add a new column to the queue_member table:
  reason_paused VARCHAR(80) so the reason can be preserved.

- #### app_sla: Migrate SLA applications out of app_meetme.
  The SLAStation and SLATrunk applications have been moved
  from app_meetme to app_sla. If you are using these applications and have
  autoload=no, you will need to explicitly load this module in modules.conf.

- #### utils.h: Deprecate `ast_gethostbyname()`. (#79)
  ast_gethostbyname() has been deprecated and will be removed
  in Asterisk 23. New code should use `ast_sockaddr_resolve()` and
  `ast_sockaddr_resolve_first_af()`.

- #### cel: add local optimization begin event (#54)
  The existing AST_CEL_LOCAL_OPTIMIZE can continue
  to be used as-is and the AST_CEL_LOCAL_OPTIMIZE_BEGIN event
  can be ignored if desired.
  


### Developer Notes:

- #### ccss:  Add option to ccss.conf to globally disable it.
  A new API ast_is_cc_enabled() has been added.  It should be
  used to ensure that CCSS is enabled before making any other ast_cc_* calls.

- #### chan_websocket: Add ability to place a MARK in the media stream.
  Apps can now send a `MARK_MEDIA` command with an optional
  `correlation_id` parameter to chan_websocket which will be placed in the
  media frame queue. When that frame is dequeued after all intervening media
  has been played to the core, chan_websocket will send a
  `MEDIA_MARK_PROCESSED` event to the app with the same correlation_id
  (if any).

- #### chan_websocket: Add capability for JSON control messages and events.
  The chan_websocket plain-text control and event messages are now
  deprecated (but remain the default) in favor of JSON formatted messages.
  See https://docs.asterisk.org/Configuration/Channel-Drivers/WebSocket for
  more information.
  A "transport_data" parameter has been added to the
- #### chan_pjsip: Add technology-specific off-nominal hangup cause to events.
  A "tech_cause" parameter has been added to the
  ChannelHangupRequest and ChannelDestroyed ARI event messages and a "TechCause"
  parameter has been added to the HangupRequest, SoftHangupRequest and Hangup
  AMI event messages.  For chan_pjsip, these will be set to the last SIP
  response status code for off-nominally terminated calls.  The parameter is
  suppressed for nominal termination.

- #### ARI: The bridges play and record APIs now handle sample rates > 8K correctly.
  The ARI /bridges/play and /bridges/record REST APIs have new
  parameters that allow the caller to specify the format to be used on the
  "Announcer" and "Recorder" channels respecitvely.

- #### taskpool: Add taskpool API, switch Stasis to using it.
  The taskpool API has been added for common usage of a
  pool of taskprocessors. It is suggested to use this API instead of the
  threadpool+taskprocessor approach.

- #### ARI: Add command to indicate progress to a channel
  A new ARI endpoint is available at `/channels/{channelId}/progress` to indicate progress to a channel.

- #### options:  Change ast_options from ast_flags to ast_flags64.
  The 32-bit ast_options has no room left to accomodate new
  options and so has been converted to an ast_flags64 structure. All internal
  references to ast_options have been updated to use the 64-bit flag
  manipulation macros.  External module references to the 32-bit ast_options
  should continue to work on little-endian systems because the
  least-significant bytes of a 64 bit integer will be in the same location as a
  32-bit integer.  Because that's not the case on big-endian systems, we've
  swapped the bytes in the flags manupulation macros on big-endian systems
  so external modules should still work however you are encouraged to test.


### Commit Authors:

- Abdelkader Boudih: (3)
- Albrecht Oster: (1)
- Alexandre Fournier: (1)
- Alexei Gradinari: (10)
- Alexey Khabulyak: (3)
- Alexey Vasilyev: (1)
- Allan Nathanson: (6)
- Andreas Wehrmann: (1)
- Anthony Minessale: (1)
- Artem Umerov: (2)
- Bastian Triller: (4)
- Ben Ford: (17)
- Boris P. Korzun: (2)
- Brad Smith: (4)
- C. Maj: (1)
- Cade Parker: (1)
- Christoph Moench-Tegeder: (1)
- Daouda Taha: (1)
- Eduardo: (1)
- Fabrice Fontaine: (3)
- Flole998: (1)
- Florent CHAUVEAU: (1)
- Frederic LE FOLL: (1)
- George Joseph: (184)
- Gitea: (1)
- Henning Westerholt: (3)
- Henrik Liljedahl: (1)
- Holger Hans Peter Freyther: (9)
- Igor Goncharovsky: (7)
- InterLinked1: (4)
- Itzanh: (1)
- Ivan Poddubny: (2)
- Jaco Kroon: (10)
- James Terhune: (1)
- Jason D. McCormick: (1)
- Jeremy Lainé: (1)
- Jiajian Zhou: (1)
- Joe Garlick: (3)
- Joe Searle: (2)
- Jose Lopes: (1)
- Joshua C. Colp: (22)
- Joshua Elson: (2)
- Justin T. Gibbs: (1)
- Kent: (1)
- Kristian F. Høgh: (1)
- Luz Paz: (4)
- Maksim Nesterov: (1)
- Marcel Wagner: (2)
- Mark Murawski: (2)
- Martin Nystroem: (1)
- Martin Tomec: (2)
- Matthew Fredrickson: (2)
- Max Grobecker: (1)
- Maximilian Fridrich: (13)
- Michael Kuron: (2)
- Michal Hajek: (2)
- Miguel Angel Nubla: (1)
- Mike Bradeen: (58)
- Mike Pultz: (3)
- MikeNaso: (1)
- Nathan Bruning: (1)
- Nathan Monfils: (2)
- Nathaniel Wesley Filardo: (1)
- Naveen Albert: (201)
- Nick French: (1)
- Niklas Larsson: (1)
- Norm Harrison: (2)
- Olaf Titz: (1)
- Peter Fern: (1)
- Peter Jannesen: (3)
- Peter Krall: (1)
- PeterHolik: (2)
- Philip Prindeville: (12)
- Roman Pertsev: (1)
- Samuel Olaechea: (1)
- Sean Bright: (122)
- Sebastian Jennen: (1)
- Sergey V. Lobanov: (1)
- Shaaah: (1)
- Shyju Kanaprath: (1)
- Sperl Viktor: (5)
- Spiridonov Dmitry: (1)
- Stanislav Abramenkov: (6)
- Steffen Arntz: (1)
- Stuart Henderson: (1)
- Sven Kube: (8)
- ThatTotallyRealMyth: (1)
- The_Blode: (1)
- Thomas B. Clark: (1)
- Thomas Guebels: (2)
- Tinet-mucw: (11)
- Vitezslav Novy: (1)
- Walter Doekes: (1)
- Zhai Liangliang: (1)
- alex2grad: (1)
- chrsmj: (2)
- cmaj: (2)
- fabriziopicconi: (1)
- gauravs456: (1)
- gibbz00: (1)
- jiangxc: (1)
- jonatascalebe: (1)
- kodokaii: (1)
- mkmer: (3)
- phoneben: (10)
- romryz: (1)
- sarangr7: (1)
- sungtae kim: (3)
- zhengsh: (3)
- zhou_jiajian: (2)

## Issue and Commit Detail:

### Closed Issues:

  - !GHSA-2grh-7mhv-fcfw: Using malformed From header can forge identity with ";" or NULL in name portion
  - !GHSA-33x6-fj46-6rfh: Path traversal via AMI ListCategories allows access to outside files
  - !GHSA-64qc-9x89-rx5j: A specifically malformed Authorization header in an incoming SIP request can cause Asterisk to crash
  - !GHSA-85x7-54wr-vh42: Asterisk xml.c uses unsafe XML_PARSE_NOENT leading to potential XXE Injection
  - !GHSA-c4cg-9275-6w44: Write=originate, is sufficient permissions for code execution / System() dialplan
  - !GHSA-c7p6-7mvq-8jq2: cli_permissions.conf: deny option does not work for disallowing shell commands
  - !GHSA-hxj9-xwr8-w8pq: Asterisk susceptible to Denial of Service via DTLS Hello packets during call initiation
  - !GHSA-mrq5-74j5-f5cr: Remote DoS and possible RCE in asterisk/res/res_stir_shaken/verification.c
  - !GHSA-rvch-3jmx-3jf3: ast_coredumper running as root sources ast_debug_tools.conf from /etc/asterisk; potentially leading to privilege escalation
  - !GHSA-v428-g3cw-7hv9: A malformed Contact or Record-Route URI in an incoming SIP request can cause Asterisk to crash when res_resolver_unbound is used
  - !GHSA-v6hp-wh3r-cwxh: The Asterisk embedded web server's /httpstatus page echos user supplied values(cookie and query string) without sanitization
  - !GHSA-v9q8-9j8m-5xwp: Uncontrolled Search-Path Element in safe_asterisk script may allow local privilege escalation.
  - !GHSA-xpc6-x892-v83c: ast_coredumper runs as root, and writes gdb init file to world writeable folder; leading to potential privilege escalation 
  - 35: [New Feature]: chan_dahdi: Allow disabling pulse or tone dialing
  - 37: [Bug]: contrib/scripts/install_prereq tries to install armhf packages on aarch64 Debian platforms
  - 39: [Bug]: Remove .gitreview from repository.
  - 41: [Bug]: say.c Time announcement does not say o'clock for the French language
  - 43: [Bug]: Link to trademark policy is no longer correct
  - 45: [bug]: Non-bundled PJSIP check for evsub pending NOTIFY check is insufficient/ineffective
  - 46: [bug]: Stir/Shaken: Wrong CID used when looking up certificates
  - 48: [bug]: res_pjsip: Mediasec requires different headers on 401 response
  - 50: [improvement]: app_sla: Migrate SLA applications from app_meetme
  - 52: [improvement]: Add local optimization begin cel event
  - 55: [bug]: res_sorcery_memory_cache: Memory leak when calling sorcery_memory_cache_open
  - 60: [bug]: Can't enter any of UTF-8 character in the CLI prompt
  - 64: [bug]: app_voicemail_imap wrong behavior when losing IMAP connection
  - 65: [bug]: heap overflow by default at startup
  - 66: [improvement]: Fix preserve reason of pause when Asterisk is restared for realtime queues
  - 71: [new-feature]: core/ari/pjsip: Add refer mechanism to refer endpoints to some resource
  - 73: [new-feature]: pjsip: Allow topology/session refreshes in early media state
  - 78: [improvement]: Deprecate ast_gethostbyname()
  - 81: [improvement]: Enhance and add additional PJSIP pubsub callbacks
  - 84: [bug]: codec_ilbc:  Fails to build with ilbc version 3.0.4
  - 87: [bug]: app_followme: Setting enable_callee_prompt=no breaks timeout
  - 89: [improvement]:  indications: logging changes
  - 91: [improvement]: Add parameter on ARI bridge create to allow it to send SDP labels
  - 94: [new-feature]: sig_analog: Add full Caller ID support for incoming calls
  - 96: [bug]: make install-logrotate causes logrotate to fail on service restart
  - 98: [new-feature]: callerid: Allow timezone to be specified at runtime
  - 100: [bug]: sig_analog: hidecallerid setting is broken
  - 102: [bug]: Strange warning - 'T' option is not compatible with remote console mode and has no effect.
  - 104: [improvement]: Add AMI action to get a list of connected channels
  - 108: [new-feature]: fair handling of calls in multi-queue scenarios
  - 110: [improvement]: utils - add lock timing information with DEBUG_THREADS
  - 116: [bug]: SIP Reason: "Call completed elsewhere" no longer propagating
  - 118: [new-feature]: chan_dahdi: Allow fake ringing to be inhibited when immediate=yes
  - 120: [bug]: chan_dahdi: Fix broken presentation for FXO caller ID
  - 122: [new-feature]: res_musiconhold: Add looplast option
  - 129: [bug]: res_speech_aeap: Crash due to NULL format on setup
  - 133: [bug]: unlock channel after moh state access
  - 136: [bug]: Makefile downloader does not follow redirects.
  - 145: [bug]: ABI issue with pjproject and pjsip_inv_session
  - 155: [bug]: GCC 13 is catching a few new trivial issues
  - 158: [bug]: test_stasis_endpoints.c: Unit test channel_messages is unstable
  - 170: [improvement]: app_voicemail - add CLI commands to manipulate messages
  - 174: [bug]: app_voicemail imap compile errors
  - 179: [bug]: Queue strategy “Linear” with Asterisk 20 on Realtime
  - 181: [improvement]: app_voicemail - add manager actions to display and manipulate messages
  - 183: [deprecation]: Deprecate users.conf
  - 193: [bug]: third-party/apply-patches doesn't sort the patch file list before applying
  - 200: [bug]: Regression: In app.h an enum is used before its declaration.
  - 202: [improvement]: app_queue: Add support for immediately applying queue caller priority change
  - 205: [new-feature]: sig_analog: Allow flash to time out to silent hold
  - 211: [bug]: stasis: Off-nominal channel leave causes bridge to be destroyed
  - 224: [new-feature]: chan_dahdi: Allow automatic reorigination on hangup
  - 226: [improvement]: Apply contact_user to incoming calls
  - 230: [bug]: PJSIP_RESPONSE_HEADERS function documentation is misleading
  - 233: [bug]: Deadlock with MixMonitorMute AMI action
  - 240: [new-feature]: sig_analog: Add Called Subscriber Held capability
  - 242: [new-feature]: logger: Allow filtering logs in CLI by channel
  - 246: [bug]: res_pjsip_logger: Reload disables logging
  - 248: [bug]: core_local: Local channels cannot have slashes in the destination
  - 255: [bug]: pjsip_endpt_register_module: Assertion "Too many modules registered"
  - 260: [bug]: maxptime must be changed to multiples of 20
  - 263: [bug]: download_externals doesn't always handle versions correctly
  - 267: [bug]: ari: refer with display_name key in request body leads to crash
  - 271: [new-feature]: sig_analog: Add Call Waiting Deluxe support.
  - 274: [bug]: Syntax Error in SQL Code
  - 275: [bug]:Asterisk make now requires ASTCFLAGS='-std=gnu99 -Wdeclaration-after-statement'
  - 277: [bug]: pbx.c: Compiler error with gcc 12.2
  - 281: [bug]: app_dial: Infinite loop if called channel hangs up while receiving digits
  - 286: [improvement]: chan_iax2: Improve authentication debugging
  - 289: [new-feature]: Add support for deleting channel and global variables
  - 294: [improvement]: chan_dahdi: Improve call pickup documentation
  - 298: [improvement]: chan_rtp: Implement RTP glue
  - 301: [bug]: Number of ICE TURN threads continually growing
  - 303: [bug]: SpeechBackground never exits
  - 308: [bug]: chan_console: Deadlock when hanging up console channels
  - 315: [improvement]: Search /var/lib/asterisk/sounds/custom for sound files before  /var/lib/asterisk/sounds/<lang>
  - 316: [bug]: Privilege Escalation in Astrisk's Group permissions.
  - 319: [bug]: func_periodic_hook truncates long channel names when setting EncodedChannel
  - 321: [bug]: Performance suffers unnecessarily when debugging deadlocks
  - 325: [bug]: hangup after beep to avoid waiting for timeout
  - 330: [improvement]: Add cel user event helper function
  - 335: [bug]: res_pjsip_pubsub: The bad_event unit test causes a SEGV in build_resource_tree
  - 337: [bug]: asterisk.c: The CLI history file is written to the wrong directory in some cases
  - 341: [bug]: app_if.c : nested EndIf incorrectly exits parent If
  - 345: [improvement]: Increase pj_sip Realm Size to 255 Characters for Improved Functionality
  - 349: [improvement]: Add libjwt to third-party
  - 351: [improvement]: Refactor res_stir_shaken to use libjwt
  - 352: [bug]: Update qualify_timeout documentation to include DNS note
  - 354: [improvement]: app_voicemail: Disable ADSI if unavailable on a line
  - 356: [new-feature]: app_directory: Add ADSI support.
  - 360: [improvement]: Update documentation for CHANGES/UPGRADE files
  - 362: [improvement]: Speed up ARI command processing
  - 379: [bug]: Orphaned taskprocessors cause shutdown delays
  - 384: [bug]: Unnecessary re-INVITE after answer
  - 388: [bug]: Crash in app_followme.c due to not acquiring a reference to nativeformats
  - 396: [improvement]: res_pjsip: Specify max ciphers allowed if too many provided
  - 398: [new-feature]: app_voicemail: Add AMI event for password change
  - 401: [bug]: app_dial: Answer Gosub option passthrough regression
  - 406: [improvement]: pjsip: Upgrade bundled version to pjproject 2.14
  - 409: [improvement]: chan_dahdi: Emit warning if specifying nonexistent cadence
  - 423: [improvement]: func_lock: Add missing see-also refs
  - 425: [improvement]: configs: Improve documentation for bandwidth in iax.conf.sample
  - 428: [bug]: cli: Output is truncated from "config show help"
  - 430: [bug]: Fix broken links
  - 437: [new-feature]: sig_analog: Add Last Number Redial
  - 440: [new-feature]: chan_dahdi: Allow manually toggling MWI on channels
  - 442: [bug]: func_channel: Some channel options are not settable
  - 445: [bug]: ast_coredumper isn't figuring out file locations properly in all cases
  - 458: [bug]: Memory leak in chan_dahdi when mwimonitor=yes on FXO
  - 462: [new-feature]: app_dial: Add new option to preserve initial stream topology of caller
  - 465: [improvement]: Change res_odbc connection pool request logic to not lock around blocking operations
  - 472: [new-feature]: chan_dahdi: Allow waitfordialtone to be specified per call
  - 474: [new-feature]: loader.c: Allow dependent modules to be unloaded automatically
  - 480: [improvement]: pbx_variables.c: Prevent infinite recursion and stack overflow with variable expansion
  - 482: [improvement]: manager.c: Improve clarity of "manager show connected" output
  - 485: [new-feature]: manager.c: Allow kicking specific manager sessions
  - 487: [bug]: Segfault possibly in ast_rtp_stop
  - 492: [improvement]: res_calendar_icalendar: Print icalendar error if available on parsing failure
  - 500: [bug regression]: res_rtp_asterisk doesn't build if pjproject isn't used
  - 503: [bug]: The res_rtp_asterisk DTLS check against ICE candidates fails when it shouldn't
  - 505: [bug]: res_pjproject: ast_sockaddr_cmp() always fails on sockaddrs created by ast_sockaddr_from_pj_sockaddr()
  - 509: [bug]: res_pjsip: Crash when looking up transport state in use
  - 513: [bug]: manager.c: Crash due to regression using wrong free function when built with MALLOC_DEBUG
  - 515: [improvement]: Implement option to override User-Agent-Header on a per-registration basis
  - 520: [improvement]: menuselect: Use more specific error message.
  - 525: [bug]: say.c: Money announcements off by one cent due to floating point rounding
  - 527: [bug]: app_voicemail_odbc no longer working after removal of macrocontext.
  - 529: [bug]: MulticastRTP without selected codec leeds to "FRACK!, Failed assertion bad magic number 0x0 for object" after ~30 calls
  - 533: [improvement]: channel.c, func_frame_trace.c: Improve debuggability of channel frame queue
  - 539: [bug]: Existence of logger.xml causes linking failure
  - 548: [improvement]: Get Record() audio duration/length
  - 551: [bug]: manager: UpdateConfig triggers reload with "Reload: no"
  - 560: [bug]: EndIf() causes next priority to be skipped
  - 565: [bug]: Application Read() returns immediately
  - 569: [improvement]: Add option to interleave input and output frames on spied channel
  - 572: [improvement]: Copy partial speech results when Asterisk is ready to move on but the speech backend is not
  - 579: [improvement]: Allow GET_TRANSFERRER_DATA for pjsip
  - 582: [improvement]: Reduce unneeded logging during startup and shutdown
  - 586: [bug]: The "restrict" keyword used in chan_iax2.c isn't supported in older gcc versions
  - 588: [new-feature]: app_dial: Allow Dial to be aborted if early media is not received
  - 592: [bug]: In certain circumstances, "pjsip show channelstats" can segfault when a fax session is active
  - 595: [improvement]: dsp.c: Fix and improve confusing warning message.
  - 597: [bug]: wrong MOS calculation
  - 599: [improvement]: Endpoint identifier request line
  - 601: [new-feature]: translate.c: implement new direct comp table mode (PR #585)
  - 611: [bug]: res_pjsip_session: Polling on non-existing file descriptors when stream is removed
  - 619: [new-feature]: app_voicemail: Allow preventing callers from marking messages as urgent
  - 624: [bug]: Park() application does not continue execution if lot is full
  - 629: [bug]: app_voicemail: Multiple executions of unit tests cause segfault
  - 634: [bug]: make install doesn't create the stir_shaken cache directory
  - 636: [bug]: Possible SEGV in res_stir_shaken due to wrong free function
  - 642: [bug]: Prometheus bridge metrics contains duplicate entries and help
  - 643: [new-feature]: pjsip show contact -- show all details same as AMI PJSIPShowContacts
  - 645: [bug]: Occasional SEGV in res_pjsip_stir_shaken.c
  - 666: [improvement]: ARI debug should contain endpoint and method
  - 669: [bug]: chan_dahdi: Tens or hundreds of thousands of channel opens attempted during restart
  - 673: [new-feature]: chan_dahdi: Add AMI action to show spans
  - 676: [bug]: res_stir_shaken implicit declaration of function errors/warnings
  - 681: [new-feature]: callerid.c: Parse all received parameters
  - 683: [improvement]: func_callerid: Warn if invalid redirecting reason is set
  - 689: [bug] Document the `Events` argument of the `Login` AMI action
  - 696: [bug]: Unexpected control subclass '14'
  - 699: [improvement]: Add support for multi-rate DTMF
  - 713: [bug]: SNI isn't being set on websocket client connections
  - 716: [bug]: Memory leak in res_stir_shaken tn_config, plus a few other issues
  - 719: [bug]: segfault on start if compiled with DETECT_DEADLOCKS
  - 721: [improvement]: logger: Add unique verbose prefixes for higher verbose levels
  - 729: [bug]: Build failure with uclibc-ng
  - 736: [bug]: Seg fault on CLI after PostgreSQL CDR module fails to load for a second time
  - 740: [new-feature]: Add multi-tenant identifier to chan_pjsip
  - 763: [bug]: autoservice thread stuck in an endless sleep
  - 765: [improvement]: Add option to not log Restricted Caller ID to queue_log
  - 770: [improvement]: pbx.c: expand fields width of "core show hints"
  - 776: [bug] DTMF broken after rtp_engine: add support for multirate RFC2833 digits commit
  - 780: [bug]: Infinite loop of "Indicated Video Update", max CPU usage
  - 781: [improvement]: Allow call by call disabling Stir/Shaken header inclusion 
  - 783: [bug]: Under certain circumstances a channel snapshot can get orphaned in the cache
  - 789: [bug]: Mediasec headers aren't sent on outgoing INVITEs
  - 797: [bug]: 
  - 799: [improvement]: Add PJSIPNOTIFY dialplan application
  - 801: [bug]: res_stasis: Occasional 200ms delay adding channel to a bridge
  - 809: [bug]: CLI stir_shaken show verification kills asterisk
  - 811: [new-feature]: ARI channel tone detect events.
  - 816: [bug]: res_pjsip_config_wizard doesn't load properly if res_pjsip is loaded first
  - 819: [bug]: Typo in voicemail.conf.sample that stops it from loading when using "make samples"
  - 821: [bug]: app_dial:  The progress timeout doesn't cause Dial to exit
  - 822: [bug]: segfault in main/rtp_engine.c:1489 after updating 20.8.1 -> 20.9.0
  - 845: [bug]: Buffer overflow in handling of security mechanisms in res_pjsip 
  - 847: [bug]: Asterisk not using negotiated fall-back 8K digits
  - 851: [bug]: unable to read audiohook both side when packet lost on one side of the call 
  - 854: [bug]:  wrong properties in stir_shaken.conf.sample
  - 856: [bug]: res_pjsip_sdp_rtp leaks astobj2 ast_format 
  - 861: [bug]: ChanSpy unable to read audiohook read direction frame when no packet lost on both side of the call
  - 876: [bug]: ChanSpy unable to write whisper_audiohook when set flag OPTION_READONLY
  - 879: [bug]: res_stir_shaken/verification.c: Getting verification errors when global_disable=yes
  - 881: [bug]: Long URLs are being rejected by the media cache because of an astdb key length limit
  - 882: [bug]: Value CHANNEL(userfield) is lost by BRIDGE_ENTER
  - 884: [bug]: A ':' at the top of in stir_shaken.conf make Asterisk producing a core file when starting
  - 889: [bug]: res_stir_shaken/verification.c has a stale include for jansson.h that can cause compilation to fail
  - 897: [improvement]: Restrict ModuleLoad AMI action to the modules directory
  - 900: [bug]: astfd.c: NULL pointer passed to fclose with nonnull attribute causes compilation failure
  - 902: [bug]: app_voicemail: Pager emails are ill-formatted when custom subject is used
  - 904: [bug]: stir_shaken: attest_level isn't being propagated correctly from attestation to profile to tn
  - 916: [bug]: Compilation errors on FreeBSD
  - 921: [bug]: Stir-Shaken doesn’t allow B or C attestation for unknown callerid which is allowed by ATIS-1000074.v003, §5.2.4
  - 923: [bug]: Transport monitor shutdown callback only works on the first disconnection
  - 924: [bug]: dnsmgr.c: dnsmgr_refresh() should not flag change if IP address order changes
  - 927: [bug]: no audio when media source changed during the call
  - 928: [bug]: chan_dahdi: MWI while off-hook when hung up on after recall ring
  - 932: [bug]: When connected to multiple IP addresses the transport monitor is only set on the first one
  - 937: [bug]: Wrong format for sample config file 'geolocation.conf.sample'
  - 938: [bug]: memory leak - CBAnn leaks a small amount format_cap related memory for every confbridge
  - 945: [improvement]: Add stereo recording support for app_mixmonitor
  - 948: [improvement]: Support SHA-256 algorithm on REGISTER and INVITE challenges
  - 951: [new-feature]: func_evalexten: Add `EVAL_SUB` function
  - 963: [bug]: missing hangup cause for ARI ChannelDestroyed when Dial times out
  - 974: [improvement]: change and/or remove some wiki mentions to docs mentions in the sample configs
  - 979: [improvement]: Add ability to suppress MOH when a remote endpoint sends "sendonly" or "inactive"
  - 982: [bug]: The addition of tenantid to the ast_sip_endpoint structure broke ABI compatibility
  - 990: [improvement]: The help for PJSIP_AOR should indicate that you need to call PJSIP_CONTACT to get contact details
  - 993: [bug]: sig_analog: Feature Group D / E911 no longer work
  - 995: [bug]: suppress_moh_on_sendonly should use AST_BOOL_VALUES instead of YESNO_VALUES in alembic script
  - 999: [bug]: Crash when setting a global variable with invalid UTF8 characters
  - 1007: [improvement]: Cannot dynamically add queue member in paused state from dialplan or command line
  - 1013: [improvement]: chan_pjsip: Send VIDUPDATE RTP frames for H.264 streams on endpoints without WebRTC
  - 1021: [improvement]: proper queue_log paused state when member added dynamically
  - 1023: [improvement]: Improve PJSIP_MEDIA_OFFER documentation
  - 1028: [bug]: "pjsip show endpoints" shows some identifies on endpoints that shouldn't be there
  - 1029: [bug]: chan_dahdi: Wrong channel state set when RINGING received
  - 1054: [bug]: chan_iax2: Frames unnecessarily backlogged with jitterbuffer if no voice frames have been received yet
  - 1058: [bug]: Asterisk fails to compile following commit 71a2e8c on Ubuntu 20.04
  - 1064: [improvement]: ast_tls_script: Add option to skip passphrase for CA private key
  - 1075: [bug]: res_prometheus does not set Content-Type header in HTTP response
  - 1085: [bug]: utils: Compilation failure with DEVMODE due to old-style definitions
  - 1088: [bug]: app_sms: Compilation failure in DEVMODE due to stringop-overflow error in GCC 15 pre-release
  - 1091: [improvement]: app queue :add to  queue log callerid name
  - 1095: [bug]: res_pjsip missing "Failed to authenticate" log entry for unknown endpoint
  - 1097: [bug]: res_pjsip/pjsip_options. ODBC: Unknown column 'qualify_2xx_only'
  - 1101: [bug]: when setting a  var with a double quotes and using Set(HASH)
  - 1109: [bug]: Off nominal memory leak in res/ari/resource_channels.c
  - 1112: [bug]: STIR/SHAKEN verification doesn't allow anonymous callerid to be passed to the dialplan.
  - 1119: [bug]: Realtime database not working after upgrade from 22.0.0 to 22.2.0
  - 1122: Need status on CVE-2024-57520 claim.
  - 1124: [bug]: Race condition between bridge and channel delete can over-write cause code set in hangup.
  - 1131: [bug]: CHANGES link broken in README.md
  - 1141: [bug]: res_pjsip: Contact header set incorrectly for call redirect (302 Moved temp.) when external_* set
  - 1144: [bug]: action_redirect don't remove bridge_after_goto data
  - 1149: [bug]: res_pjsip: Mismatch in tcp_keepalive_enable causes not to enable
  - 1164: [bug]: WARNING Message in messages.log for res_curl.conf [globals]
  - 1171: [improvement]: Need the capability in audiohook.c for fractional (float) type volume adjustments.
  - 1176: [bug]: ast_slinear_saturated_multiply_float produces potentially audible distortion artifacts
  - 1178: [improvement]: jansson: Upgrade version to jansson 2.14.1
  - 1181: [bug]: Incorrect PJSIP Endpoint Device States on Multiple Channels
  - 1190: [bug]: Crash when starting ConfBridge recording over CLI and AMI
  - 1197: [bug]: ChannelHangupRequest does not show cause code in all cases
  - 1206: [improvement]: chan_iax2: Minor improvements to documentation and warning messages.
  - 1220: [bug]: res_pjsip_caller_id: OLI is not parsed if contained in a URI parameter
  - 1224: [improvement]: app_meetme: Removal version is incorrect
  - 1230: [bug]: ast_frame_adjust_volume and ast_frame_adjust_volume_float crash on interpolated frames
  - 1234: [bug]: Set CalllerID lost on DTMF attended transfer
  - 1240: [bug]: WebRTC invites failing on Chrome 136
  - 1243: [bug]: make menuconfig fails due to changes in GTK callbacks
  - 1251: [improvement]: PJSIP shouldn't require SIP Date header to process full shaken passport which includes iat
  - 1254: [bug]: ActiveChannels not reported when using AMI command PJSIPShowEndpoint
  - 1259: [bug]: New TenantID feature doesn't seem to set CDR for incoming calls
  - 1260: [bug]: Asterisk sends RTP audio stream before ICE/DTLS completes
  - 1269: [bug]: MixMonitor with D option produces corrupt file
  - 1271: [bug]: STIR/SHAKEN not accepting port 8443 in certificate URLs
  - 1272: [improvement]: STIR/SHAKEN handle X5U certificate chains
  - 1273: [bug]: When executed with GotoIf, the action Redirect does not take effect and causes confusion in dialplan execution.
  - 1276: MixMonitor produces broken recordings in bridged calls with asymmetric codecs (e.g., alaw vs G.722)
  - 1279: [bug]: regression: 20.12.0 downgrades quality of wav16 recordings
  - 1280: [improvement]: logging playback of audio per channel
  - 1282: [bug]: Alternate Channel Storage Backends menuselect not enabling it
  - 1287: [bug]: channelstorage.c: Compilation failure with DEBUG_FD_LEAKS
  - 1288: [bug]: Crash when destroying channel with C++ alternative storage backend enabled
  - 1289: [bug]: sorcery - duplicate objects from multiple backends and backend divergence on update
  - 1301: [bug]: sig_analog: fgccamamf doesn't handle STP, STP2, or STP3
  - 1304: [bug]: FLUSH_MEDIA does not reset frame_queue_length in WebSocket channel
  - 1305: [bug]: Realtime incorrectly falls back to next backend on record-not-found (SQL_NO_DATA), causing incorrect behavior and delay
  - 1307: [improvement]: ast_tls_cert: Allow certificate validity to be configurable
  - 1309: [bug]: Crash with C++ alternative storage backend enabled
  - 1315:  [bug]: When executed with dialplan, the action Redirect does not take effect.
  - 1317: [bug]: AGI command buffer overflow with long variables
  - 1321: [improvement]: app_agent_pool: Remove obsolete documentation
  - 1323: [new-feature]: add CANCEL dispostion in CDR
  - 1327: [bug]: res_stasis_device_state: can't delete ARI Devicestate after asterisk restart
  - 1332: [new-feature]: func_curl: Allow auth methods to be set
  - 1340: [bug]: comfort noise packet corrupted
  - 1349: [bug]: Race condition on redirect can cause missing Diversion header
  - 1352: [improvement]: Websocket channel with custom URI
  - 1353: [bug]: AST_DATA_DIR/sounds/custom directory not searched
  - 1358: [new-feature]: app_chanspy: Add option to not automatically answer channel
  - 1364: [bug]: bridge.c: BRIDGE_NOANSWER not always obeyed
  - 1366: [improvement]: func_frame_drop: Handle allocation failure properly
  - 1369: [bug]: test_res_prometheus: Compilation failure in devmode due to curlopts not using long type
  - 1371: [improvement]: func_frame_drop: Add debug messages for frames that can be dropped
  - 1375: [improvement]: dsp.c: Improve logging in tone_detect().
  - 1378: [bug]: chan_dahdi: dialmode feature is not properly reset between calls
  - 1380: [bug]: sig_analog: Segfault due to calling strcmp on NULL
  - 1384: [bug]: chan_websocket: asterisk crashes on hangup after STOP_MEDIA_BUFFERING command with id
  - 1386: [bug]: enabling announceposition_only_up prevents any queue position announcements
  - 1390: [improvement]: res_tonedetect: Add option to automatically end detection in TONE_DETECT
  - 1394: [improvement]: sig_analog: Skip Caller ID spill if Caller ID is disabled
  - 1396: [new-feature]: pbx_builtins: Make tone option for WaitExten configurable
  - 1401: [bug]: app_waitfornoise timeout is always less then configured because of time() usage
  - 1417: [bug]: static code analysis issues in abstract_jb
  - 1419: [bug]: static code analysis issues in app_adsiprog.c
  - 1421: [bug]: static code analysis issues in apps/app_dtmfstore.c
  - 1422: [bug]: static code analysis issues in apps/app_externalivr.c
  - 1425: [bug]: static code analysis issues in apps/app_queue.c
  - 1427: [bug]: static code analysis issues in apps/app_stream_echo.c
  - 1430: [bug]: static code analysis issues in res/stasis/app.c
  - 1434: [improvement]: pbx_variables: Create real channel for dialplan eval CLI command
  - 1436: [improvement]: res_cliexec: Avoid unnecessary cast to char*
  - 1442: [bug]: static code analysis issues in main/bridge_basic.c
  - 1444: [bug]: static code analysis issues in bridges/bridge_simple.c
  - 1446: [bug]: static code analysis issues in bridges/bridge_softmix.c
  - 1455: [new-feature]: chan_dahdi: Add DAHDI_CHANNEL function
  - 1457: [bug]: segmentation fault because of a wrong ari config
  - 1462: [bug]: chan_websocket isn't handling the "opus" codec correctly.
  - 1467: [bug]: Crash in res_pjsip_refer during REFER progress teardown with PJSIP_TRANSFER_HANDLING(ari-only)
  - 1474: [bug]: Media doesn't flow for video conference after res_rtp_asterisk change to stop media flow before DTLS completes
  - 1478: [improvement]: Stasis threadpool -> taskpool
  - 1479: [bug]: The ARI bridge play and record APIs limit audio bandwidth by forcing the slin8 format.
  - 1483: [improvement]: sig_analog: Eliminate possible timeout for Last Number Redial
  - 1485: [improvement]: func_scramble: Add example to XML documentation.
  - 1487: [improvement]: app_dial: Allow partial seconds to be used for dial timeouts
  - 1489: [improvement]: config_options.c: Improve misleading error message
  - 1491: [bug]: Segfault: `channelstorage_cpp` fast lookup without lock (`get_by_name_exact`/`get_by_uniqueid`) leads to UAF during hangup
  - 1493: [new-feature]: app_sf: Add post-digit timer option
  - 1496: [improvement]: dsp.c: Minor fixes to debug log messages
  - 1499: [new-feature]: func_math: Add function to return the digit sum
  - 1501: [improvement]: codec_builtin: Fix some inaccurate quality weights.
  - 1505: [improvement]: res_fax: Add XML documentation for channel variables
  - 1507: [improvement]: res_tonedetect: Minor formatting issue in documentation
  - 1509: [improvement]: res_fax.c — log debug error as debug, not regular log
  - 1510: [new-feature]: sig_analog: Allow '#' to end the inter-digit timeout when dialing.
  - 1514: [improvement]: func_channel: Allow R/W of ADSI CPE capability setting.
  - 1517: [improvement]: core_unreal: Preserve ADSI capability when dialing Local channels
  - 1519: [improvement]: app_dial / func_callerid: DNIS information is not propagated by Dial
  - 1525: [bug]: chan_websocket: fix use of raw payload variable for string comparison in process_text_message
  - 1531: [bug]: Memory corruption in manager.c due to double free of criteria variable.
  - 1534: [bug]: app_queue when using gosub breaks dialplan when going from 20 to 21, What's new in 21 doesn't mention it's a breaking change,
  - 1535: [bug]: chan_pjsip changes SSRC on WebRTC channels, which is unsupported by some browsers
  - 1536: [bug]: asterisk -rx connects to console instead of executing a command
  - 1539: [bug]: safe_asterisk without TTY doesn't log to file
  - 1544: [improvement]: While Receiving the MediaConnect Message Using External Media Over websocket ChannelID is  Details are missing
  - 1546: [improvement]: Not able to pass the custom variables over the websockets using external Media with ari client library nodejs
  - 1552: [improvement]: chan_dahdi.conf.sample: Warnings for callgroup/pickupgroup in stock config
  - 1554: [bug]: safe_asterisk recurses into subdirectories of startup.d after f97361
  - 1559: [improvement]: Handle TLS handshake attacks in order to resolve the issue of exceeding the maximum number of HTTPS sessions.
  - 1563: [bug]:  chan_websocket.c: Wrong variable used in ast_strings_equal() (payload instead of command)
  - 1566: [improvement]: Improve Taskprocessor logging
  - 1568: [improvement]: Queue is playing announcements when announce_to_first_user is false
  - 1572: [improvement]: List modules at various support levels
  - 1574: [improvement]: Add playback progress acknowledgment for WebSocket media (per-chunk or byte-level acknowledgment)
  - 1576: [improvement]: res_pjsip_messaging: Follow 3xx redirect messages if redirect_method=uri_pjsip
  - 1578: [bug]: Deadlock with externalMedia custom channel id and cpp map channel backend
  - 1585: [bug]: cli 'stasis show topics' calls a read lock which freezes asterisk till the process is done
  - 1587: [bug]: chan_websocket terminates websocket on CNG/non-audio
  - 1590: [bug]: Fix: Use ast instead of p->chan to get the DIALSTATUS variable
  - 1592: [bug]: app_disa: ResetCDR warning on most invocations
  - 1597: [bug]: app_reload: Reload() without arguments doesn't work.
  - 1599: [bug]: pbx.c: Running "dialplan reload" shows wrong number of contexts
  - 1604: [bug]: asterisk crashes during dtmf input thru websocket -- fixed
  - 1609: [bug]: Crash: Double free in ast_channel_destructor leading to SIGABRT (Asterisk 20.17.0) with C++ channel storage
  - 1635: [bug]: Regression: Fix endpoint memory leak
  - 1638: [bug]: Channel drivers creating ephemeral channels create per-endpoint topics and cache when they shouldn't
  - 1643: [bug]: chan_websocket crash when channel hung up before read thread is started
  - 1645: [bug]: chan_websocket stuck channels
  - 1647: [bug]: "presencestate change" CLI command doesn't accept NOT_SET
  - 1648: [bug]: ARI announcer channel can cause crash in specific scenario due to unreffing of borrowed format
  - 1660: [bug]: missing hangup cause for ARI ChannelDestroyed when Originated channel times out
  - 1662: [improvement]: Include remote IP address in http.c “Requested URI has no handler” log entries
  - 1667: [bug]: Multiple geolocation issues with rendering XML
  - 1673: [bug]: A crash occurs during the call to mixmonitor_ds_remove_and_free
  - 1675: [bug]: res_pjsip_mwi: off-nominal endpoint ao2 reference leak in mwi_get_notify_data()
  - 1681: [bug]: stasis/control.c: Memory leak of hangup_time in set-timeout
  - 1683: [improvement]: chan_websocket: Use channel FD polling to read data from websocket instead of dedicated thread.
  - 1692: [improvement]:  Add comment to asterisk.conf.sample clarifying that template sections are ignored
  - 1700: [improvement]: Improve sorcery cache populate
  - 1739: [bug]: Regression in 23.2.0 with regard to parsing fractional numbers when system locale is non-standard
  - ASTERISK-21502: New SIP Channel Driver - add Advice of Charge support
  - ASTERISK-21741: [patch] - Improved Caller ID Diagnostics and Processing for FXO Channels
  - ASTERISK-21795: failed compilation - dns.c references res_nsearch which is not available on uclibc
  - ASTERISK-26826: testsuite: Add support for Python 3
  - ASTERISK-26894: pjsip should support tel uri scheme
  - ASTERISK-27830: Asterisk crashes on Invalid UTF-8 string
  - ASTERISK-28109: pbx_dundi: Does not support chan_pjsip
  - ASTERISK-28233: pbx_dundi: PJSIP is not a supported technology
  - ASTERISK-28422: Memory Leak in Confbridge menu
  - ASTERISK-28689: res_pjsip: Crash when locking group lock when sending stateful response
  - ASTERISK-28767: chan_pjsip: Caller ID not used when checking for extension, callerid supplement executed too late
  - ASTERISK-29185: chan_pjsip: Endpoint: allow = all is broken.
  - ASTERISK-29428: DTMF on progress results in infinite loop if progress followed by hangup received
  - ASTERISK-29432: New function to allow access to any channel
  - ASTERISK-29453: alembic: incoming_call_offer_pref and outgoing_call_offer_pref missing in "ps_endpoints" table
  - ASTERISK-29455: Local channels (dialed using Originate dialplan application) play back gsm files over ulaw files when both exist
  - ASTERISK-29497: Add conditional branch applications
  - ASTERISK-29516: app_senddtmf / local: Sending DTMF does not work when not answered
  - ASTERISK-29604: ari: Segfault with lots of calls
  - ASTERISK-29793: adsi: CAS is malformed
  - ASTERISK-29810: app_signal: Add channel signaling applications
  - ASTERISK-29846: channels: bad ao2 ref causes crash
  - ASTERISK-29899: features: Add advanced transfer initiation options
  - ASTERISK-29905: OSX: bininstall launchd issue on cross-platfrom build
  - ASTERISK-29906: [patch] update RLS to reflect the changes to the lists
  - ASTERISK-29912: res_pjsip: module reload disables logging
  - ASTERISK-29913: func_json: Adds multi-level and array parsing to JSON_DECODE
  - ASTERISK-29917: ami: FilterList action doesn't exist
  - ASTERISK-29966: pbx_variables: ast_str_strlen can be wrong
  - ASTERISK-29992: chan_dahdi: Allow pulse and tone dialing to be disabled
  - ASTERISK-29998: sla: deadlock when calling SLAStation application
  - ASTERISK-30003: chan_dahdi: Allow fake ringing to be inhibited when immediate=yes
  - ASTERISK-30004: chan_dahdi: Allow flash to hold to time out to silence
  - ASTERISK-30013: core_local: Local channels cannot have slashes in the destination
  - ASTERISK-30018: app_meetme: MeetmeList AMI event not documented
  - ASTERISK-30020: ConfbridgeListRooms Event Not Documented
  - ASTERISK-30032: Support of mediasec SIP headers and SDP attributes
  - ASTERISK-30037: Add test support to calling external processes
  - ASTERISK-30045: Add test coverage to res/res_crypto.c functionality
  - ASTERISK-30046: Reimplement res/res_crypto.c internals with EVP_PKEY interface to Openssl API's
  - ASTERISK-30091: cdr: Allow CDRs to ignore call state changes
  - ASTERISK-30100: res_pjsip: Path is ignored on INVITE to endpoint
  - ASTERISK-30107: iostream: Build failure with libressl
  - ASTERISK-30135: [res_musiconhold] Allows the moh only for the answered call
  - ASTERISK-30136: db: Add AMI action to retrieve all keys beginning with a prefix
  - ASTERISK-30137: manager: Global disabled event filtered is incomplete
  - ASTERISK-30143: manager: Read and Write output from "manager show connected" is not well documented/useful
  - ASTERISK-30146: res_pjsip_logger: Add method-based log filtering
  - ASTERISK-30150: res_pjsip_session: Add support for custom parameters
  - ASTERISK-30151: Documentation doesn't include info about "field", a 3rd required parameter.
  - ASTERISK-30153: logger: Improve log levels
  - ASTERISK-30158: PJSIP: Add new 100rel option "peer_supported"
  - ASTERISK-30159: general: Remove obsolete SVN references
  - ASTERISK-30160: cdr.conf: Remove obsolete app_mysql reference
  - ASTERISK-30161: locks: add AMI event for deadlock
  - ASTERISK-30162: when chan_iax is used to relay calls, no ringing indication is played
  - ASTERISK-30163: general: fix minor formatting issues
  - ASTERISK-30164: chan_iax2: Add missing option documentation
  - ASTERISK-30167: res_geolocation:  Refactor for issues found by users
  - ASTERISK-30176: manager: GetConfig can read files outside of Asterisk
  - ASTERISK-30177: res_geolocation:  Add option to suppress empty elements
  - ASTERISK-30178: extend user_eq_phone behavior to local uri's
  - ASTERISK-30179: app_amd: Allow audio to be played while AMD is running
  - ASTERISK-30180: app_broadcast: Add a channel audio multicasting application
  - ASTERISK-30182: res_geolocation: Add built-in profiles to use in fully dynamic configurations
  - ASTERISK-30185: res_geolocation: Allow location parameters to be specified in profiles
  - ASTERISK-30186: res_pjsip: Add support for reloading TLS certificate and key information
  - ASTERISK-30190: res_geolocation:  GEOLOC_PROFILE isn't returning correct values on incoming channel
  - ASTERISK-30192: res_tonedetect: fix typo for frametype
  - ASTERISK-30193: chan_pjsip should return all codecs on a re-INVITE without SDP
  - ASTERISK-30198: Error `Too many open files` occurs after about ~8000 calls when using mixmonitor
  - ASTERISK-30209: pbx_variables: Use const char for pbx_substitute_variables_helper_full_location
  - ASTERISK-30210: func_frame_trace: Channel masquerade triggers assertion
  - ASTERISK-30211: app_confbridge: Add end_marked_any option
  - ASTERISK-30213: Make crypto_load() reentrant and handle symlinks correctly
  - ASTERISK-30215: Inbound SIP INVITE with Geo Location causing a Segmentation Fault
  - ASTERISK-30216: app_bridgewait: Add option for BridgeWait to not answer
  - ASTERISK-30217: Registration do not allow multiple proxies
  - ASTERISK-30220: func_scramble: Fix segfault due to null pointer deref
  - ASTERISK-30222: func_strings: Add trim functions
  - ASTERISK-30223: features: add no-answer option to Bridge application
  - ASTERISK-30226: REGRESSION: res_crypto complains about the stir_shaken directory in /var/lib/asterisk/keys
  - ASTERISK-30232: Initialize stack-based ast_test_capture structures correctly
  - ASTERISK-30234: res_geolocation: ...may be used uninitialized error in geoloc_config.c
  - ASTERISK-30235: res_crypto and tests:  Memory issues and and uninitialized variable error
  - ASTERISK-30237: res_prometheus: Crash when scraping bridges
  - ASTERISK-30239: Prometheus plugin crashes Asterisk when using local channel
  - ASTERISK-30240: app voicemail odbc build error with gcc 11.1
  - ASTERISK-30241: res_pjsip_gelocation: Downgrade some NOTICE scope trace debugs to DEBUG level
  - ASTERISK-30243: func_logic: IF function complains if both branches are empty
  - ASTERISK-30244: res_pjsip_pubsub: Occasional crash when TCP/TLS connection terminated and subscription persistence is removed
  - ASTERISK-30245: db: ListItems is incorrect
  - ASTERISK-30248: ast_get_digit_str adds bogus initial delimiter if first character not to be spoken
  - ASTERISK-30252: Unidirectional snoop on resampled channel causes garbled audio
  - ASTERISK-30254: res_tonedetect: Add audible ringback detection to TONE_DETECT
  - ASTERISK-30256: chan_dahdi: Fix format truncation warnings
  - ASTERISK-30258: Dialing API: Cancel a running async thread, does not always cancel all calls
  - ASTERISK-30262: res_pjsip_session: Allow a context to be specified for overlap dialing
  - ASTERISK-30263: res_pjsip_notify: Allow using pjsip_notify.conf from AMI
  - ASTERISK-30264: res_pjsip: Subscription handlers do not get cleanly unregistered, causing crash
  - ASTERISK-30265: res_pjsip_session: Fix missing PLAR support on INVITEs
  - ASTERISK-30273: test_mwi: compilation fails on 32-bit Debian
  - ASTERISK-30274: chan_dahdi: Unavailable channels are BUSY
  - ASTERISK-30278: tcptls: Abort occurs if SSL error is logged if MALLOC_DEBUG is enabled
  - ASTERISK-30280: Create capability to assign a Media Experience Score to RTP streams
  - ASTERISK-30281: chan_rtp: Local address being used before being set
  - ASTERISK-30282: CI: Coredump output isn't saved when running unittests
  - ASTERISK-30283: app_voicemail: Fix msg_create_from_file not sending email to user
  - ASTERISK-30284: app_mixmonitor: Add option to delete recording file when done
  - ASTERISK-30285: manager.c: Remove outdated documentation
  - ASTERISK-30286: app_mixmonitor: Add option to use real Caller ID for Caller ID
  - ASTERISK-30289: xmldoc: Allow XML docs to be reloaded
  - ASTERISK-30290: file.c: Don't emit warnings on winks.
  - ASTERISK-30293: Memory leak in JSON_DECODE
  - ASTERISK-30295: test_json: Remove duplicated static function
  - ASTERISK-30297: chan_sip: Remove deprecated module
  - ASTERISK-30298: chan_alsa: Remove deprecated module
  - ASTERISK-30299: chan_mgcp: Remove deprecated module
  - ASTERISK-30300: chan_skinny: Remove deprecated module
  - ASTERISK-30302: app_osplookup: Remove deprecated module
  - ASTERISK-30303: res_monitor: Remove deprecated module
  - ASTERISK-30304: app_macro: Remove deprecated module
  - ASTERISK-30305: chan_dahdi: Allow FXO channels to start immediately
  - ASTERISK-30308: pbx_builtins: Allow Answer to return immediately
  - ASTERISK-30309: app_sla: Migrate SLA applications from app_meetme
  - ASTERISK-30311: func_presencestate: Fix invalid memory access.
  - ASTERISK-30314: res_agi: RECORD FILE doesn't respect "transmit_silence" asterisk.conf option
  - ASTERISK-30316: res_pjsip: Documentation should point out default if contact_user is not being set for outbound registrations
  - ASTERISK-30319: Add BYE Reason support for SIP
  - ASTERISK-30321: Build:  Embedded blobs have executable stacks
  - ASTERISK-30322: res_hep: Add capture agent name support
  - ASTERISK-30325: Upgrade Asterisk to bundled pjproject 2.13
  - ASTERISK-30326: app_followme: Setting enable_callee_prompt=no(false) in followme.conf breaks timeout for calling from FollowMe application
  - ASTERISK-30327: rtp_engine.h: Remove obsolete example usage
  - ASTERISK-30328: Typo in from_domain description on res_pjsip configuration documentation
  - ASTERISK-30330: callerid: Allow timezone to be specified at runtime
  - ASTERISK-30331: sig_analog: Add full Caller ID support for incoming calls
  - ASTERISK-30332: func_callerid: Warn if invalid redirecting reason provided
  - ASTERISK-30333: chan_dahdi: Fix broken presentation for FXO caller ID
  - ASTERISK-30335: pbx_builtins: Remove deprecated and defunct applications and options
  - ASTERISK-30336: sig_analog: Fix no timeout duration
  - ASTERISK-30338: pjproject: Backport security fixes from 2.13
  - ASTERISK-30340: res_media_cache curl options configureable
  - ASTERISK-30344: ari: Memory leak in create when specifying JSON
  - ASTERISK-30345: loader.c: Modules that decline to load cannot be reloaded
  - ASTERISK-30346: Fix NULL dereferencing issue in Geolocation
  - ASTERISK-30347: xmldocs: Remove references to removed applications
  - ASTERISK-30349: app_if:  Format truncation error
  - ASTERISK-30350: res_pjsip_sdp_rtp: rtp_timeout_hold is not used when moh_passthrough has call on hold
  - ASTERISK-30351: manager: Originate variables are not added when setvar used in manager.conf
  - ASTERISK-30353: func_frame_trace: Print text for text frames
  - ASTERISK-30354: chan_iax2: Lack of formats prior to receiving voice frames causes jitterbuffer to stall
  - ASTERISK-30357: chan_dahdi: Allow automatic reoriginate on hangup
  - ASTERISK-30359: Install Prereq Script Enhancements
  - ASTERISK-30361: json.h: Add missing ast_json_object_real_get
  - ASTERISK-30367: pbx: Fix outdated channel snapshots with pbx_exec
  - ASTERISK-30369: res_pjsip: Websockets from same IP shut down when they shouldn't be
  - ASTERISK-30371: app_cdr: Remove deprecated NoCDR application
  - ASTERISK-30372: sig_analog: Add Called Subscriber Held capability
  - ASTERISK-30373: sig_analog: Add Call Waiting Deluxe options
  - ASTERISK-30375: res_http_media_cache: Crash when URL has no path component.
  - ASTERISK-30379: http: fix NULL pointer dereference while enable_status on TLS-only
  - ASTERISK-30388: res_phoneprov: Stale SERVER variable when multi-homed
  - ASTERISK-30391: res_rtp_asterisk: Issue with transcoding g722 after MES changes
  - ASTERISK-30404: app_directory: Add reading directory configuration from custom file
  - ASTERISK-30405: app_directory: Add 's' option to skip channel call
  - ASTERISK-30407: res_stir_shaken: Ordering of JSON fields incorrect, and tn lacks canonicalization
  - ASTERISK-30411: app_read: add option to include terminating digit on empty, terminated strings
  - ASTERISK-30417: Copy/Paste error in UnpauseQueueMember
  - ASTERISK-30419: pjsip: Crash when sending NOTIFY in PJSIP 2.13
  - ASTERISK-30422: app_senddtmf: add the option for senddtmf to answer
  - ASTERISK-30424: pjproject_bundled: cross-compilation broken when ssl autodetected
  - ASTERISK-30428: bridging: Music on hold continues after INVITE with replaces
  - ASTERISK-30429: res_sorcery_memory_cache: Memory leak when calling sorcery_memory_cache_open
  - ASTERISK-30433: http.c: Minor simplification to HTTP status output.
  - ASTERISK-30438: app_osplookup: Remove obsolete sample config
  - ASTERISK-30440: app_senddtmf: Add Flash AMI action
  - ASTERISK-30441: func_json: Fix JSON parsing of complex objects
  - ASTERISK-30442: make install-logrotate causes logrotate to fail on service restart
  - ASTERISK-30446: bridge_builtin_features: add periodic beep option to one touch monitor
  - ASTERISK-30449: contrib: rc.archlinux.asterisk uses invalid redirect.
  - ASTERISK-30455: Increase channel name column width on cli
  - ASTERISK-30457: res_agi: RECORD FILE plays 2 beeps
  - ASTERISK-30462: res_musiconhold: Add looplast option
  - ASTERISK-30464: app_mixmonitor: Allow specifying which MixMonitor instance (or all of them) to mute/unmute using MixMonitorMute
  - ASTERISK-30465: format_sln: add support for .slin files
  - ASTERISK-30469: res_pjsip_pubsub: Regression for subscription shutdowns
  - ASTERISK-30474: res_prometheus provides broken description
  - ASTERISK-30479: voicemail.conf: Comments about #include files are wrong
  - ASTERISK-30483: logger: Allow filtering logs in CLI by channel
  - ASTERISK-30485: res_pjsip_pubsub: Add APIs for new pubsub capabilities
  - ASTERISK-30486: app_queue: Fix minor xmldoc issues
  - ASTERISK-30488: say.c Time announcement does not say o'clock for the French language

### Commits By Author:

- #### Abdelkader Boudih (3):
  - samples: Use "asterisk" instead of "postgres" for username
  - res_config_pgsql: normalize database connection option with cel and cdr by supporting new options name
  - normalize contrib/ast-db-manage/queue_log.ini.sample

- #### Albrecht Oster (1):
  - res_pjproject: Fix DTLS client check failing on some platforms

- #### Alexandre Fournier (1):
  - res_geoloc: fix NULL pointer dereference bug

- #### Alexei Gradinari (10):
  - res_pjsip_mwi: Fix off-nominal endpoint ao2 ref leak in mwi_get_notify_data
  - sorcery: Prevent duplicate objects and ensure missing objects are created on update
  - res_config_odbc: Prevent Realtime fallback on record-not-found (SQL_NO_DATA)
  - chan_pjsip: set correct Endpoint Device State on multiple channels
  - autoservice: Do not sleep if autoservice_stop is called within autoservice thread
  - res_pjsip_sdp_rtp fix leaking astobj2 ast_format
  - app_queue:  Add option to not log Restricted Caller ID to queue_log
  - pbx.c: expand fields width of "core show hints"
  - format_wav: replace ast_log(LOG_DEBUG, ...) by ast_debug(1, ...)
  - res_pjsip_pubsub: Postpone destruction of old subscriptions on RLS update

- #### Alexey Khabulyak (3):
  - pbx_lua.c: segfault when pass null data to term_color function
  - app_dial.c: Moved channel lock to prevent deadlock
  - format_gsm.c: Added mime type

- #### Alexey Vasilyev (1):
  - res_rtp_asterisk.c: Fix bridged_payload matching with sample rate for DTMF

- #### Allan Nathanson (6):
  - file.c: with "sounds_search_custom_dir = yes", search "custom" directory
  - file.c: missing "custom" sound files should not generate warning logs
  - config.c: #include of non-existent file should not crash
  - config.c: fix #tryinclude being converted to #include on rewrite
  - config.c: retain leading whitespace before comments
  - dnsmgr.c: dnsmgr_refresh() incorrectly flags change with DNS round-robin

- #### Andreas Wehrmann (1):
  - pbx_ael: unregister AELSub application and CLI commands on module load failure

- #### Anthony Minessale (1):
  - Update contact information for anthm

- #### Artem Umerov (2):
  - Fix missing ast_test_flag64 in extconf.c
  - logger.h: Fix build when AST_DEVMODE is not defined.

- #### Bastian Triller (4):
  - Fix some doxygen, typos and whitespace
  - cli: Show configured cache dir
  - func_json: Fix crashes for some types
  - res_pjsip_session: Send Session Interval too small response

- #### Ben Ford (17):
  - app_queue.c: Fix error in Queue parameter documentation.
  - rtp_engine.c: Add exception for comfort noise payload.
  - res_rtp_asterisk: Don't send RTP before DTLS has negotiated.
  - contrib: Add systemd service and timer files for malloc trim.
  - documentation: Update Gosub, Goto, and add new documentationtype.
  - manager.c: Restrict ListCategories to the configuration directory.
  - Add res_pjsip_config_sangoma external module.
  - app_mixmonitor: Add 'D' option for dual-channel audio.
  - manager.c: Restrict ModuleLoad to the configured modules directory.
  - channel: Add multi-tenant identifier.
  - Upgrade bundled pjproject to 2.14.
  - manager.c: Prevent path traversal with GetConfig.
  - res_pjsip_session: Added new function calls to avoid ABI issues.
  - AMI: Add CoreShowChannelMap action.
  - res_pjsip_sdp_rtp.c: Use correct timeout when put on hold.
  - pjproject: 2.13 security fixes
  - res_pjsip: Add TEL URI support for basic calls.

- #### Boris P. Korzun (2):
  - http.c: Minor simplification to HTTP status output.
  - http.c: Fix NULL pointer dereference bug

- #### Brad Smith (4):
  - BuildSystem: Bump autotools versions on OpenBSD.
  - main/utils: Simplify the FreeBSD ast_get_tid() handling
  - main/utils: Implement ast_get_tid() for OpenBSD
  - res_rtp_asterisk.c: Fix runtime issue with LibreSSL

- #### C. Maj (1):
  - Makefile: Add module-list-* targets.

- #### Cade Parker (1):
  - chan_mobile: decrease CHANNEL_FRAME_SIZE to prevent delay

- #### Christoph Moench-Tegeder (1):
  - Fix Endianness detection in utils.h for non-Linux

- #### Daouda Taha (1):
  - app_mixmonitor: Add 's' (skip) option to delay recording.

- #### Eduardo (1):
  - codec_builtin: Use multiples of 20 for maximum_ms

- #### Fabrice Fontaine (3):
  - res/stasis/control.c: include signal.h
  - configure: fix detection of re-entrant resolver functions
  - main/iostream.c: fix build with libressl

- #### Flole998 (1):
  - res_pjsip_outbound_registration.c: Add User-Agent header override

- #### Florent CHAUVEAU (1):
  - audiosocket: added support for DTMF frames
  - asterisk/channel.h: fix documentation for 'ast_waitfor_nandfds()'
  - audiosocket: fix timeout, fix dialplan app exit, server address in logs

- #### Frederic LE FOLL (1):
  - Dialing API: Cancel a running async thread, may not cancel all calls

- #### George Joseph (184):
  - Initial commit for certified-22.8
  - xml.c: Replace XML_PARSE_NOENT with XML_PARSE_NONET for xmlReadFile.
  - http.c: Change httpstatus to default disabled and sanitize output.
  - chan_websocket.conf.sample: Fix category name.
  - chan_websocket: Use the channel's ability to poll fds for the websocket read.
  - res_geolocation:  Fix multiple issues with XML generation.
  - stasis/control.c: Add destructor to timeout_datastore.
  - chan_websocket: Add locking in send_event and check for NULL websocket handle.
  - endpoint.c: Plug a memory leak in ast_endpoint_shutdown().
  - ccss:  Add option to ccss.conf to globally disable it.
  - app_directed_pickup.c: Change some log messages from NOTICE to VERBOSE.
  - ast_coredumper: Fix multiple issues
  - chan_websocket: Add ability to place a MARK in the media stream.
  - chan_websocket: Add capability for JSON control messages and events.
  - build: Add menuselect options to facilitate code tracing and coverage
  - channelstorage:  Allow storage driver read locking to be skipped.
  - res_stir_shaken: Add STIR_SHAKEN_ATTESTATION dialplan function.
  - chan_pjsip: Disable SSRC change for WebRTC endpoints.
  - safe_asterisk:  Fix logging and sorting issue.
  - chan_pjsip: Add technology-specific off-nominal hangup cause to events.
  - taskpool:  Fix some references to threadpool that should be taskpool.
  - chan_websocket.c: Change payload references to command instead.
  - channelstorage_cpp_map_name_id: Add read locking around retrievals.
  - ARI: The bridges play and record APIs now handle sample rates > 8K correctly.
  - res_rtp_asterisk.c: Use rtp->dtls in __rtp_sendto when rtcp mux is used.
  - chan_websocket: Fix codec validation and add passthrough option.
  - res_ari: Ensure outbound websocket config has a websocket_client_id.
  - chan_websocket: Allow additional URI parameters to be added to the outgoing URI.
  - chan_websocket: Fix buffer overrun when processing TEXT websocket frames.
  - xmldoc.c: Fix rendering of CLI output.
  - channelstorage_cpp_map_name_id.cc: Refactor iterators for thread-safety.
  - res_srtp: Add menuselect options to enable AES_192, AES_256 and AES_GCM
  - options:  Change ast_options from ast_flags to ast_flags64.
  - cdr.c: Set tenantid from party_a->base instead of chan->base.
  - app_mixmonitor:  Update the documentation concerning the "D" option.
  - Media over Websocket Channel Driver
  - res_pjsip_authenticator_digest: Fix SEGV if get_authorization_hdr returns NULL.
  - res_stir_shaken: Test for missing semicolon in Identity header.
  - channelstorage: Rename callbacks that conflict with DEBUG_FD_LEAKS.
  - channelstorage_cpp_map_name_id: Fix callback returning non-matching channels.
  - res_stir_shaken.so: Handle X5U certificate chains.
  - res_stir_shaken: Add "ignore_sip_date_header" config option.
  - res_websocket_client:  Add more info to the XML documentation.
  - ARI Outbound Websockets
  - res_websocket_client: Create common utilities for websocket clients.
  - asterisk.c: Add option to restrict shell access from remote consoles.
  - res_pjsip_messaging.c: Mask control characters in received From display name
  - Alternate Channel Storage Backends
  - lock.h: Add include for string.h when DEBUG_THREADS is defined.
  - Prequisites for ARI Outbound Websockets
  - asterisk.c: Add "pre-init" and "pre-module" capability to cli.conf.
  - ari_websockets: Fix frack if ARI config fails to load.
  - ARI: REST over Websocket
  - README.md: Updates and Fixes
  - manager.c: Check for restricted file in action_createconfig.
  - swagger_model.py: Fix invalid escape sequence in get_list_parameter_type().
  - bridging: Fix multiple bridging issues causing SEGVs and FRACKs.
  - res_config_pgsql: Fix regression that removed dbname config.
  - res_stir_shaken: Allow missing or anonymous CID to continue to the dialplan.
  - resource_channels.c: Fix memory leak in ast_ari_channels_external_media.
  - func_strings.c: Prevent SEGV in HASH single-argument mode.
  - docs: Add version information to AGI command XML elements.
  - docs: Add version information to ARI resources and methods.
  - res_pjsip_authenticator_digest: Make correct error messages appear again.
  - alembic: Database updates required.
  - res_pjsip: Fix startup/reload memory leak in config_auth.
  - docs: Add version information to application and function XML elements
  - docs: Add version information to manager event instance XML elements
  - README.md, asterisk.c: Update Copyright Dates
  - docs: Add version information to configObject and configOption XML elements
  - res_pjsip_authenticator_digest: Fix issue with missing auth and DONT_OPTIMIZE
  - docs: Various XML fixes
  - docs: Enable since/version handling for XML, CLI and ARI documentation
  - Add SHA-256 and SHA-512-256 as authentication digest algorithms
  - Add C++ Standard detection to configure and fix a new C++20 compile issue
  - gcc14: Fix issues caught by gcc 14
  - Header fixes for compiling C++ source files
  - Add ability to pass arguments to unit tests from the CLI
  - Allow C++ source files (as extension .cc) in the main directory
  - res_stir_shaken: Allow sending Identity headers for unknown TNs
  - res_pjsip: Change suppress_moh_on_sendonly to OPT_BOOL_T
  - res_pjsip: Add new endpoint option "suppress_moh_on_sendonly"
  - func_pjsip_aor/contact: Fix documentation for contact ID
  - res_pjsip: Move tenantid to end of ast_sip_endpoint
  - res_srtp: Change Unsupported crypto suite msg from verbose to debug
  - pjproject_bundled:  Tweaks to support out-of-tree development
  - core_unreal.c: Fix memory leak in ast_unreal_new_channels()
  - geolocation.sample.conf: Fix comment marker at end of file
  - manager.c: Add unit test for Originate app and appdata permissions
  - res_rtp_asterisk: Fix dtls timer issues causing FRACKs and SEGVs
  - Fix application references to Background
  - manager.conf.sample: Fix mathcing typo
  - manager: Enhance event filtering for performance
  - manager.c: Split XML documentation to manager_doc.xml
  - db.c: Remove limit on family/key length
  - stir_shaken: Fix propagation of attest_level and a few other values
  - res_stir_shaken: Remove stale include for jansson.h in verification.c
  - res_stir_shaken.c: Fix crash when stir_shaken.conf is invalid
  - res_stir_shaken: Check for disabled before param validation
  - res_resolver_unbound: Test for NULL ub_result in unbound_resolver_callback
  - app_voicemail: Use ast_asprintf to create mailbox SQL query
  - security_agreements.c: Refactor the to_str functions and fix a few other bugs
  - stir_shaken.conf.sample: Fix bad references to private_key_path
  - manager.c: Fix FRACK when doing CoreShowChannelMap in DEVMODE
  - manager.c: Add entries to Originate blacklist
  - rtp_engine.c: Prevent segfault in ast_rtp_codecs_payloads_unset()
  - stir_shaken: CRL fixes and a new CLI command
  - res_pjsip_config_wizard.c: Refactor load process
  - voicemail.conf.sample: Fix ':' comment typo
  - bridge_softmix: Fix queueing VIDUPDATE control frames
  - ast-db-manage: Remove duplicate enum creation
  - security_agreement.c: Always add the Require and Proxy-Require headers
  - stasis_channels: Use uniqueid and name to delete old snapshots
  - app_voicemail_odbc: Allow audio to be kept on disk
  - tcptls/iostream:  Add support for setting SNI on client TLS connections
  - stir_shaken:  Fix memory leak, typo in config, tn canonicalization
  - make_buildopts_h: Always include DETECT_DEADLOCKS
  - logger.h:  Add SCOPE_CALL and SCOPE_CALL_WITH_RESULT
  - rtp_engine and stun: call ast_register_atexit instead of ast_register_cleanup
  - manager.c: Add missing parameters to Login documentation
  - res_stir_shaken:  Fix compilation for CentOS7 (openssl 1.0.2)
  - Fix incorrect application and function documentation references
  - res_pjsip_stir_shaken.c:  Add checks for missing parameters
  - attestation_config.c: Use ast_free instead of ast_std_free
  - Makefile: Add stir_shaken/cache to directories created on install
  - Stir/Shaken Refactor
  - pjsip show channelstats: Prevent possible segfault when faxing
  - Reduce startup/shutdown verbose logging
  - res_rtp_asterisk: Fix regression issues with DTLS client check
  - res_rtp_asterisk.c: Check DTLS packets against ICE candidate list
  - MergeApproved.yml:  Remove unneeded concurrency
  - ast_coredumper: Increase reliability
  - SECURITY.md: Update with correct documentation URL
  - codec_ilbc: Disable system ilbc if version >= 3.0.0
  - chan_pjsip: Add PJSIPHangup dialplan app and manager action
  - bridge_simple: Suppress unchanged topology change requests
  - api.wiki.mustache: Fix indentation in generated markdown
  - res_pjsip_exten_state,res_pjsip_mwi: Allow unload on shutdown
  - logger.h: Add ability to change the prefix on SCOPE_TRACE output
  - Add libjwt to third-party
  - lock.c: Separate DETECT_DEADLOCKS from DEBUG_THREADS
  - asterisk.c: Use the euid's home directory to read/write cli history
  - file.c: Add ability to search custom dir for sounds
  - res_pjsip_pubsub: Add body_type to test_handler for unit tests
  - make_buildopts_h, et. al.  Allow adding all cflags to buildopts.h
  - func_periodic_hook: Don't truncate channel name
  - safe_asterisk: Change directory permissions to 755
  - ari-stubs: Fix more local anchor references
  - ari-stubs: Fix broken documentation anchors
  - alembic: Fix quoting of the 100rel column
  - download_externals:  Fix a few version related issues
  - pjproject_bundled: Increase PJSIP_MAX_MODULE to 38
  - Prepare master for Asterisk 22
  - app.h: Move declaration of ast_getdata_result before its first use
  - apply_patches: Sort patch list before applying
  - rest-api: Updates for new documentation site
  - rest-api: Ran make ari stubs to fix resource_endpoints inconsistency
  - test_statis_endpoints:  Fix channel_messages test again
  - test_stasis_endpoints.c: Make channel_messages more stable
  - build: Fix a few gcc 13 issues
  - Initial GitHub PRs
  - Initial GitHub Issue Templates
  - test.c: Fix counting of tests and add 2 new tests
  - make_version: Strip svn stuff and suppress ref HEAD errors
  - res_pjsip: Replace invalid UTF-8 sequences in callerid name
  - res_rtp_asterisk: Don't use double math to generate timestamps
  - res_rtp_asterisk: Asterisk Media Experience Score (MES)
  - Revert "res_rtp_asterisk: Asterisk Media Experience Score (MES)"
  - res_pjsip_transport_websocket: Add remote port to transport
  - res_rtp_asterisk: Asterisk Media Experience Score (MES)
  - pjsip_transport_events: Fix possible use after free on transport
  - runUnittests.sh:  Save coredumps to proper directory
  - chan_rtp: Make usage of ast_rtp_instance_get_local_address clearer
  - res_geolocation: Update wiki documentation
  - res_crypto: Memory issues and uninitialized variable errors
  - res_geolocation: Fix issues exposed by compiling with -O2
  - res_geolocation: Fix segfault when there's an empty element
  - res_geolocation: Add two new options to GEOLOC_PROFILE
  - res_geolocation:  Allow location parameters on the profile object
  - res_geolocation: Add profile parameter suppress_empty_ca_elements
  - res_geolocation:  Add built-in profiles
  - res_geolocation: Address user issues, remove complexity, plug leaks
  - Geolocation: Wiki Documentation
  - Update master branch for Asterisk 21

- #### Gitea (1):
  - res_pjsip_header_funcs: Duplicate new header value, don't copy.

- #### Henning Westerholt (3):
  - chan_pjsip: also return all codecs on empty re-INVITE for late offers (#59)
  - chan_pjsip: fix music on hold continues after INVITE with replaces
  - res_pjsip: return all codecs on a re-INVITE without SDP

- #### Henrik Liljedahl (1):
  - res_pjsip_sdp_rtp.c: Initial RTP inactivity check must consider the rtp_timeout setting.

- #### Holger Hans Peter Freyther (9):
  - ari/pjsip: Make it possible to control transfers through ARI
  - res_prometheus: Fix duplicate output of metric and help text
  - stasis: Update the snapshot after setting the redirect
  - ari: Provide the caller ID RDNIS for the channels
  - ari/stasis: Indicate progress before playback on a bridge
  - res_prometheus: Do not generate broken metrics
  - res_http_media_cache: Introduce options and customize
  - res_http_media_cache: Do not crash when there is no extension
  - res_prometheus: Do not crash on invisible bridges

- #### Igor Goncharovsky (7):
  - func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()
  - app_queue.c: Add new global 'log_unpause_on_reason_change'
  - app_waitforsilence.c: Use milliseconds to calculate timeout time
  - res_pjsip_path.c: Fix path when dialing using PJSIP_DIAL_CONTACTS()
  - res_pjsip_rfc3326: Add SIP causes support for RFC3326
  - res_pjsip: Fix path usage in case dialing with '@'
  - res_pjsip_outbound_registration: Allow to use multiple proxies for registration

- #### InterLinked1 (4):
  - chan_dahdi: Fix broken hidecallerid setting. (#101)
  - asterisk.c: Fix option warning for remote console. (#103)
  - res_pjsip_pubsub: Add new pubsub module capabilities. (#82)
  - say.c: Fix French time playback. (#42)

- #### Itzanh (1):
  - app_sms.c: Fix sending and receiving SMS messages in protocol 2

- #### Ivan Poddubny (2):
  - configs: Fix a misleading IPv6 ACL example in Named ACLs
  - asterisk.c: Fix sending incorrect messages to systemd notify

- #### Jaco Kroon (10):
  - res_musiconhold: Appropriately lock channel during start.
  - res_odbc: cache_size option to limit the cached connections.
  - res_odbc: cache_type option for res_odbc.
  - res_odbc: release threads from potential starvation.
  - configure:  Use . file rather than source file.
  - tcptls: when disabling a server port, we should set the accept_fd to -1.
  - configure: fix test code to match gethostbyname_r prototype. (#75)
  - res_calendar: output busy state as part of show calendar.
  - Build system: Avoid executable stack.
  - manager: be more aggressive about purging http sessions.

- #### James Terhune (1):
  - main/stasis_channels.c: Fix crash when setting a global variable with invalid UTF8 characters

- #### Jason D. McCormick (1):
  - install_prereq: Fix dependency install on aarch64.

- #### Jeremy Lainé (1):
  - docs: Fix minor typo in MixMonitor AMI action

- #### Jiajian Zhou (1):
  - AMI: Add parking position parameter to Park action

- #### Joe Garlick (3):
  - chan_websocket: Fixed Ping/Pong messages hanging up the websocket channel
  - chan_websocket.c: Tolerate other frame types
  - chan_websocket.c: Add DTMF messages

- #### Joe Searle (2):
  - pjproject: Increase maximum SDP formats and attribute limits
  - res_stasis.c: Add new type 'sdp_label' for bridge creation.

- #### Jose Lopes (1):
  - res_stasis_device_state: Fix delete ARI Devicestates after asterisk restart.

- #### Joshua C. Colp (22):
  - devicestate: Don't publish redundant device state messages.
  - endpoints: Remove need for stasis subscription.
  - app_queue: Allow stasis message filtering to work.
  - sorcery: Move from threadpool to taskpool.
  - taskpool: Update versions for taskpool stasis options.
  - taskpool: Add taskpool API, switch Stasis to using it.
  - channel: Always provide cause code in ChannelHangupRequest.
  - LICENSE: Update company name, email, and address.
  - utils: Make behavior of ast_strsep* match strsep.
  - Update issue guidelines link for bug reports.
  - variables: Add additional variable dialplan functions.
  - manager: Tolerate stasis messages with no channel snapshot.
  - audiohook: Unlock channel in mute if no audiohooks present.
  - app_queue: Add support for applying caller priority change immediately.
  - Update config.yml
  - LICENSE: Update link to trademark policy. (#44)
  - pbx_dundi: Fix PJSIP endpoint configuration check.
  - res_pjsip_aoc: Don't assume a body exists on responses.
  - ari: Destroy body variables in channel create.
  - res_agi: Respect "transmit_silence" option for "RECORD FILE".
  - res_pjsip_sdp_rtp: Skip formats without SDP details.
  - pjsip: Add TLS transport reload support for certificate and key.

- #### Joshua Elson (2):
  - fix: Correct default flag for tcp_keepalive_enable option
  - Implement Configurable TCP Keepalive Settings in PJSIP Transports

- #### Justin T. Gibbs (1):
  - rtp/rtcp: Configure dual-stack behavior via IPV6_V6ONLY

- #### Kent (1):
  - res_pjsip: Add new AOR option "qualify_2xx_only"

- #### Kristian F. Høgh (1):
  - app_queue.c: Only announce to head caller if announce_to_first_user

- #### Luz Paz (4):
  - docs: Fix typos in apps/
  - docs: Fix typos in cdr/ Found via codespell
  - docs: Fix various typos in channels/ Found via `codespell -q 3 -S "./CREDITS,*.po" -L abd,asent,atleast,cachable,childrens,contentn,crypted,dne,durationm,enew,exten,inout,leapyear,mye,nd,oclock,offsetp,ot,parm,parms,preceeding,pris,ptd,requestor,re-use,re-used,re-uses,ser,siz,slanguage,slin,thirdparty,varn,varns,ues`
  - docs: Fix various typos in main/ Found via `codespell -q 3 -S "./CREDITS" -L abd,asent,atleast,childrens,contentn,crypted,dne,durationm,exten,inout,leapyear,nd,oclock,offsetp,ot,parm,parms,requestor,ser,slanguage,slin,thirdparty,varn,varns,ues`

- #### Maksim Nesterov (1):
  - func_uuid: Add a new dialplan function to generate UUIDs

- #### Marcel Wagner (2):
  - res_pjsip: Fix typo in from_domain documentation
  - res_pjsip: Update contact_user to point out default

- #### Mark Murawski (2):
  - chan_pjsip:  Add the same details as PJSIPShowContacts to the CLI via 'pjsip show contact'
  - Remove files that are no longer updated

- #### Martin Nystroem (1):
  - res_ari.c: Add additional output to ARI requests when debug is enabled

- #### Martin Tomec (2):
  - chan_pjsip.c: Change SSRC after media source change
  - res_pjsip_refer.c: Allow GET_TRANSFERRER_DATA

- #### Matthew Fredrickson (2):
  - res_odbc.c: Allow concurrent access to request odbc connections
  - app_followme.c: Grab reference on nativeformats before using it

- #### Max Grobecker (1):
  - res_pjsip_geolocation: Add support for Geolocation loc-src parameter

- #### Maximilian Fridrich (13):
  - res_pjsip_messaging: Add support for following 3xx redirects
  - res_pjsip: Introduce redirect module for handling 3xx responses
  - chan_pjsip: Send VIDUPDATE RTP frame for all H.264 streams
  - res_pjsip_session: Reset pending_media_state->read_callbacks
  - res_pjsip_nat: Fix potential use of uninitialized transport details
  - app_dial: Add option "j" to preserve initial stream topology of caller
  - chan_rtp: Implement RTP glue for UnicastRTP channels
  - main/refer.c: Fix double free in refer_data_destructor + potential leak
  - core/ari/pjsip: Add refer mechanism
  - chan_pjsip: Allow topology/session refreshes in early media state (#74)
  - res_pjsip: mediasec: Add Security-Client headers after 401 (#49)
  - res_pjsip: Add mediasec capabilities.
  - res_pjsip: Add 100rel option "peer_supported".

- #### Michael Kuron (2):
  - manager: AOC-S support for AOCMessage
  - res_pjsip_aoc: New module for sending advice-of-charge with chan_pjsip

- #### Michal Hajek (2):
  - manager: fix double free of criteria variable when adding filter
  - audiohook.c: Improve frame pairing logic to avoid MixMonitor breakage with mixed codecs

- #### Miguel Angel Nubla (1):
  - configure: Makefile downloader enable follow redirects.

- #### Mike Bradeen (58):
  - ast_coredumper: check ast_debug_tools.conf permissions
  - ast_coredumper: create gdbinit file with restrictive permissions
  - res_sorcery_memory_cache: Reduce cache lock time for sorcery memory cache populate command
  - taskprocessors: Improve logging and add new cli options
  - res_pjsip_diversion: resolve race condition between Diversion header processing and redirect
  - res_pjsip_nat.c: Do not overwrite transfer host
  - chan_pjsip: Serialize INVITE creation on DTMF attended transfer
  - stasis/control.c: Set Hangup Cause to No Answer on Dial timeout
  - bridge_channel: don't set cause code on channel during bridge delete if already set
  - res_pjsip_sdp_rtp: Use negotiated DTMF Payload types on bitrate mismatch
  - Update version for Asterisk 22
  - res_pjsip_notify: add dialplan application
  - res_stasis: fix intermittent delays on adding channel to bridge
  - res_pjsip_sdp_rtp: Add support for default/mismatched 8K RFC 4733/2833 digits
  - rtp_engine: add support for multirate RFC2833 digits
  - app_chanspy: Add 'D' option for dual-channel audio
  - app_voicemail_odbc: remove macrocontext from voicemail_messages table
  - res_pjsip: disable raw bad packet logging
  - res_speech: allow speech to translate input channel
  - res_stasis: signal when new command is queued
  - res_pjsip: update qualify_timeout documentation with DNS note
  - res_speech_aeap: add aeap error handling
  - cel: add publish user event helper
  - func_periodic_hook: Add hangup step to avoid timeout
  - res_speech_aeap: check for null format on response
  - app_voicemail: Fix for loop declarations
  - Adds manager actions to allow move/remove/forward individual messages in a particular mailbox folder. The forward command can be used to copy a message within a mailbox or to another mailbox. Also adds a VoicemailBoxSummarry, required to retrieve message ID's.
  - app_voicemail: add CLI commands for message manipulation
  - app_voicemail: fix imap compilation errors
  - res_musiconhold: avoid moh state access on unlocked chan
  - utils: add lock timestamps for DEBUG_THREADS
  - indications: logging changes
  - cel: add local optimization begin event (#54)
  - res_pjsip_pubsub: subscription cleanup changes
  - bridge_builtin_features: add beep via touch variable
  - res_mixmonitor: MixMonitorMute by MixMonitor ID
  - format_sln: add .slin as supported file extension
  - cli: increase channel column width
  - app_read: Add an option to return terminator on empty digits.
  - app_directory: Add a 'skip call' option.
  - app_senddtmf: Add option to answer target channel.
  - res_pjsip: Prevent SEGV in pjsip_evsub_send_request
  - res_pjsip: Upgraded bundled pjsip to 2.13
  - app_directory: add ability to specify configuration file
  - res_monitor: Remove deprecated module.
  - app_macro: Remove deprecated module.
  - chan_sip: Remove deprecated module.
  - chan_alsa: Remove deprecated module.
  - chan_mgcp: Remove deprecated module.
  - app_osplookup: Remove deprecated module.
  - chan_skinny: Remove deprecated module.
  - manager: prevent file access outside of config dir
  - res_pjsip: prevent crash on websocket disconnect
  - audiohook: add directional awareness
  - res_pjsip: Add user=phone on From and PAID for usereqphone=yes
  - alembic: add missing ps_endpoints columns
  - CI: Fixing path issue on venv check
  - CI: use Python3 virtual environment

- #### Mike Pultz (3):
  - res_curl.conf.sample: clean up sample configuration and add new SSL options
  - manager.c: Add Processed Call Count to CoreStatus output
  - func_curl.c: Add additional CURL options for SSL requests

- #### MikeNaso (1):
  - res_pjsip.c: Set contact_user on incoming call local Contact header

- #### Nathan Bruning (1):
  - app_queue: Add force_longest_waiting_caller option.

- #### Nathan Monfils (2):
  - manager.c: Fix presencestate object leak
  - manager.c: Invalid ref-counting when purging events

- #### Nathaniel Wesley Filardo (1):
  - configure.ac: use AC_PATH_TOOL for nm

- #### Naveen Albert (201):
  - chan_dahdi.conf.sample: Avoid warnings with default configs.
  - app_reload: Fix Reload() without arguments.
  - pbx.c: Print new context count when reloading dialplan.
  - app_disa: Avoid use of removed ResetCDR() option.
  - func_callerid: Document limitation of DNID fields.
  - func_channel: Allow R/W of ADSI CPE capability setting.
  - core_unreal: Preserve ADSI capability when dialing Local channels.
  - sig_analog: Allow '#' to end the inter-digit timeout when dialing.
  - func_math: Add DIGIT_SUM function.
  - app_sf: Add post-digit timer option to ReceiveSF.
  - codec_builtin.c: Adjust some of the quality scores to reflect reality.
  - res_tonedetect: Fix formatting of XML documentation.
  - res_fax: Add XML documentation for channel variables.
  - app_dial: Allow fractional seconds for dial timeouts.
  - dsp.c: Make minor fixes to debug log messages.
  - config_options.c: Improve misleading warning.
  - func_scramble: Add example to XML documentation.
  - sig_analog: Eliminate potential timeout with Last Number Redial.
  - chan_dahdi: Add DAHDI_CHANNEL function.
  - app_adsiprog: Fix possible NULL dereference.
  - res_cliexec: Remove unnecessary casts to char*.
  - pbx_variables.c: Create real channel for "dialplan eval function".
  - pbx_builtins: Allow custom tone for WaitExten.
  - res_tonedetect: Add option for TONE_DETECT detection to auto stop.
  - sig_analog: Skip Caller ID spill if usecallerid=no.
  - chan_dahdi: Fix erroneously persistent dialmode.
  - sig_analog: Fix SEGV due to calling strcmp on NULL.
  - dsp.c: Improve debug logging in tone_detect().
  - app_chanspy: Add option to not automatically answer channel.
  - func_frame_drop: Add debug messages for dropped frames.
  - test_res_prometheus: Fix compilation failure on Debian 13.
  - func_frame_drop: Handle allocation failure properly.
  - bridge.c: Obey BRIDGE_NOANSWER variable to skip answering channel.
  - func_curl: Allow auth methods to be set.
  - app_agent_pool: Remove documentation for removed option.
  - ast_tls_cert: Make certificate validity configurable.
  - sig_analog: Properly handle STP, ST2P, and ST3P for fgccamamf.
  - app_record: Add RECORDING_INFO function.
  - sig_analog: Add Call Waiting Deluxe support.
  - app_sms: Ignore false positive vectorization warning.
  - res_pjsip_caller_id: Also parse URI parameters for ANI2.
  - app_meetme: Remove inaccurate removal version from xmldocs.
  - chan_iax2: Minor improvements to documentation and warning messages.
  - utils: Disable old style definition warnings for libdb.
  - ast_tls_cert: Add option to skip passphrase for CA private key.
  - chan_iax2: Avoid unnecessarily backlogging non-voice frames.
  - sig_analog: Add Last Number Redial feature.
  - chan_dahdi: Fix wrong channel state when RINGING recieved.
  - chan_iax2: Add log message for rejected calls.
  - sig_analog: Fix regression with FGD and E911 signaling.
  - func_evalexten: Add EVAL_SUB function.
  - app_dial: Fix progress timeout calculation with no answer timeout.
  - app_dial: Fix progress timeout.
  - chan_dahdi: Never send MWI while off-hook.
  - main, res, tests: Fix compilation errors on FreeBSD.
  - astfd.c: Avoid calling fclose with NULL argument.
  - app_voicemail: Fix ill-formatted pager emails with custom subject.
  - res_pjsip_logger: Preserve logging state on reloads.
  - logger: Add unique verbose prefixes for levels 5-10.
  - say.c: Fix cents off-by-one due to floating point rounding.
  - loader.c: Allow dependent modules to be unloaded recursively.
  - callerid.c: Parse previously ignored Caller ID parameters.
  - file.c, channel.c: Don't emit warnings if progress received.
  - func_callerid: Emit warning if invalid redirecting reason set.
  - chan_dahdi: Add DAHDIShowStatus AMI action.
  - chan_dahdi: Don't retry opening nonexistent channels on restart.
  - menuselect: Minor cosmetic fixes.
  - pbx_variables.c: Prevent SEGV due to stack overflow.
  - manager.c: Add CLI command to kick AMI sessions.
  - chan_dahdi: Allow specifying waitfordialtone per call.
  - res_parking: Fail gracefully if parking lot is full.
  - app_dial: Add dial time for progress/ringing.
  - app_voicemail: Properly reinitialize config after unit tests.
  - app_voicemail: Allow preventing mark messages as urgent.
  - dsp.c: Fix and improve potentially inaccurate log message.
  - configure: Rerun bootstrap on modern platform.
  - app_if: Fix next priority calculation.
  - manager.c: Fix erroneous reloads in UpdateConfig.
  - res_calendar_icalendar: Print iCalendar error on parsing failure.
  - chan_dahdi: Allow MWI to be manually toggled on channels.
  - logger: Fix linking regression.
  - func_frame_trace: Add CLI command to dump frame queue.
  - menuselect: Use more specific error message.
  - app_if: Fix faulty EndIf branching.
  - manager.c: Fix regression due to using wrong free function.
  - config_options.c: Fix truncation of option descriptions.
  - manager.c: Improve clarity of "manager show connected".
  - general: Fix broken links.
  - sig_analog: Fix channel leak when mwimonitor is enabled.
  - func_channel: Expose previously unsettable options.
  - func_lock: Add missing see-also refs to documentation.
  - configs: Improve documentation for bandwidth in iax.conf.
  - logger: Add channel-based filtering.
  - chan_dahdi: Warn if nonexistent cadence is requested.
  - app_directory: Add ADSI support to Directory.
  - core_local: Fix local channel parsing with slashes.
  - app_voicemail: Add AMI event for mailbox PIN changes.
  - res_pjsip: Include cipher limit in config error message.
  - chan_dahdi: Clarify scope of callgroup/pickupgroup.
  - app_voicemail: Disable ADSI if unavailable.
  - chan_console: Fix deadlock caused by unclean thread exit.
  - chan_iax2: Improve authentication debugging.
  - app_dial: Fix infinite loop when sending digits.
  - pbx.c: Fix gcc 12 compiler warning.
  - sig_analog: Add Called Subscriber Held capability.
  - res_pjsip_header_funcs: Make prefix argument optional.
  - chan_dahdi: Allow autoreoriginating after hangup.
  - sig_analog: Allow three-way flash to time out to silence.
  - users.conf: Deprecate users.conf configuration.
  - sig_analog: Allow immediate fake ring to be suppressed.
  - res_musiconhold: Add option to loop last file.
  - chan_dahdi: Fix Caller ID presentation for FXO ports.
  - sig_analog: Add fuller Caller ID support.
  - callerid: Allow specifying timezone for date/time.
  - logrotate: Fix duplicate log entries.
  - app_sla: Migrate SLA applications out of app_meetme.
  - chan_dahdi: Add dialmode option for FXS lines.
  - res_pjsip_stir_shaken: Fix JSON field ordering and disallowed TN characters.
  - pbx_dundi: Add PJSIP support.
  - voicemail.conf: Fix incorrect comment about #include.
  - app_queue: Fix minor xmldoc duplication and vagueness.
  - app_osplookup: Remove obsolete sample config.
  - func_json: Fix JSON parsing issues.
  - app_dial: Fix DTMF not relayed to caller on unanswered calls.
  - app_senddtmf: Add SendFlash AMI action.
  - chan_iax2: Fix jitterbuffer regression prior to receiving audio.
  - app_signal: Add signaling applications
  - func_json: Enhance parsing capabilities of JSON_DECODE
  - res_pjsip_session: Add overlap_context option.
  - loader: Allow declined modules to be unloaded.
  - app_broadcast: Add Broadcast application
  - func_frame_trace: Print text for text frames.
  - app_cdr: Remove deprecated application and option.
  - manager: Fix appending variables.
  - json.h: Add ast_json_object_real_get.
  - pbx_app: Update outdated pbx_exec channel snapshots.
  - res_pjsip_session: Use Caller ID for extension matching.
  - pbx_builtins: Remove deprecated and defunct functionality.
  - app_voicemail_odbc: Fix string overflow warning.
  - func_callerid: Warn about invalid redirecting reason.
  - app_sendtext: Remove references to removed applications.
  - app_if: Fix format truncation errors.
  - res_hep: Add support for named capture agents.
  - app_if: Adds conditional branch applications
  - res_pjsip_session.c: Map empty extensions in INVITEs to s.
  - res_pjsip_header_funcs: Add custom parameter support.
  - app_voicemail: Fix missing email in msg_create_from_file.
  - res_adsi: Fix major regression caused by media format rearchitecture.
  - func_presencestate: Fix invalid memory access.
  - sig_analog: Fix no timeout duration.
  - xmldoc: Allow XML docs to be reloaded.
  - rtp_engine.h: Update examples using ast_format_set.
  - app_mixmonitor: Add option to use real Caller ID for voicemail.
  - pbx_builtins: Allow Answer to return immediately.
  - chan_dahdi: Allow FXO channels to start immediately.
  - sla: Prevent deadlock and crash due to autoservicing.
  - func_json: Fix memory leak.
  - test_json: Remove duplicated static function.
  - file.c: Don't emit warnings on winks.
  - app_mixmonitor: Add option to delete files on exit.
  - translate.c: Prefer better codecs upon translate ties.
  - manager: Update ModuleCheck documentation.
  - tcptls: Prevent crash when freeing OpenSSL errors.
  - tests: Fix compilation errors on 32-bit.
  - res_pjsip_notify: Add option support for AMI.
  - res_pjsip_logger: Add method-based logging option.
  - chan_dahdi: Fix unavailable channels returning busy.
  - res_pjsip_pubsub: Prevent removing subscriptions.
  - say: Don't prepend ampersand erroneously.
  - cdr: Allow bridging and dial state changes to be ignored.
  - res_tonedetect: Add ringback support to TONE_DETECT.
  - chan_dahdi: Resolve format truncation warning.
  - db: Fix incorrect DB tree count for AMI.
  - res_pjsip_geolocation: Change some notices to debugs.
  - func_logic: Don't emit warning if both IF branches are empty.
  - features: Add no answer option to Bridge.
  - app_bridgewait: Add option to not answer channel.
  - app_amd: Add option to play audio during AMD.
  - func_export: Add EXPORT function
  - func_scramble: Fix null pointer dereference.
  - func_strings: Add trim functions.
  - func_frame_trace: Remove bogus assertion.
  - lock.c: Add AMI event for deadlocks.
  - app_confbridge: Add end_marked_any option.
  - pbx_variables: Use const char if possible.
  - cli: Prevent assertions on startup from bad ao2 refs.
  - res_tonedetect: Fix typos referring to wrong variables.
  - features: Add transfer initiation options.
  - general: Very minor coding guideline fixes.
  - chan_iax2: Add missing options documentation.
  - app_confbridge: Fix memory leak on updated menu options.
  - manager: Remove documentation for nonexistent action.
  - cdr.conf: Remove obsolete app_mysql reference.
  - general: Remove obsolete SVN references.
  - app_meetme: Add missing AMI documentation.
  - general: Improve logging levels of some log messages.
  - app_confbridge: Add missing AMI documentation.
  - func_srv: Document field parameter.
  - pbx_functions.c: Manually update ast_str strlen.
  - manager: Fix incomplete filtering of AMI events.
  - db: Add AMI action to retrieve DB keys at prefix.

- #### Nick French (1):
  - pjproject_bundled: fix cross-compilation with ssl libs

- #### Niklas Larsson (1):
  - app_queue: Preserve reason for realtime queues

- #### Norm Harrison (2):
  - asterisk/channel.h: fix documentation for 'ast_waitfor_nandfds()'
  - audiosocket: fix timeout, fix dialplan app exit, server address in logs

- #### Olaf Titz (1):
  - app_voicemail_imap: Fix message count when IMAP server is unavailable

- #### Peter Fern (1):
  - streams:  Ensure that stream is closed in ast_stream_and_wait on error

- #### Peter Jannesen (3):
  - action_redirect: remove after_bridge_goto_info
  - channel: Preserve CHANNEL(userfield) on masquerade.
  - cel_custom: Allow absolute filenames.

- #### Peter Krall (1):
  - res/ari/resource_bridges.c: Normalize channel_format ref handling for bridge media

- #### PeterHolik (2):
  - chan_rtp.c: MulticastRTP missing refcount without codec option
  - chan_rtp.c: Change MulticastRTP nameing to avoid memory leak

- #### Philip Prindeville (12):
  - res_crypto: handle unsafe private key files
  - res_crypto: don't modify fname in try_load_key()
  - res_crypto: use ast_file_read_dirs() to iterate
  - test: initialize capture structure before freeing
  - res_crypto: don't complain about directories
  - res_crypto: Use EVP API's instead of legacy API's
  - test: Add coverage for res_crypto
  - res_crypto: make keys reloadable on demand for testing
  - test: Add test coverage for capture child process output
  - main/utils: allow checking for command in $PATH
  - test: Add ability to capture child process output
  - res_crypto: Don't load non-regular files in keys directory

- #### Roman Pertsev (1):
  - res_audiosocket: fix temporarily unavailable

- #### Samuel Olaechea (1):
  - configs: Fix typo in pjsip.conf.sample.

- #### Sean Bright (122):
  - asterisk.c: Use C.UTF-8 locale instead of relying on user's environment.
  - cli.c: Allow 'channel request hangup' to accept patterns.
  - asterisk.c: Allow multi-byte characters on the Asterisk CLI.
  - func_presencestate.c: Allow `NOT_SET` to be set from CLI.
  - func_talkdetect.c: Remove reference to non-existent variables.
  - cel: Add missing manager documentation.
  - res_odbc: Use SQL_SUCCEEDED() macro where applicable.
  - http.c: Include remote address in URI handler message.
  - Revert "func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()"
  - cel_manager.c: Correct manager event mask for CEL events.
  - app_queue.c: Update docs to correct QueueMemberPause event name.
  - app_stream_echo.c: Check that stream is non-NULL before dereferencing.
  - abstract_jb.c: Remove redundant timer check per static analysis.
  - chan_websocket: Fix crash on DTMF_END event.
  - app_dtmfstore: Avoid a potential buffer overflow.
  - main: Explicitly mark case statement fallthrough as such.
  - bridge_softmix: Return early on topology allocation failure.
  - bridge_simple: Increase code verbosity for clarity.
  - safe_asterisk: Resolve a POSIX sh problem and restore globbing behavior.
  - app_externalivr: Prevent out-of-bounds read during argument processing.
  - audiohook.c: Ensure correct AO2 reference is dereffed.
  - res_musiconhold.c: Ensure we're always locked around music state access.
  - res_musiconhold.c: Annotate when the channel is locked.
  - channelstorage_makeopts.xml: Remove errant XML character.
  - res_pjsip: Fix empty `ActiveChannels` property in AMI responses.
  - app_confbridge: Prevent crash when publishing channel-less event.
  - res_config_curl.c: Remove unnecessary warnings.
  - res_rtp_asterisk.c: Don't truncate spec-compliant `ice-ufrag` or `ice-pwd`.
  - docs: AMI documentation fixes.
  - res_rtp_asterisk.c: Use correct timeout value for T.140 RED timer.
  - channel.c: Remove dead AST_GENERATOR_FD code.
  - docs: Indent <since> tags.
  - res_prometheus.c: Set Content-Type header on /metrics response.
  - strings.c: Improve numeric detection in `ast_strings_match()`.
  - dialplan_functions_doc.xml: Document PJSIP_MEDIA_OFFER's `media` argument.
  - manager: Add `<since>` tags for all AMI actions.
  - manager.c: Rename restrictedFile to is_restricted_file.
  - config.c: Fix off-nominal reference leak.
  - res_pjsip.c: Fix Contact header rendering for IPv6 addresses.
  - Revert "res_rtp_asterisk: Count a roll-over of the sequence number even on lost packets."
  - func_base64.c: Ensure we set aside enough room for base64 encoded data.
  - alembic: Drop redundant voicemail_messages index.
  - res_agi.c: Ensure SIGCHLD handler functions are properly balanced.
  - cdr_custom: Allow absolute filenames.
  - res_pjsip_pubsub: Persist subscription 'generator_data' in sorcery
  - res_pjsip_logger.c: Fix 'OPTIONS' tab completion.
  - alembic: Make 'revises' header comment match reality.
  - logger.h: Include SCOPE_CALL_WITH_INT_RESULT() in non-dev-mode builds.
  - pjsip: Add PJSIP_PARSE_URI_FROM dialplan function.
  - manager.c: Properly terminate `CoreShowChannelMap` event.
  - xml.c: Update deprecated libxml2 API usage.
  - asterisk.c: Don't log an error if .asterisk_history does not exist.
  - bundled_pjproject: Disable UPnP support.
  - file.h: Rename function argument to avoid C++ keyword clash.
  - app_queue.c: Properly handle invalid strategies from realtime.
  - alembic: Correct NULLability of PJSIP id columns.
  - cli.c: `core show channels concise` is not really deprecated.
  - alembic: Fix compatibility with SQLAlchemy 2.0+.
  - res_config_mysql.c: Support hostnames up to 255 bytes.
  - res_pjsip: Fix alembic downgrade for boolean columns.
  - alembic: Quote new MySQL keyword 'qualify.'
  - res_pjsip: Use consistent type for boolean columns.
  - strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.
  - res_pjsip_t38.c: Permit IPv6 SDP connection addresses.
  - res_pjsip_session.c: Correctly format SDP connection addresses.
  - rtp_engine.c: Correct sample rate typo for L16/44100.
  - app_confbridge: Don't emit warnings on valid configurations.
  - make_xml_documentation: Really collect LOCAL_MOD_SUBDIRS documentation.
  - pbx_config.c: Don't crash when unloading module.
  - logger.c: Move LOG_GROUP documentation to dedicated XML file.
  - res_pjsip_header_funcs.c: Check URI parameter length before copying.
  - config.c: Log #exec include failures.
  - make_xml_documentation: Properly handle absolute LOCAL_MOD_SUBDIRS.
  - app_voicemail.c: Completely resequence mailbox folders.
  - res_rtp_asterisk.c: Update for OpenSSL 3+.
  - alembic: Update list of TLS methods available on ps_transports.
  - app.c: Allow ampersands in playback lists to be escaped.
  - uri.c: Simplify ast_uri_make_host_with_port()
  - func_curl.c: Remove CURLOPT() plaintext documentation.
  - res_http_websocket.c: Set hostname on client for certificate validation.
  - live_ast: Add astcachedir to generated asterisk.conf.
  - chan_iax2.c: Don't send unsanitized data to the logger.
  - resource_channels.c: Explicit codec request when creating UnicastRTP.
  - doc: Update IP Quality of Service links.
  - chan_iax2.c: Ensure all IEs are displayed when dumping frame contents.
  - app_queue.c: Emit unpause reason with PauseQueueMember event.
  - res_rtp_asterisk.c: Fix memory leak in ephemeral certificate creation.
  - res_pjsip_dtmf_info.c: Add 'INFO' to Allow header.
  - pjsip_configuration.c: Disable DTLS renegotiation if WebRTC is enabled.
  - func_curl.c: Ensure channel is locked when manipulating datastores.
  - res_stasis_recording.c: Save recording state when unmuted.
  - extconfig: Allow explicit DB result set ordering to be disabled.
  - res_pjsip: Enable TLS v1.3 if present.
  - extensions.conf.sample: Remove reference to missing context.
  - func_export: Use correct function argument as variable name.
  - chan_iax2.c: Avoid crash with IAX2 switch support.
  - res_geolocation: Ensure required 'location_info' is present.
  - apply_patches: Use globbing instead of file/sort.
  - res_pjsip_rfc3326: Prefer Q.850 cause code over SIP.
  - pjsip_transport_events.c: Use %zu printf specifier for size_t.
  - res_crypto.c: Gracefully handle potential key filename truncation.
  - configure: Remove obsolete and deprecated constructs.
  - ast-db-manage: Synchronize revisions between comments and code.
  - res_crypto.c: Avoid using the non-portable ALLPERMS macro.
  - ast-db-manage: Fix alembic branching error caused by #122.
  - sounds: Update download URL to use HTTPS.
  - res_pjsip_pubsub.c: Use pjsip version for pending NOTIFY check. (#47)
  - utils.h: Deprecate `ast_gethostbyname()`. (#79)
  - xml.c: Process XML Inclusions recursively. (#69)
  - core: Cleanup gerrit and JIRA references. (#58)
  - ael: Regenerate lexers and parsers.
  - loader.c: Minor module key check simplification.
  - res_agi: RECORD FILE plays 2 beeps.
  - contrib: rc.archlinux.asterisk uses invalid redirect.
  - test.c: Avoid passing -1 to FD_* family of functions.
  - test_crypto.c: Fix getcwd(…) build error.
  - app_queue: Minor docs and logging fixes for UnpauseQueueMember.
  - app_queue: Reset all queue defaults before reload.
  - doxygen: Fix doxygen errors.
  - app_playback.c: Fix PLAYBACKSTATUS regression.
  - res_pjsip_logger: Add method-based logging option.
  - chan_dahdi.c: Resolve a format-truncation build warning.
  - channel.h: Remove redundant declaration.

- #### Sebastian Jennen (1):
  - translate.c: implement new direct comp table mode

- #### Sergey V. Lobanov (1):
  - build: fix bininstall launchd issue on cross-platform build

- #### Shaaah (1):
  - app_queue.c : fix "queue add member" usage string

- #### Shyju Kanaprath (1):
  - README.md: Removed outdated link

- #### Sperl Viktor (5):
  - cel: Add STREAM_BEGIN, STREAM_END and DTMF event types.
  - res_agi: Increase AGI command buffer size from 2K to 8K
  - app_queue: indicate the paused state of a dynamically added member in queue_log.
  - app_queue: allow dynamically adding a queue member in paused state.
  - res_pjsip_endpoint_identifier_ip: Endpoint identifier request URI

- #### Spiridonov Dmitry (1):
  - sorcery.c: Fixed crash error when executing "module reload"

- #### Stanislav Abramenkov (6):
  - bundled_pjproject: Avoid deadlock between transport and transaction
  - jansson: Upgrade version to jansson 2.14.1
  - res_pjproject: Fix typo (OpenmSSL->OpenSSL)
  - Upgrade bundled pjproject to 2.15.1 Resolves: asterisk#1016
  - Upgrade bundled pjproject to 2.14.1
  - pjsip: Upgrade bundled version to pjproject 2.13.1

- #### Steffen Arntz (1):
  - logger.c fix: malformed JSON template

- #### Stuart Henderson (1):
  - app_queue: fix comparison for announce-position-only-up

- #### Sven Kube (8):
  - res_pjsip_refer: don't defer session termination for ari transfer
  - res_audiosocket: add message types for all slin sample rates
  - stasis_channels.c: Make protocol_id optional to enable blind transfer via ari
  - stasis_channels.c: Add null check for referred_by in ast_ari_transfer_message_create
  - ARI: Add command to indicate progress to a channel
  - resource_channels.c: Don't call ast_channel_get_by_name on empty optional arguments
  - res_audiosocket.c: Add retry mechanism for reading data from AudioSocket
  - res_audiosocket.c: Set the TCP_NODELAY socket option

- #### ThatTotallyRealMyth (1):
  - safe_asterisk: Add ownership checks for /etc/asterisk/startup.d and its files.

- #### The_Blode (1):
  - install_prereq: Add Linux Mint support.

- #### Thomas B. Clark (1):
  - menuselect: Fix GTK menu callbacks for Fedora 42 compatibility

- #### Thomas Guebels (2):
  - pjsip_transport_events: handle multiple addresses for a domain
  - pjsip_transport_events: Avoid monitor destruction

- #### Tinet-mucw (11):
  - app_mixmonitor.c: Fix crash in mixmonitor_ds_remove_and_free when datastore is NULL
  - core_unreal.c: Use ast instead of p->chan to get the DIALSTATUS variable
  - iostream.c: Handle TLS handshake attacks in order to resolve the issue of exceeding the maximum number of HTTPS sessions.
  - pbx.c: When the AST_SOFTHANGUP_ASYNCGOTO flag is set, pbx_extension_helper should return directly.
  - pbx.c: when set flag AST_SOFTHANGUP_ASYNCGOTO, ast_explicit_goto should return -1.
  - audiohook.c: resolving the issue with audiohook both reading when packet loss on one side of the call
  - app_chanspy.c: resolving the issue writing frame to whisper audiohook.
  - app_chanspy.c: resolving the issue with audiohook direction read
  - res_pjsip_sdp_rtp.c: Fix DTMF Handling in Re-INVITE with dtmf_mode set to auto
  - bridge_basic.c: Make sure that ast_bridge_channel is not destroyed while iterating over bridge->channels. From the gdb information, we can see that while iterating over bridge->channels, the ast_bridge_channel reference count is 0, indicating it has already been destroyed.Additionally, when ast_bridge_channel is removed from bridge->channels, the bridge is first locked. Therefore, locking the bridge before iterating over bridge->channels can resolve the race condition.
  - res_pjsip_transport_websocket: Prevent transport from being destroyed before message finishes.

- #### Vitezslav Novy (1):
  - res_rtp_asterisk: fix wrong counter management in ioqueue objects

- #### Walter Doekes (1):
  - chan_ooh323: Fix R/0 typo in docs

- #### Zhai Liangliang (1):
  - Update config.guess and config.sub

- #### alex2grad (1):
  - app_followme: fix issue with enable_callee_prompt=no (#88)

- #### chrsmj (2):
  - samples: remove and/or change some wiki mentions
  - cdr_pgsql: Fix crash when the module fails to load multiple times.

- #### cmaj (2):
  - app_speech_utils.c: Allow partial speech results.
  - res_phoneprov.c: Multihomed SERVER cache prevention

- #### fabriziopicconi (1):
  - rtp.conf.sample: Correct stunaddr example.

- #### gauravs456 (1):
  - chan_websocket: Add channel_id to MEDIA_START, DRIVER_STATUS and DTMF_END events.

- #### gibbz00 (1):
  - feat: ARI "ChannelToneDetected" event

- #### jiangxc (1):
  - res_agi.c: Prevent possible double free during `SPEECH RECOGNIZE`

- #### jonatascalebe (1):
  - manager.c: Add new parameter 'PreDialGoSub' to Originate AMI action

- #### kodokaii (1):
  - chan_websocket: Reset frame_queue_length to 0 after FLUSH_MEDIA

- #### mkmer (3):
  - utils.h: Add rounding to float conversion to int.
  - frame.c: validate frame data length is less than samples when adjusting volume
  - audiohook.c: Add ability to adjust volume with float

- #### phoneben (10):
  - Add comment to asterisk.conf.sample clarifying that template sections are ignored
  - Disable device state caching for ephemeral channels
  - Fix false null-deref warning in channel_state
  - channelstorage_cpp: Fix fallback return value in channelstorage callback
  - stasis: switch stasis show topics temporary container from list - RBtree
  - res_fax.c: lower FAXOPT read warning to debug level
  - app_queue: Add NULL pointer checks in app_queue
  - app_queue: queue rules – Add support for QUEUE_RAISE_PENALTY=rN to raise penalties only for members within min/max range
  - Add log-caller-id-name option to log Caller ID Name in queue log
  - func_cut: Add example to documentation.

- #### romryz (1):
  - res_rtp_asterisk.c: Correct coefficient in MOS calculation.

- #### sarangr7 (1):
  - main/dial.c: Set channel hangup cause on timeout in handle_timeout_trip

- #### sungtae kim (3):
  - res_pjsip: Expanding PJSIP endpoint ID and relevant resource length to 255 characters
  - res_stasis_snoop: Fix snoop crash
  - res_musiconhold: Add option to not play music on hold on unanswered channels

- #### zhengsh (3):
  - app_audiosocket: Fixed timeout with -1 to avoid busy loop.
  - res_rtp_asterisk: Move ast_rtp_rtcp_report_alloc using `rtp->themssrc_valid` into the scope of the rtp_instance lock.
  - res_sorcery_memory_cache.c: Fix memory leak (#56)

- #### zhou_jiajian (2):
  - cdr: add CANCEL dispostion in CDR
  - res_fax_spandsp.c: Clean up a spaces/tabs issue

### Commit List:

-  Initial commit for certified-22.8
-  xml.c: Replace XML_PARSE_NOENT with XML_PARSE_NONET for xmlReadFile.
-  ast_coredumper: check ast_debug_tools.conf permissions
-  http.c: Change httpstatus to default disabled and sanitize output.
-  ast_coredumper: create gdbinit file with restrictive permissions
-  asterisk.c: Use C.UTF-8 locale instead of relying on user's environment.
-  chan_websocket.conf.sample: Fix category name.
-  chan_websocket: Fixed Ping/Pong messages hanging up the websocket channel
-  cli.c: Allow 'channel request hangup' to accept patterns.
-  res_sorcery_memory_cache: Reduce cache lock time for sorcery memory cache populate command
-  Add comment to asterisk.conf.sample clarifying that template sections are ignored
-  chan_websocket: Use the channel's ability to poll fds for the websocket read.
-  asterisk.c: Allow multi-byte characters on the Asterisk CLI.
-  func_presencestate.c: Allow `NOT_SET` to be set from CLI.
-  res/ari/resource_bridges.c: Normalize channel_format ref handling for bridge media
-  res_geolocation:  Fix multiple issues with XML generation.
-  stasis/control.c: Add destructor to timeout_datastore.
-  func_talkdetect.c: Remove reference to non-existent variables.
-  configure.ac: use AC_PATH_TOOL for nm
-  res_pjsip_mwi: Fix off-nominal endpoint ao2 ref leak in mwi_get_notify_data
-  res_pjsip_messaging: Add support for following 3xx redirects
-  res_pjsip: Introduce redirect module for handling 3xx responses
-  app_mixmonitor.c: Fix crash in mixmonitor_ds_remove_and_free when datastore is NULL
-  res_pjsip_refer: don't defer session termination for ari transfer
-  chan_dahdi.conf.sample: Avoid warnings with default configs.
-  main/dial.c: Set channel hangup cause on timeout in handle_timeout_trip
-  cel: Add missing manager documentation.
-  res_odbc: Use SQL_SUCCEEDED() macro where applicable.
-  rtp/rtcp: Configure dual-stack behavior via IPV6_V6ONLY
-  http.c: Include remote address in URI handler message.
-  Disable device state caching for ephemeral channels
-  chan_websocket: Add locking in send_event and check for NULL websocket handle.
-  Fix false null-deref warning in channel_state
-  endpoint.c: Plug a memory leak in ast_endpoint_shutdown().
-  Revert "func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()"
-  cel_manager.c: Correct manager event mask for CEL events.
-  app_queue.c: Update docs to correct QueueMemberPause event name.
-  taskprocessors: Improve logging and add new cli options
-  manager: fix double free of criteria variable when adding filter
-  app_stream_echo.c: Check that stream is non-NULL before dereferencing.
-  abstract_jb.c: Remove redundant timer check per static analysis.
-  channelstorage_cpp: Fix fallback return value in channelstorage callback
-  ccss:  Add option to ccss.conf to globally disable it.
-  app_directed_pickup.c: Change some log messages from NOTICE to VERBOSE.
-  chan_websocket: Fix crash on DTMF_END event.
-  chan_websocket.c: Tolerate other frame types
-  app_reload: Fix Reload() without arguments.
-  pbx.c: Print new context count when reloading dialplan.
-  Makefile: Add module-list-* targets.
-  app_disa: Avoid use of removed ResetCDR() option.
-  core_unreal.c: Use ast instead of p->chan to get the DIALSTATUS variable
-  ast_coredumper: Fix multiple issues
-  app_mixmonitor: Add 's' (skip) option to delay recording.
-  stasis: switch stasis show topics temporary container from list - RBtree
-  app_dtmfstore: Avoid a potential buffer overflow.
-  main: Explicitly mark case statement fallthrough as such.
-  bridge_softmix: Return early on topology allocation failure.
-  bridge_simple: Increase code verbosity for clarity.
-  app_queue.c: Only announce to head caller if announce_to_first_user
-  chan_websocket: Add ability to place a MARK in the media stream.
-  chan_websocket: Add capability for JSON control messages and events.
-  build: Add menuselect options to facilitate code tracing and coverage
-  channelstorage:  Allow storage driver read locking to be skipped.
-  res_audiosocket: fix temporarily unavailable
-  safe_asterisk: Resolve a POSIX sh problem and restore globbing behavior.
-  res_stir_shaken: Add STIR_SHAKEN_ATTESTATION dialplan function.
-  iostream.c: Handle TLS handshake attacks in order to resolve the issue of exceeding the maximum number of HTTPS sessions.
-  chan_pjsip: Disable SSRC change for WebRTC endpoints.
-  chan_websocket: Add channel_id to MEDIA_START, DRIVER_STATUS and DTMF_END events.
-  safe_asterisk:  Fix logging and sorting issue.
-  Fix Endianness detection in utils.h for non-Linux
-  app_queue.c: Fix error in Queue parameter documentation.
-  devicestate: Don't publish redundant device state messages.
-  chan_pjsip: Add technology-specific off-nominal hangup cause to events.
-  res_audiosocket: add message types for all slin sample rates
-  res_fax.c: lower FAXOPT read warning to debug level
-  endpoints: Remove need for stasis subscription.
-  app_queue: Allow stasis message filtering to work.
-  taskpool:  Fix some references to threadpool that should be taskpool.
-  Update contact information for anthm
-  chan_websocket.c: Change payload references to command instead.
-  func_callerid: Document limitation of DNID fields.
-  func_channel: Allow R/W of ADSI CPE capability setting.
-  core_unreal: Preserve ADSI capability when dialing Local channels.
-  func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()
-  sig_analog: Allow '#' to end the inter-digit timeout when dialing.
-  func_math: Add DIGIT_SUM function.
-  app_sf: Add post-digit timer option to ReceiveSF.
-  codec_builtin.c: Adjust some of the quality scores to reflect reality.
-  res_tonedetect: Fix formatting of XML documentation.
-  res_fax: Add XML documentation for channel variables.
-  channelstorage_cpp_map_name_id: Add read locking around retrievals.
-  app_dial: Allow fractional seconds for dial timeouts.
-  dsp.c: Make minor fixes to debug log messages.
-  config_options.c: Improve misleading warning.
-  func_scramble: Add example to XML documentation.
-  sig_analog: Eliminate potential timeout with Last Number Redial.
-  ARI: The bridges play and record APIs now handle sample rates > 8K correctly.
-  res_pjsip_geolocation: Add support for Geolocation loc-src parameter
-  sorcery: Move from threadpool to taskpool.
-  stasis_channels.c: Make protocol_id optional to enable blind transfer via ari
-  Fix some doxygen, typos and whitespace
-  stasis_channels.c: Add null check for referred_by in ast_ari_transfer_message_create
-  app_queue: Add NULL pointer checks in app_queue
-  app_externalivr: Prevent out-of-bounds read during argument processing.
-  chan_dahdi: Add DAHDI_CHANNEL function.
-  taskpool: Update versions for taskpool stasis options.
-  taskpool: Add taskpool API, switch Stasis to using it.
-  app_adsiprog: Fix possible NULL dereference.
-  manager.c: Fix presencestate object leak
-  audiohook.c: Ensure correct AO2 reference is dereffed.
-  res_cliexec: Remove unnecessary casts to char*.
-  rtp_engine.c: Add exception for comfort noise payload.
-  pbx_variables.c: Create real channel for "dialplan eval function".
-  res_rtp_asterisk.c: Use rtp->dtls in __rtp_sendto when rtcp mux is used.
-  chan_websocket: Fix codec validation and add passthrough option.
-  res_ari: Ensure outbound websocket config has a websocket_client_id.
-  chan_websocket.c: Add DTMF messages
-  app_queue.c: Add new global 'log_unpause_on_reason_change'
-  app_waitforsilence.c: Use milliseconds to calculate timeout time
-  Fix missing ast_test_flag64 in extconf.c
-  pbx_builtins: Allow custom tone for WaitExten.
-  res_tonedetect: Add option for TONE_DETECT detection to auto stop.
-  app_queue: fix comparison for announce-position-only-up
-  sorcery: Prevent duplicate objects and ensure missing objects are created on update
-  sig_analog: Skip Caller ID spill if usecallerid=no.
-  chan_dahdi: Fix erroneously persistent dialmode.
-  chan_websocket: Allow additional URI parameters to be added to the outgoing URI.
-  chan_websocket: Fix buffer overrun when processing TEXT websocket frames.
-  sig_analog: Fix SEGV due to calling strcmp on NULL.
-  ARI: Add command to indicate progress to a channel
-  dsp.c: Improve debug logging in tone_detect().
-  res_stasis_device_state: Fix delete ARI Devicestates after asterisk restart.
-  app_chanspy: Add option to not automatically answer channel.
-  xmldoc.c: Fix rendering of CLI output.
-  func_frame_drop: Add debug messages for dropped frames.
-  test_res_prometheus: Fix compilation failure on Debian 13.
-  func_frame_drop: Handle allocation failure properly.
-  pbx_lua.c: segfault when pass null data to term_color function
-  bridge.c: Obey BRIDGE_NOANSWER variable to skip answering channel.
-  res_rtp_asterisk: Don't send RTP before DTLS has negotiated.
-  app_dial.c: Moved channel lock to prevent deadlock
-  res_pjsip_diversion: resolve race condition between Diversion header processing and redirect
-  file.c: with "sounds_search_custom_dir = yes", search "custom" directory
-  cel: Add STREAM_BEGIN, STREAM_END and DTMF event types.
-  channelstorage_cpp_map_name_id.cc: Refactor iterators for thread-safety.
-  res_srtp: Add menuselect options to enable AES_192, AES_256 and AES_GCM
-  cdr: add CANCEL dispostion in CDR
-  func_curl: Allow auth methods to be set.
-  options:  Change ast_options from ast_flags to ast_flags64.
-  res_config_odbc: Prevent Realtime fallback on record-not-found (SQL_NO_DATA)
-  resource_channels.c: Don't call ast_channel_get_by_name on empty optional arguments
-  app_agent_pool: Remove documentation for removed option.
-  pbx.c: When the AST_SOFTHANGUP_ASYNCGOTO flag is set, pbx_extension_helper should return directly.
-  res_agi: Increase AGI command buffer size from 2K to 8K
-  ast_tls_cert: Make certificate validity configurable.
-  cdr.c: Set tenantid from party_a->base instead of chan->base.
-  app_mixmonitor:  Update the documentation concerning the "D" option.
-  sig_analog: Properly handle STP, ST2P, and ST3P for fgccamamf.
-  chan_websocket: Reset frame_queue_length to 0 after FLUSH_MEDIA
-  chan_pjsip.c: Change SSRC after media source change
-  Media over Websocket Channel Driver
-  bundled_pjproject: Avoid deadlock between transport and transaction
-  utils.h: Add rounding to float conversion to int.
-  pbx.c: when set flag AST_SOFTHANGUP_ASYNCGOTO, ast_explicit_goto should return -1.
-  res_musiconhold.c: Ensure we're always locked around music state access.
-  res_musiconhold.c: Annotate when the channel is locked.
-  res_musiconhold: Appropriately lock channel during start.
-  res_pjsip_authenticator_digest: Fix SEGV if get_authorization_hdr returns NULL.
-  safe_asterisk: Add ownership checks for /etc/asterisk/startup.d and its files.
-  res_stir_shaken: Test for missing semicolon in Identity header.
-  channelstorage: Rename callbacks that conflict with DEBUG_FD_LEAKS.
-  channelstorage_cpp_map_name_id: Fix callback returning non-matching channels.
-  audiohook.c: Improve frame pairing logic to avoid MixMonitor breakage with mixed codecs
-  channelstorage_makeopts.xml: Remove errant XML character.
-  res_stir_shaken.so: Handle X5U certificate chains.
-  res_stir_shaken: Add "ignore_sip_date_header" config option.
-  app_record: Add RECORDING_INFO function.
-  app_sms.c: Fix sending and receiving SMS messages in protocol 2
-  app_queue: queue rules – Add support for QUEUE_RAISE_PENALTY=rN to raise penalties only for members within min/max range
-  res_websocket_client:  Add more info to the XML documentation.
-  res_odbc: cache_size option to limit the cached connections.
-  res_odbc: cache_type option for res_odbc.
-  res_pjsip: Fix empty `ActiveChannels` property in AMI responses.
-  ARI Outbound Websockets
-  res_websocket_client: Create common utilities for websocket clients.
-  asterisk.c: Add option to restrict shell access from remote consoles.
-  res_pjsip_messaging.c: Mask control characters in received From display name
-  frame.c: validate frame data length is less than samples when adjusting volume
-  res_audiosocket.c: Add retry mechanism for reading data from AudioSocket
-  res_audiosocket.c: Set the TCP_NODELAY socket option
-  menuselect: Fix GTK menu callbacks for Fedora 42 compatibility
-  jansson: Upgrade version to jansson 2.14.1
-  pjproject: Increase maximum SDP formats and attribute limits
-  manager.c: Invalid ref-counting when purging events
-  res_pjsip_nat.c: Do not overwrite transfer host
-  chan_pjsip: Serialize INVITE creation on DTMF attended transfer
-  Alternate Channel Storage Backends
-  sig_analog: Add Call Waiting Deluxe support.
-  app_sms: Ignore false positive vectorization warning.
-  lock.h: Add include for string.h when DEBUG_THREADS is defined.
-  res_pjsip_caller_id: Also parse URI parameters for ANI2.
-  app_meetme: Remove inaccurate removal version from xmldocs.
-  docs: Fix typos in apps/
-  stasis/control.c: Set Hangup Cause to No Answer on Dial timeout
-  chan_iax2: Minor improvements to documentation and warning messages.
-  pbx_ael: unregister AELSub application and CLI commands on module load failure
-  res_pjproject: Fix DTLS client check failing on some platforms
-  Prequisites for ARI Outbound Websockets
-  contrib: Add systemd service and timer files for malloc trim.
-  action_redirect: remove after_bridge_goto_info
-  channel: Always provide cause code in ChannelHangupRequest.
-  Add log-caller-id-name option to log Caller ID Name in queue log
-  asterisk.c: Add "pre-init" and "pre-module" capability to cli.conf.
-  app_confbridge: Prevent crash when publishing channel-less event.
-  ari_websockets: Fix frack if ARI config fails to load.
-  ARI: REST over Websocket
-  audiohook.c: Add ability to adjust volume with float
-  audiosocket: added support for DTMF frames
-  asterisk/channel.h: fix documentation for 'ast_waitfor_nandfds()'
-  audiosocket: fix timeout, fix dialplan app exit, server address in logs
-  chan_pjsip:  Add the same details as PJSIPShowContacts to the CLI via 'pjsip show contact'
-  Update config.guess and config.sub
-  chan_pjsip: set correct Endpoint Device State on multiple channels
-  file.c: missing "custom" sound files should not generate warning logs
-  documentation: Update Gosub, Goto, and add new documentationtype.
-  res_config_curl.c: Remove unnecessary warnings.
-  README.md: Updates and Fixes
-  res_rtp_asterisk.c: Don't truncate spec-compliant `ice-ufrag` or `ice-pwd`.
-  fix: Correct default flag for tcp_keepalive_enable option
-  docs: AMI documentation fixes.
-  config.c: #include of non-existent file should not crash
-  manager.c: Check for restricted file in action_createconfig.
-  swagger_model.py: Fix invalid escape sequence in get_list_parameter_type().
-  res_rtp_asterisk.c: Use correct timeout value for T.140 RED timer.
-  docs: Fix typos in cdr/ Found via codespell
-  docs: Fix various typos in channels/ Found via `codespell -q 3 -S "./CREDITS,*.po" -L abd,asent,atleast,cachable,childrens,contentn,crypted,dne,durationm,enew,exten,inout,leapyear,mye,nd,oclock,offsetp,ot,parm,parms,preceeding,pris,ptd,requestor,re-use,re-used,re-uses,ser,siz,slanguage,slin,thirdparty,varn,varns,ues`
-  docs: Fix various typos in main/ Found via `codespell -q 3 -S "./CREDITS" -L abd,asent,atleast,childrens,contentn,crypted,dne,durationm,exten,inout,leapyear,nd,oclock,offsetp,ot,parm,parms,requestor,ser,slanguage,slin,thirdparty,varn,varns,ues`
-  bridging: Fix multiple bridging issues causing SEGVs and FRACKs.
-  bridge_channel: don't set cause code on channel during bridge delete if already set
-  res_config_pgsql: Fix regression that removed dbname config.
-  res_stir_shaken: Allow missing or anonymous CID to continue to the dialplan.
-  resource_channels.c: Fix memory leak in ast_ari_channels_external_media.
-  ari/pjsip: Make it possible to control transfers through ARI
-  channel.c: Remove dead AST_GENERATOR_FD code.
-  func_strings.c: Prevent SEGV in HASH single-argument mode.
-  docs: Add version information to AGI command XML elements.
-  docs: Fix minor typo in MixMonitor AMI action
-  utils: Disable old style definition warnings for libdb.
-  rtp.conf.sample: Correct stunaddr example.
-  docs: Add version information to ARI resources and methods.
-  docs: Indent <since> tags.
-  res_pjsip_authenticator_digest: Make correct error messages appear again.
-  alembic: Database updates required.
-  res_pjsip: Fix startup/reload memory leak in config_auth.
-  docs: Add version information to application and function XML elements
-  docs: Add version information to manager event instance XML elements
-  LICENSE: Update company name, email, and address.
-  res_prometheus.c: Set Content-Type header on /metrics response.
-  README.md, asterisk.c: Update Copyright Dates
-  docs: Add version information to configObject and configOption XML elements
-  res_pjsip_authenticator_digest: Fix issue with missing auth and DONT_OPTIMIZE
-  ast_tls_cert: Add option to skip passphrase for CA private key.
-  chan_iax2: Avoid unnecessarily backlogging non-voice frames.
-  config.c: fix #tryinclude being converted to #include on rewrite
-  sig_analog: Add Last Number Redial feature.
-  docs: Various XML fixes
-  strings.c: Improve numeric detection in `ast_strings_match()`.
-  docs: Enable since/version handling for XML, CLI and ARI documentation
-  logger.h: Fix build when AST_DEVMODE is not defined.
-  dialplan_functions_doc.xml: Document PJSIP_MEDIA_OFFER's `media` argument.
-  samples: Use "asterisk" instead of "postgres" for username
-  manager: Add `<since>` tags for all AMI actions.
-  logger.c fix: malformed JSON template
-  manager.c: Rename restrictedFile to is_restricted_file.
-  res_config_pgsql: normalize database connection option with cel and cdr by supporting new options name
-  res_pjproject: Fix typo (OpenmSSL->OpenSSL)
-  Add SHA-256 and SHA-512-256 as authentication digest algorithms
-  config.c: retain leading whitespace before comments
-  config.c: Fix off-nominal reference leak.
-  normalize contrib/ast-db-manage/queue_log.ini.sample
-  Add C++ Standard detection to configure and fix a new C++20 compile issue
-  chan_dahdi: Fix wrong channel state when RINGING recieved.
-  Upgrade bundled pjproject to 2.15.1 Resolves: asterisk#1016
-  gcc14: Fix issues caught by gcc 14
-  Header fixes for compiling C++ source files
-  Add ability to pass arguments to unit tests from the CLI
-  res_pjsip: Add new AOR option "qualify_2xx_only"
-  res_odbc: release threads from potential starvation.
-  app_queue: indicate the paused state of a dynamically added member in queue_log.
-  Allow C++ source files (as extension .cc) in the main directory
-  format_gsm.c: Added mime type
-  func_uuid: Add a new dialplan function to generate UUIDs
-  app_queue: allow dynamically adding a queue member in paused state.
-  chan_iax2: Add log message for rejected calls.
-  chan_pjsip: Send VIDUPDATE RTP frame for all H.264 streams
-  audiohook.c: resolving the issue with audiohook both reading when packet loss on one side of the call
-  res_curl.conf.sample: clean up sample configuration and add new SSL options
-  res_rtp_asterisk.c: Fix bridged_payload matching with sample rate for DTMF
-  manager.c: Add Processed Call Count to CoreStatus output
-  func_curl.c: Add additional CURL options for SSL requests
-  sig_analog: Fix regression with FGD and E911 signaling.
-  main/stasis_channels.c: Fix crash when setting a global variable with invalid UTF8 characters
-  res_stir_shaken: Allow sending Identity headers for unknown TNs
-  manager.c: Restrict ListCategories to the configuration directory.
-  res_pjsip: Change suppress_moh_on_sendonly to OPT_BOOL_T
-  res_pjsip: Add new endpoint option "suppress_moh_on_sendonly"
-  res_pjsip.c: Fix Contact header rendering for IPv6 addresses.
-  samples: remove and/or change some wiki mentions
-  func_pjsip_aor/contact: Fix documentation for contact ID
-  res_pjsip: Move tenantid to end of ast_sip_endpoint
-  pjsip_transport_events: handle multiple addresses for a domain
-  func_evalexten: Add EVAL_SUB function.
-  res_srtp: Change Unsupported crypto suite msg from verbose to debug
-  Add res_pjsip_config_sangoma external module.
-  app_mixmonitor: Add 'D' option for dual-channel audio.
-  pjsip_transport_events: Avoid monitor destruction
-  app_dial: Fix progress timeout calculation with no answer timeout.
-  pjproject_bundled:  Tweaks to support out-of-tree development
-  Revert "res_rtp_asterisk: Count a roll-over of the sequence number even on lost packets."
-  core_unreal.c: Fix memory leak in ast_unreal_new_channels()
-  dnsmgr.c: dnsmgr_refresh() incorrectly flags change with DNS round-robin
-  geolocation.sample.conf: Fix comment marker at end of file
-  func_base64.c: Ensure we set aside enough room for base64 encoded data.
-  app_dial: Fix progress timeout.
-  chan_dahdi: Never send MWI while off-hook.
-  manager.c: Add unit test for Originate app and appdata permissions
-  alembic: Drop redundant voicemail_messages index.
-  res_agi.c: Ensure SIGCHLD handler functions are properly balanced.
-  main, res, tests: Fix compilation errors on FreeBSD.
-  res_rtp_asterisk: Fix dtls timer issues causing FRACKs and SEGVs
-  manager.c: Restrict ModuleLoad to the configured modules directory.
-  res_agi.c: Prevent possible double free during `SPEECH RECOGNIZE`
-  cdr_custom: Allow absolute filenames.
-  astfd.c: Avoid calling fclose with NULL argument.
-  channel: Preserve CHANNEL(userfield) on masquerade.
-  cel_custom: Allow absolute filenames.
-  app_voicemail: Fix ill-formatted pager emails with custom subject.
-  res_pjsip_pubsub: Persist subscription 'generator_data' in sorcery
-  Fix application references to Background
-  manager.conf.sample: Fix mathcing typo
-  manager: Enhance event filtering for performance
-  manager.c: Split XML documentation to manager_doc.xml
-  db.c: Remove limit on family/key length
-  stir_shaken: Fix propagation of attest_level and a few other values
-  res_stir_shaken: Remove stale include for jansson.h in verification.c
-  res_stir_shaken.c: Fix crash when stir_shaken.conf is invalid
-  res_stir_shaken: Check for disabled before param validation
-  app_chanspy.c: resolving the issue writing frame to whisper audiohook.
-  autoservice: Do not sleep if autoservice_stop is called within autoservice thread
-  res_resolver_unbound: Test for NULL ub_result in unbound_resolver_callback
-  app_voicemail: Use ast_asprintf to create mailbox SQL query
-  res_pjsip_sdp_rtp: Use negotiated DTMF Payload types on bitrate mismatch
-  app_chanspy.c: resolving the issue with audiohook direction read
-  security_agreements.c: Refactor the to_str functions and fix a few other bugs
-  res_pjsip_sdp_rtp fix leaking astobj2 ast_format
-  stir_shaken.conf.sample: Fix bad references to private_key_path
-  res_pjsip_logger.c: Fix 'OPTIONS' tab completion.
-  alembic: Make 'revises' header comment match reality.
-  Update version for Asterisk 22
-  chan_mobile: decrease CHANNEL_FRAME_SIZE to prevent delay
-  res_pjsip_notify: add dialplan application
-  manager.c: Fix FRACK when doing CoreShowChannelMap in DEVMODE
-  channel: Add multi-tenant identifier.
-  configure:  Use . file rather than source file.
-  feat: ARI "ChannelToneDetected" event
-  manager.c: Add entries to Originate blacklist
-  res_stasis: fix intermittent delays on adding channel to bridge
-  res_pjsip_sdp_rtp.c: Fix DTMF Handling in Re-INVITE with dtmf_mode set to auto
-  rtp_engine.c: Prevent segfault in ast_rtp_codecs_payloads_unset()
-  stir_shaken: CRL fixes and a new CLI command
-  res_pjsip_config_wizard.c: Refactor load process
-  voicemail.conf.sample: Fix ':' comment typo
-  bridge_softmix: Fix queueing VIDUPDATE control frames
-  res_pjsip_path.c: Fix path when dialing using PJSIP_DIAL_CONTACTS()
-  res_pjsip_sdp_rtp: Add support for default/mismatched 8K RFC 4733/2833 digits
-  ast-db-manage: Remove duplicate enum creation
-  security_agreement.c: Always add the Require and Proxy-Require headers
-  logger.h: Include SCOPE_CALL_WITH_INT_RESULT() in non-dev-mode builds.
-  stasis_channels: Use uniqueid and name to delete old snapshots
-  app_voicemail_odbc: Allow audio to be kept on disk
-  bridge_basic.c: Make sure that ast_bridge_channel is not destroyed while iterating over bridge->channels. From the gdb information, we can see that while iterating over bridge->channels, the ast_bridge_channel reference count is 0, indicating it has already been destroyed.Additionally, when ast_bridge_channel is removed from bridge->channels, the bridge is first locked. Therefore, locking the bridge before iterating over bridge->channels can resolve the race condition.
-  app_queue:  Add option to not log Restricted Caller ID to queue_log
-  pbx.c: expand fields width of "core show hints"
-  pjsip: Add PJSIP_PARSE_URI_FROM dialplan function.
-  manager.c: Properly terminate `CoreShowChannelMap` event.
-  cli: Show configured cache dir
-  xml.c: Update deprecated libxml2 API usage.
-  cdr_pgsql: Fix crash when the module fails to load multiple times.
-  asterisk.c: Don't log an error if .asterisk_history does not exist.
-  chan_ooh323: Fix R/0 typo in docs
-  bundled_pjproject: Disable UPnP support.
-  file.h: Rename function argument to avoid C++ keyword clash.
-  rtp_engine: add support for multirate RFC2833 digits
-  configs: Fix a misleading IPv6 ACL example in Named ACLs
-  asterisk.c: Fix sending incorrect messages to systemd notify
-  res/stasis/control.c: include signal.h
-  res_pjsip_logger: Preserve logging state on reloads.
-  logger: Add unique verbose prefixes for levels 5-10.
-  say.c: Fix cents off-by-one due to floating point rounding.
-  loader.c: Allow dependent modules to be unloaded recursively.
-  res_pjsip_sdp_rtp.c: Initial RTP inactivity check must consider the rtp_timeout setting.
-  tcptls/iostream:  Add support for setting SNI on client TLS connections
-  stir_shaken:  Fix memory leak, typo in config, tn canonicalization
-  make_buildopts_h: Always include DETECT_DEADLOCKS
-  sorcery.c: Fixed crash error when executing "module reload"
-  callerid.c: Parse previously ignored Caller ID parameters.
-  logger.h:  Add SCOPE_CALL and SCOPE_CALL_WITH_RESULT
-  app_queue.c: Properly handle invalid strategies from realtime.
-  file.c, channel.c: Don't emit warnings if progress received.
-  alembic: Correct NULLability of PJSIP id columns.
-  rtp_engine and stun: call ast_register_atexit instead of ast_register_cleanup
-  manager.c: Add missing parameters to Login documentation
-  func_callerid: Emit warning if invalid redirecting reason set.
-  chan_dahdi: Add DAHDIShowStatus AMI action.
-  res_stir_shaken:  Fix compilation for CentOS7 (openssl 1.0.2)
-  Fix incorrect application and function documentation references
-  cli.c: `core show channels concise` is not really deprecated.
-  res_pjsip_endpoint_identifier_ip: Endpoint identifier request URI
-  Implement Configurable TCP Keepalive Settings in PJSIP Transports
-  chan_dahdi: Don't retry opening nonexistent channels on restart.
-  res_pjsip_refer.c: Allow GET_TRANSFERRER_DATA
-  res_ari.c: Add additional output to ARI requests when debug is enabled
-  alembic: Fix compatibility with SQLAlchemy 2.0+.
-  manager.c: Add new parameter 'PreDialGoSub' to Originate AMI action
-  menuselect: Minor cosmetic fixes.
-  pbx_variables.c: Prevent SEGV due to stack overflow.
-  res_prometheus: Fix duplicate output of metric and help text
-  manager.c: Add CLI command to kick AMI sessions.
-  chan_dahdi: Allow specifying waitfordialtone per call.
-  res_parking: Fail gracefully if parking lot is full.
-  res_config_mysql.c: Support hostnames up to 255 bytes.
-  res_pjsip: Fix alembic downgrade for boolean columns.
-  Upgrade bundled pjproject to 2.14.1
-  alembic: Quote new MySQL keyword 'qualify.'
-  res_pjsip_session: Reset pending_media_state->read_callbacks
-  res_pjsip_stir_shaken.c:  Add checks for missing parameters
-  app_dial: Add dial time for progress/ringing.
-  app_voicemail: Properly reinitialize config after unit tests.
-  app_queue.c : fix "queue add member" usage string
-  app_voicemail: Allow preventing mark messages as urgent.
-  res_pjsip: Use consistent type for boolean columns.
-  attestation_config.c: Use ast_free instead of ast_std_free
-  Makefile: Add stir_shaken/cache to directories created on install
-  Stir/Shaken Refactor
-  translate.c: implement new direct comp table mode
-  README.md: Removed outdated link
-  strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.
-  res_rtp_asterisk.c: Correct coefficient in MOS calculation.
-  dsp.c: Fix and improve potentially inaccurate log message.
-  pjsip show channelstats: Prevent possible segfault when faxing
-  Reduce startup/shutdown verbose logging
-  configure: Rerun bootstrap on modern platform.
-  Upgrade bundled pjproject to 2.14.
-  app_speech_utils.c: Allow partial speech results.
-  res_pjsip_outbound_registration.c: Add User-Agent header override
-  utils: Make behavior of ast_strsep* match strsep.
-  app_chanspy: Add 'D' option for dual-channel audio
-  app_if: Fix next priority calculation.
-  res_pjsip_t38.c: Permit IPv6 SDP connection addresses.
-  BuildSystem: Bump autotools versions on OpenBSD.
-  main/utils: Simplify the FreeBSD ast_get_tid() handling
-  res_pjsip_session.c: Correctly format SDP connection addresses.
-  rtp_engine.c: Correct sample rate typo for L16/44100.
-  manager.c: Fix erroneous reloads in UpdateConfig.
-  res_calendar_icalendar: Print iCalendar error on parsing failure.
-  app_confbridge: Don't emit warnings on valid configurations.
-  app_voicemail_odbc: remove macrocontext from voicemail_messages table
-  chan_dahdi: Allow MWI to be manually toggled on channels.
-  logger: Fix linking regression.
-  chan_rtp.c: MulticastRTP missing refcount without codec option
-  chan_rtp.c: Change MulticastRTP nameing to avoid memory leak
-  func_frame_trace: Add CLI command to dump frame queue.
-  menuselect: Use more specific error message.
-  res_pjsip_nat: Fix potential use of uninitialized transport details
-  app_if: Fix faulty EndIf branching.
-  manager.c: Fix regression due to using wrong free function.
-  res_rtp_asterisk: Fix regression issues with DTLS client check
-  res_pjsip_header_funcs: Duplicate new header value, don't copy.
-  res_pjsip: disable raw bad packet logging
-  res_rtp_asterisk.c: Check DTLS packets against ICE candidate list
-  manager.c: Prevent path traversal with GetConfig.
-  config_options.c: Fix truncation of option descriptions.
-  manager.c: Improve clarity of "manager show connected".
-  make_xml_documentation: Really collect LOCAL_MOD_SUBDIRS documentation.
-  general: Fix broken links.
-  MergeApproved.yml:  Remove unneeded concurrency
-  app_dial: Add option "j" to preserve initial stream topology of caller
-  pbx_config.c: Don't crash when unloading module.
-  ast_coredumper: Increase reliability
-  logger.c: Move LOG_GROUP documentation to dedicated XML file.
-  res_odbc.c: Allow concurrent access to request odbc connections
-  res_pjsip_header_funcs.c: Check URI parameter length before copying.
-  config.c: Log #exec include failures.
-  make_xml_documentation: Properly handle absolute LOCAL_MOD_SUBDIRS.
-  app_voicemail.c: Completely resequence mailbox folders.
-  sig_analog: Fix channel leak when mwimonitor is enabled.
-  res_rtp_asterisk.c: Update for OpenSSL 3+.
-  alembic: Update list of TLS methods available on ps_transports.
-  func_channel: Expose previously unsettable options.
-  app.c: Allow ampersands in playback lists to be escaped.
-  uri.c: Simplify ast_uri_make_host_with_port()
-  func_curl.c: Remove CURLOPT() plaintext documentation.
-  res_http_websocket.c: Set hostname on client for certificate validation.
-  live_ast: Add astcachedir to generated asterisk.conf.
-  SECURITY.md: Update with correct documentation URL
-  func_lock: Add missing see-also refs to documentation.
-  app_followme.c: Grab reference on nativeformats before using it
-  configs: Improve documentation for bandwidth in iax.conf.
-  logger: Add channel-based filtering.
-  chan_iax2.c: Don't send unsanitized data to the logger.
-  codec_ilbc: Disable system ilbc if version >= 3.0.0
-  resource_channels.c: Explicit codec request when creating UnicastRTP.
-  doc: Update IP Quality of Service links.
-  chan_pjsip: Add PJSIPHangup dialplan app and manager action
-  chan_iax2.c: Ensure all IEs are displayed when dumping frame contents.
-  chan_dahdi: Warn if nonexistent cadence is requested.
-  stasis: Update the snapshot after setting the redirect
-  ari: Provide the caller ID RDNIS for the channels
-  main/utils: Implement ast_get_tid() for OpenBSD
-  res_rtp_asterisk.c: Fix runtime issue with LibreSSL
-  app_directory: Add ADSI support to Directory.
-  core_local: Fix local channel parsing with slashes.
-  Remove files that are no longer updated
-  app_voicemail: Add AMI event for mailbox PIN changes.
-  app_queue.c: Emit unpause reason with PauseQueueMember event.
-  bridge_simple: Suppress unchanged topology change requests
-  res_pjsip: Include cipher limit in config error message.
-  res_speech: allow speech to translate input channel
-  res_rtp_asterisk.c: Fix memory leak in ephemeral certificate creation.
-  res_pjsip_dtmf_info.c: Add 'INFO' to Allow header.
-  Update issue guidelines link for bug reports.
-  api.wiki.mustache: Fix indentation in generated markdown
-  pjsip_configuration.c: Disable DTLS renegotiation if WebRTC is enabled.
-  configs: Fix typo in pjsip.conf.sample.
-  res_pjsip_exten_state,res_pjsip_mwi: Allow unload on shutdown
-  res_pjsip: Expanding PJSIP endpoint ID and relevant resource length to 255 characters
-  res_stasis: signal when new command is queued
-  ari/stasis: Indicate progress before playback on a bridge
-  func_curl.c: Ensure channel is locked when manipulating datastores.
-  logger.h: Add ability to change the prefix on SCOPE_TRACE output
-  res_pjsip: update qualify_timeout documentation with DNS note
-  res_speech_aeap: add aeap error handling
-  Add libjwt to third-party
-  chan_dahdi: Clarify scope of callgroup/pickupgroup.
-  func_json: Fix crashes for some types
-  app_voicemail: Disable ADSI if unavailable.
-  codec_builtin: Use multiples of 20 for maximum_ms
-  lock.c: Separate DETECT_DEADLOCKS from DEBUG_THREADS
-  asterisk.c: Use the euid's home directory to read/write cli history
-  res_pjsip_transport_websocket: Prevent transport from being destroyed before message finishes.
-  cel: add publish user event helper
-  chan_console: Fix deadlock caused by unclean thread exit.
-  file.c: Add ability to search custom dir for sounds
-  chan_iax2: Improve authentication debugging.
-  res_rtp_asterisk: fix wrong counter management in ioqueue objects
-  res_pjsip_pubsub: Add body_type to test_handler for unit tests
-  make_buildopts_h, et. al.  Allow adding all cflags to buildopts.h
-  func_periodic_hook: Add hangup step to avoid timeout
-  res_stasis_recording.c: Save recording state when unmuted.
-  res_speech_aeap: check for null format on response
-  func_periodic_hook: Don't truncate channel name
-  safe_asterisk: Change directory permissions to 755
-  chan_rtp: Implement RTP glue for UnicastRTP channels
-  variables: Add additional variable dialplan functions.
-  ari-stubs: Fix more local anchor references
-  ari-stubs: Fix broken documentation anchors
-  res_pjsip_session: Send Session Interval too small response
-  app_dial: Fix infinite loop when sending digits.
-  app_voicemail: Fix for loop declarations
-  alembic: Fix quoting of the 100rel column
-  pbx.c: Fix gcc 12 compiler warning.
-  app_audiosocket: Fixed timeout with -1 to avoid busy loop.
-  download_externals:  Fix a few version related issues
-  main/refer.c: Fix double free in refer_data_destructor + potential leak
-  sig_analog: Add Called Subscriber Held capability.
-  install_prereq: Fix dependency install on aarch64.
-  res_pjsip.c: Set contact_user on incoming call local Contact header
-  extconfig: Allow explicit DB result set ordering to be disabled.
-  res_pjsip_header_funcs: Make prefix argument optional.
-  pjproject_bundled: Increase PJSIP_MAX_MODULE to 38
-  manager: Tolerate stasis messages with no channel snapshot.
-  Prepare master for Asterisk 22
-  core/ari/pjsip: Add refer mechanism
-  chan_dahdi: Allow autoreoriginating after hangup.
-  audiohook: Unlock channel in mute if no audiohooks present.
-  sig_analog: Allow three-way flash to time out to silence.
-  res_prometheus: Do not generate broken metrics
-  res_pjsip: Enable TLS v1.3 if present.
-  func_cut: Add example to documentation.
-  extensions.conf.sample: Remove reference to missing context.
-  func_export: Use correct function argument as variable name.
-  app_queue: Add support for applying caller priority change immediately.
-  app.h: Move declaration of ast_getdata_result before its first use
-  chan_iax2.c: Avoid crash with IAX2 switch support.
-  res_geolocation: Ensure required 'location_info' is present.
-  Adds manager actions to allow move/remove/forward individual messages in a particular mailbox folder. The forward command can be used to copy a message within a mailbox or to another mailbox. Also adds a VoicemailBoxSummarry, required to retrieve message ID's.
-  app_voicemail: add CLI commands for message manipulation
-  res_rtp_asterisk: Move ast_rtp_rtcp_report_alloc using `rtp->themssrc_valid` into the scope of the rtp_instance lock.
-  users.conf: Deprecate users.conf configuration.
-  sig_analog: Allow immediate fake ring to be suppressed.
-  apply_patches: Use globbing instead of file/sort.
-  apply_patches: Sort patch list before applying
-  pjsip: Upgrade bundled version to pjproject 2.13.1
-  app_voicemail: fix imap compilation errors
-  res_musiconhold: avoid moh state access on unlocked chan
-  utils: add lock timestamps for DEBUG_THREADS
-  rest-api: Updates for new documentation site
-  rest-api: Ran make ari stubs to fix resource_endpoints inconsistency
-  app_voicemail_imap: Fix message count when IMAP server is unavailable
-  res_pjsip_rfc3326: Prefer Q.850 cause code over SIP.
-  Update config.yml
-  res_pjsip_session: Added new function calls to avoid ABI issues.
-  app_queue: Add force_longest_waiting_caller option.
-  pjsip_transport_events.c: Use %zu printf specifier for size_t.
-  res_crypto.c: Gracefully handle potential key filename truncation.
-  configure: Remove obsolete and deprecated constructs.
-  res_fax_spandsp.c: Clean up a spaces/tabs issue
-  ast-db-manage: Synchronize revisions between comments and code.
-  test_statis_endpoints:  Fix channel_messages test again
-  res_crypto.c: Avoid using the non-portable ALLPERMS macro.
-  tcptls: when disabling a server port, we should set the accept_fd to -1.
-  AMI: Add parking position parameter to Park action
-  test_stasis_endpoints.c: Make channel_messages more stable
-  build: Fix a few gcc 13 issues
-  ast-db-manage: Fix alembic branching error caused by #122.
-  sounds: Update download URL to use HTTPS.
-  configure: Makefile downloader enable follow redirects.
-  res_musiconhold: Add option to loop last file.
-  chan_dahdi: Fix Caller ID presentation for FXO ports.
-  AMI: Add CoreShowChannelMap action.
-  sig_analog: Add fuller Caller ID support.
-  res_stasis.c: Add new type 'sdp_label' for bridge creation.
-  app_followme: fix issue with enable_callee_prompt=no (#88)
-  app_queue: Preserve reason for realtime queues
-  indications: logging changes
-  callerid: Allow specifying timezone for date/time.
-  logrotate: Fix duplicate log entries.
-  app_sla: Migrate SLA applications out of app_meetme.
-  chan_pjsip: Allow topology/session refreshes in early media state (#74)
-  chan_dahdi: Fix broken hidecallerid setting. (#101)
-  asterisk.c: Fix option warning for remote console. (#103)
-  res_pjsip_pubsub: Add new pubsub module capabilities. (#82)
-  configure: fix test code to match gethostbyname_r prototype. (#75)
-  res_pjsip_pubsub.c: Use pjsip version for pending NOTIFY check. (#47)
-  res_sorcery_memory_cache.c: Fix memory leak (#56)
-  utils.h: Deprecate `ast_gethostbyname()`. (#79)
-  xml.c: Process XML Inclusions recursively. (#69)
-  chan_pjsip: also return all codecs on empty re-INVITE for late offers (#59)
-  cel: add local optimization begin event (#54)
-  core: Cleanup gerrit and JIRA references. (#58)
-  res_pjsip: mediasec: Add Security-Client headers after 401 (#49)
-  LICENSE: Update link to trademark policy. (#44)
-  say.c: Fix French time playback. (#42)
-  chan_dahdi: Add dialmode option for FXS lines.
-  Initial GitHub PRs
-  Initial GitHub Issue Templates
-  pbx_dundi: Fix PJSIP endpoint configuration check.
-  res_pjsip_stir_shaken: Fix JSON field ordering and disallowed TN characters.
-  pbx_dundi: Add PJSIP support.
-  chan_pjsip: fix music on hold continues after INVITE with replaces
-  install_prereq: Add Linux Mint support.
-  voicemail.conf: Fix incorrect comment about #include.
-  app_queue: Fix minor xmldoc duplication and vagueness.
-  test.c: Fix counting of tests and add 2 new tests
-  res_pjsip_pubsub: subscription cleanup changes
-  res_calendar: output busy state as part of show calendar.
-  ael: Regenerate lexers and parsers.
-  loader.c: Minor module key check simplification.
-  bridge_builtin_features: add beep via touch variable
-  res_mixmonitor: MixMonitorMute by MixMonitor ID
-  format_sln: add .slin as supported file extension
-  cli: increase channel column width
-  app_osplookup: Remove obsolete sample config.
-  func_json: Fix JSON parsing issues.
-  app_dial: Fix DTMF not relayed to caller on unanswered calls.
-  configure: fix detection of re-entrant resolver functions
-  res_agi: RECORD FILE plays 2 beeps.
-  app_senddtmf: Add SendFlash AMI action.
-  http.c: Minor simplification to HTTP status output.
-  make_version: Strip svn stuff and suppress ref HEAD errors
-  res_http_media_cache: Introduce options and customize
-  contrib: rc.archlinux.asterisk uses invalid redirect.
-  main/iostream.c: fix build with libressl
-  res_pjsip: Replace invalid UTF-8 sequences in callerid name
-  test.c: Avoid passing -1 to FD_* family of functions.
-  chan_iax2: Fix jitterbuffer regression prior to receiving audio.
-  test_crypto.c: Fix getcwd(…) build error.
-  pjproject_bundled: fix cross-compilation with ssl libs
-  res_phoneprov.c: Multihomed SERVER cache prevention
-  app_read: Add an option to return terminator on empty digits.
-  app_directory: Add a 'skip call' option.
-  app_senddtmf: Add option to answer target channel.
-  res_pjsip: Prevent SEGV in pjsip_evsub_send_request
-  app_queue: Minor docs and logging fixes for UnpauseQueueMember.
-  app_queue: Reset all queue defaults before reload.
-  res_pjsip: Upgraded bundled pjsip to 2.13
-  doxygen: Fix doxygen errors.
-  app_signal: Add signaling applications
-  app_directory: add ability to specify configuration file
-  func_json: Enhance parsing capabilities of JSON_DECODE
-  res_pjsip_session: Add overlap_context option.
-  res_stasis_snoop: Fix snoop crash
-  res_monitor: Remove deprecated module.
-  app_playback.c: Fix PLAYBACKSTATUS regression.
-  res_rtp_asterisk: Don't use double math to generate timestamps
-  app_macro: Remove deprecated module.
-  format_wav: replace ast_log(LOG_DEBUG, ...) by ast_debug(1, ...)
-  res_pjsip_rfc3326: Add SIP causes support for RFC3326
-  res_rtp_asterisk: Asterisk Media Experience Score (MES)
-  Revert "res_rtp_asterisk: Asterisk Media Experience Score (MES)"
-  http.c: Fix NULL pointer dereference bug
-  loader: Allow declined modules to be unloaded.
-  app_broadcast: Add Broadcast application
-  func_frame_trace: Print text for text frames.
-  app_cdr: Remove deprecated application and option.
-  res_http_media_cache: Do not crash when there is no extension
-  manager: Fix appending variables.
-  json.h: Add ast_json_object_real_get.
-  res_pjsip_transport_websocket: Add remote port to transport
-  chan_sip: Remove deprecated module.
-  res_rtp_asterisk: Asterisk Media Experience Score (MES)
-  pbx_app: Update outdated pbx_exec channel snapshots.
-  res_pjsip_session: Use Caller ID for extension matching.
-  pbx_builtins: Remove deprecated and defunct functionality.
-  res_pjsip_sdp_rtp.c: Use correct timeout when put on hold.
-  app_voicemail_odbc: Fix string overflow warning.
-  streams:  Ensure that stream is closed in ast_stream_and_wait on error
-  func_callerid: Warn about invalid redirecting reason.
-  app_sendtext: Remove references to removed applications.
-  res_pjsip: Fix path usage in case dialing with '@'
-  res_geoloc: fix NULL pointer dereference bug
-  res_pjsip_aoc: Don't assume a body exists on responses.
-  app_if: Fix format truncation errors.
-  chan_alsa: Remove deprecated module.
-  manager: AOC-S support for AOCMessage
-  chan_mgcp: Remove deprecated module.
-  res_pjsip_aoc: New module for sending advice-of-charge with chan_pjsip
-  res_hep: Add support for named capture agents.
-  res_pjsip: Fix typo in from_domain documentation
-  app_if: Adds conditional branch applications
-  res_pjsip_session.c: Map empty extensions in INVITEs to s.
-  res_pjsip: Update contact_user to point out default
-  res_pjsip_header_funcs: Add custom parameter support.
-  app_voicemail: Fix missing email in msg_create_from_file.
-  ari: Destroy body variables in channel create.
-  res_adsi: Fix major regression caused by media format rearchitecture.
-  func_presencestate: Fix invalid memory access.
-  sig_analog: Fix no timeout duration.
-  xmldoc: Allow XML docs to be reloaded.
-  rtp_engine.h: Update examples using ast_format_set.
-  app_osplookup: Remove deprecated module.
-  chan_skinny: Remove deprecated module.
-  app_mixmonitor: Add option to use real Caller ID for voicemail.
-  manager: prevent file access outside of config dir
-  pjsip_transport_events: Fix possible use after free on transport
-  pjproject: 2.13 security fixes
-  pbx_builtins: Allow Answer to return immediately.
-  chan_dahdi: Allow FXO channels to start immediately.
-  sla: Prevent deadlock and crash due to autoservicing.
-  Build system: Avoid executable stack.
-  func_json: Fix memory leak.
-  test_json: Remove duplicated static function.
-  res_agi: Respect "transmit_silence" option for "RECORD FILE".
-  file.c: Don't emit warnings on winks.
-  app_mixmonitor: Add option to delete files on exit.
-  translate.c: Prefer better codecs upon translate ties.
-  manager: Update ModuleCheck documentation.
-  runUnittests.sh:  Save coredumps to proper directory
-  chan_rtp: Make usage of ast_rtp_instance_get_local_address clearer
-  res_pjsip: prevent crash on websocket disconnect
-  tcptls: Prevent crash when freeing OpenSSL errors.
-  res_pjsip_outbound_registration: Allow to use multiple proxies for registration
-  tests: Fix compilation errors on 32-bit.
-  res_pjsip: return all codecs on a re-INVITE without SDP
-  res_pjsip_notify: Add option support for AMI.
-  res_pjsip_logger: Add method-based logging option.
-  Dialing API: Cancel a running async thread, may not cancel all calls
-  chan_dahdi: Fix unavailable channels returning busy.
-  res_pjsip_pubsub: Prevent removing subscriptions.
-  say: Don't prepend ampersand erroneously.
-  res_crypto: handle unsafe private key files
-  audiohook: add directional awareness
-  cdr: Allow bridging and dial state changes to be ignored.
-  res_tonedetect: Add ringback support to TONE_DETECT.
-  chan_dahdi: Resolve format truncation warning.
-  res_crypto: don't modify fname in try_load_key()
-  res_crypto: use ast_file_read_dirs() to iterate
-  res_geolocation: Update wiki documentation
-  res_pjsip: Add mediasec capabilities.
-  res_prometheus: Do not crash on invisible bridges
-  db: Fix incorrect DB tree count for AMI.
-  res_pjsip_geolocation: Change some notices to debugs.
-  func_logic: Don't emit warning if both IF branches are empty.
-  features: Add no answer option to Bridge.
-  app_bridgewait: Add option to not answer channel.
-  app_amd: Add option to play audio during AMD.
-  test: initialize capture structure before freeing
-  func_export: Add EXPORT function
-  res_pjsip: Add 100rel option "peer_supported".
-  manager: be more aggressive about purging http sessions.
-  func_scramble: Fix null pointer dereference.
-  func_strings: Add trim functions.
-  res_crypto: Memory issues and uninitialized variable errors
-  res_geolocation: Fix issues exposed by compiling with -O2
-  res_crypto: don't complain about directories
-  res_pjsip: Add user=phone on From and PAID for usereqphone=yes
-  res_geolocation: Fix segfault when there's an empty element
-  res_musiconhold: Add option to not play music on hold on unanswered channels
-  res_pjsip: Add TEL URI support for basic calls.
-  res_crypto: Use EVP API's instead of legacy API's
-  test: Add coverage for res_crypto
-  res_crypto: make keys reloadable on demand for testing
-  test: Add test coverage for capture child process output
-  main/utils: allow checking for command in $PATH
-  test: Add ability to capture child process output
-  res_crypto: Don't load non-regular files in keys directory
-  func_frame_trace: Remove bogus assertion.
-  lock.c: Add AMI event for deadlocks.
-  app_confbridge: Add end_marked_any option.
-  pbx_variables: Use const char if possible.
-  res_geolocation: Add two new options to GEOLOC_PROFILE
-  res_geolocation:  Allow location parameters on the profile object
-  res_geolocation: Add profile parameter suppress_empty_ca_elements
-  res_geolocation:  Add built-in profiles
-  res_pjsip_sdp_rtp: Skip formats without SDP details.
-  cli: Prevent assertions on startup from bad ao2 refs.
-  pjsip: Add TLS transport reload support for certificate and key.
-  res_tonedetect: Fix typos referring to wrong variables.
-  alembic: add missing ps_endpoints columns
-  chan_dahdi.c: Resolve a format-truncation build warning.
-  res_pjsip_pubsub: Postpone destruction of old subscriptions on RLS update
-  channel.h: Remove redundant declaration.
-  features: Add transfer initiation options.
-  CI: Fixing path issue on venv check
-  CI: use Python3 virtual environment
-  general: Very minor coding guideline fixes.
-  res_geolocation: Address user issues, remove complexity, plug leaks
-  chan_iax2: Add missing options documentation.
-  app_confbridge: Fix memory leak on updated menu options.
-  Geolocation: Wiki Documentation
-  manager: Remove documentation for nonexistent action.
-  cdr.conf: Remove obsolete app_mysql reference.
-  general: Remove obsolete SVN references.
-  app_meetme: Add missing AMI documentation.
-  general: Improve logging levels of some log messages.
-  app_confbridge: Add missing AMI documentation.
-  func_srv: Document field parameter.
-  pbx_functions.c: Manually update ast_str strlen.
-  build: fix bininstall launchd issue on cross-platform build
-  manager: Fix incomplete filtering of AMI events.
-  db: Add AMI action to retrieve DB keys at prefix.
-  Update master branch for Asterisk 21

### Commit Details:

#### Initial commit for certified-22.8
  Author: George Joseph
  Date:   2026-02-23


#### xml.c: Replace XML_PARSE_NOENT with XML_PARSE_NONET for xmlReadFile.
  Author: George Joseph
  Date:   2026-01-15

  The xmlReadFile XML_PARSE_NOENT flag, which allows parsing of external
  entities, could allow a potential XXE injection attack.  Replacing it with
  XML_PARSE_NONET, which prevents network access, is safer.

  Resolves: #GHSA-85x7-54wr-vh42

#### ast_coredumper: check ast_debug_tools.conf permissions
  Author: Mike Bradeen
  Date:   2026-01-15

  Prevent ast_coredumper from using ast_debug_tools.conf files that are
  not owned by root or are writable by other users or groups.

  Prevent ast_logescalator and ast_loggrabber from doing the same if
  they are run as root.

  Resolves: #GHSA-rvch-3jmx-3jf3

  UserNote: ast_debug_tools.conf must be owned by root and not be
  writable by other users or groups to be used by ast_coredumper or
  by ast_logescalator or ast_loggrabber when run as root.

#### http.c: Change httpstatus to default disabled and sanitize output.
  Author: George Joseph
  Date:   2026-01-15

  To address potential security issues, the httpstatus page is now disabled
  by default and the echoed query string and cookie output is html-escaped.

  Resolves: #GHSA-v6hp-wh3r-cwxh

  UpgradeNote: To prevent possible security issues, the `/httpstatus` page
  served by the internal web server is now disabled by default.  To explicitly
  enable it, set `enable_status=yes` in http.conf.

#### ast_coredumper: create gdbinit file with restrictive permissions
  Author: Mike Bradeen
  Date:   2026-01-15

  Modify gdbinit to use the install command with explicit permissions (-m 600)
  when creating the .ast_coredumper.gdbinit file. This ensures the file is
  created with restricted permissions (readable/writable only by the owner)
  to avoid potential privilege escalation.

  Resolves: #GHSA-xpc6-x892-v83c

#### asterisk.c: Use C.UTF-8 locale instead of relying on user's environment.
  Author: Sean Bright
  Date:   2026-01-23

  Resolves: #1739

#### chan_websocket.conf.sample: Fix category name.
  Author: George Joseph
  Date:   2026-01-21

  UserNote: The category name in the chan_websocket.conf.sample file was
  incorrect.  It should be "global" instead of "general".

#### chan_websocket: Fixed Ping/Pong messages hanging up the websocket channel
  Author: Joe Garlick
  Date:   2026-01-15

  When chan_websocket received a Ping or a Pong opcode it would cause the channel to hangup. This change allows Ping/Pong opcodes and allows them to silently pass

#### cli.c: Allow 'channel request hangup' to accept patterns.
  Author: Sean Bright
  Date:   2026-01-05

  This extends 'channel request hangup' to accept multiple channel
  names, a POSIX Extended Regular Expression, a glob-like pattern, or a
  combination of all of them.

  UserNote: The 'channel request hangup' CLI command now accepts
  multiple channel names, POSIX Extended Regular Expressions, glob-like
  patterns, or a combination of all of them. See the CLI command 'core
  show help channel request hangup' for full details.

#### res_sorcery_memory_cache: Reduce cache lock time for sorcery memory cache populate command
  Author: Mike Bradeen
  Date:   2026-01-06

  Reduce cache lock time for AMI and CLI sorcery memory cache populate
  commands by adding a new populate_lock to the sorcery_memory_cache
  struct which is locked separately from the existing cache lock so that
  the cache lock can be maintained for a reduced time, locking only when
  the cache objects are removed and re-populated.

  Resolves: #1700

  UserNote: The AMI command sorcery memory cache populate will now
  return an error if there is an internal error performing the populate.
  The CLI command will display an error in this case as well.

#### Add comment to asterisk.conf.sample clarifying that template sections are ignored
  Author: phoneben
  Date:   2026-01-05

  Add comment to asterisk.conf.sample clarifying that template sections are ignored.

  Resolves: #1692

#### chan_websocket: Use the channel's ability to poll fds for the websocket read.
  Author: George Joseph
  Date:   2025-12-30

  We now add the websocket's file descriptor to the channel's fd array and let
  it poll for data availability instead if having a dedicated thread that
  does the polling. This eliminates the thread and allows removal of most
  explicit locking since the core channel code will lock the channel to prevent
  simultaneous calls to webchan_read, webchan_hangup, etc.

  While we were here, the hangup code was refactored to use ast_hangup_with_cause
  instead of directly queueing an AST_CONTROL_HANGUP frame.  This allows us
  to set hangup causes and generate snapshots.

  For a bit of extra debugging, a table of websocket close codes was added
  to http_websocket.h with an accompanying "to string" function added to
  res_http_websocket.c

  Resolves: #1683

#### asterisk.c: Allow multi-byte characters on the Asterisk CLI.
  Author: Sean Bright
  Date:   2025-12-13

  Versions of libedit that support Unicode expect that the
  EL_GETCFN (the function that does character I/O) will fill in a
  `wchar_t` with a character, which may be multi-byte. The built-in
  function that libedit provides, but does not expose with a public API,
  does properly handle multi-byte sequences.

  Due to the design of Asterisk's console processing loop, Asterisk
  provides its own implementation which does not handle multi-byte
  characters. Changing Asterisk to use libedit's built-in function would
  be ideal, but would also require changing some fundamental things
  about console processing which could be fairly disruptive.

  Instead, we bring in libedit's `read_char` implementation and modify
  it to suit our specific needs.

  Resolves: #60

#### func_presencestate.c: Allow `NOT_SET` to be set from CLI.
  Author: Sean Bright
  Date:   2026-01-01

  Resolves: #1647

#### res/ari/resource_bridges.c: Normalize channel_format ref handling for bridge media
  Author: Peter Krall
  Date:   2025-12-17

  Always take an explicit reference on the format used for bridge playback
  and recording channels, regardless of where it was sourced, and release
  it after prepare_bridge_media_channel. This aligns the code paths and
  avoids mixing borrowed and owned references while preserving behavior.

  Fixes: #1648

#### res_geolocation:  Fix multiple issues with XML generation.
  Author: George Joseph
  Date:   2025-12-17

  * 3d positions were being rendered without an enclosing `<gml:pos>`
    element resulting in invalid XML.
  * There was no way to set the `id` attribute on the enclosing `tuple`, `device`
    and `person` elements.
  * There was no way to set the value of the `deviceID` element.
  * Parsing of degree and radian UOMs was broken resulting in them appearing
    outside an XML element.
  * The UOM schemas for degrees and radians were reversed.
  * The Ellipsoid shape was missing and the Ellipse shape was defined multiple
    times.
  * The `crs` location_info parameter, although documented, didn't work.
  * The `pos3d` location_info parameter appears in some documentation but
    wasn't being parsed correctly.
  * The retransmission-allowed and retention-expiry sub-elements of usage-rules
    were using the `gp` namespace instead of the `gbp` namespace.

  In addition to fixing the above, several other code refactorings were
  performed and the unit test enhanced to include a round trip
  XML -> eprofile -> XML validation.

  Resolves: #1667

  UserNote: Geolocation: Two new optional profile parameters have been added.
  * `pidf_element_id` which sets the value of the `id` attribute on the top-level
    PIDF-LO `device`, `person` or `tuple` elements.
  * `device_id` which sets the content of the `<deviceID>` element.
  Both parameters can include channel variables.

  UpgradeNote: Geolocation: In order to correct bugs in both code and
  documentation, the following changes to the parameters for GML geolocation
  locations are now in effect:
  * The documented but unimplemented `crs` (coordinate reference system) element
    has been added to the location_info parameter that indicates whether the `2d`
    or `3d` reference system is to be used. If the crs isn't valid for the shape
    specified, an error will be generated. The default depends on the shape
    specified.
  * The Circle, Ellipse and ArcBand shapes MUST use a `2d` crs.  If crs isn't
    specified, it will default to `2d` for these shapes.
    The Sphere, Ellipsoid and Prism shapes MUST use a `3d` crs. If crs isn't
    specified, it will default to `3d` for these shapes.
    The Point and Polygon shapes may use either crs.  The default crs is `2d`
    however so if `3d` positions are used, the crs must be explicitly set to `3d`.
  * The `geoloc show gml_shape_defs` CLI command has been updated to show which
    coordinate reference systems are valid for each shape.
  * The `pos3d` element has been removed in favor of allowing the `pos` element
    to include altitude if the crs is `3d`.  The number of values in the `pos`
    element MUST be 2 if the crs is `2d` and 3 if the crs is `3d`.  An error
    will be generated for any other combination.
  * The angle unit-of-measure for shapes that use angles should now be included
    in the respective parameter.  The default is `degrees`. There were some
    inconsistent references to `orientation_uom` in some documentation but that
    parameter never worked and is now removed.  See examples below.
  Examples...
  ```
    location_info = shape="Sphere", pos="39.0 -105.0 1620", radius="20"
    location_info = shape="Point", crs="3d", pos="39.0 -105.0 1620"
    location_info = shape="Point", pos="39.0 -105.0"
    location_info = shape=Ellipsoid, pos="39.0 -105.0 1620", semiMajorAxis="20"
                  semiMinorAxis="10", verticalAxis="0", orientation="25 degrees"
    pidf_element_id = ${CHANNEL(name)}-${EXTEN}
    device_id = mac:001122334455
    Set(GEOLOC_PROFILE(pidf_element_id)=${CHANNEL(name)}/${EXTEN})
  ```

#### stasis/control.c: Add destructor to timeout_datastore.
  Author: George Joseph
  Date:   2025-12-31

  The timeout_datastore was missing a destructor resulting in a leak
  of 16 bytes for every outgoing ARI call.

  Resolves: #1681

#### func_talkdetect.c: Remove reference to non-existent variables.
  Author: Sean Bright
  Date:   2025-12-30


#### configure.ac: use AC_PATH_TOOL for nm
  Author: Nathaniel Wesley Filardo
  Date:   2025-11-27

  `nm` might, especially in cross-compilation scenarios, be available but prefixed with the target triple. So: use `AC_PATH_TOOL` rather than `AC_PATH_PROG` to find it. (See https://www.gnu.org/software/autoconf/manual/autoconf-2.68/html_node/Generic-Programs.html .)

  Found and proposed fix tested by cross-compiling Asterisk using Nixpkgs on x86_64 targeting aarch64. :)

#### res_pjsip_mwi: Fix off-nominal endpoint ao2 ref leak in mwi_get_notify_data
  Author: Alexei Gradinari
  Date:   2025-12-29

  Delay acquisition of the ast_sip_endpoint reference in mwi_get_notify_data()
  to avoid an ao2 ref leak on early-return error paths.

  Move ast_sip_subscription_get_endpoint() to just before first use so all
  acquired references are properly cleaned up.

  Fixes: #1675

#### res_pjsip_messaging: Add support for following 3xx redirects
  Author: Maximilian Fridrich
  Date:   2025-11-07

  This commit integrates the redirect module into res_pjsip_messaging
  to enable following 3xx redirect responses for outgoing SIP MESSAGEs.

  When follow_redirect_methods contains 'message' on an endpoint, Asterisk
  will now follow 3xx redirect responses for MESSAGEs, similar to how
  it behaves for INVITE responses.

  Resolves: #1576

  UserNote: A new pjsip endpoint option follow_redirect_methods was added.
  This option is a comma-delimited, case-insensitive list of SIP methods
  for which SIP 3XX redirect responses are followed. An alembic upgrade
  script has been added for adding this new option to the Asterisk
  database.

#### res_pjsip: Introduce redirect module for handling 3xx responses
  Author: Maximilian Fridrich
  Date:   2025-11-07

  This commit introduces a new redirect handling module that provides
  infrastructure for following SIP 3xx redirect responses. The redirect
  functionality respects the endpoint's redirect_method setting and only
  follows redirects when set to 'uri_pjsip'. This infrastructure can be
  used by any PJSIP module that needs to handle 3xx redirect responses.

#### app_mixmonitor.c: Fix crash in mixmonitor_ds_remove_and_free when datastore is NULL
  Author: Tinet-mucw
  Date:   2025-12-25

  The datastore may be NULL, so a null pointer check needs to be added.

  Resolves: #1673

#### res_pjsip_refer: don't defer session termination for ari transfer
  Author: Sven Kube
  Date:   2025-10-23

  Allow session termination during an in progress ari handled transfer.

#### chan_dahdi.conf.sample: Avoid warnings with default configs.
  Author: Naveen Albert
  Date:   2025-10-23

  callgroup and pickupgroup may only be specified for FXO-signaled channels;
  however, the chan_dahdi sample config had these options uncommented in
  the [channels] section, thus applying these settings to all channels,
  resulting in warnings. Comment these out so there are no warnings with
  an unmodified sample config.

  Resolves: #1552

#### main/dial.c: Set channel hangup cause on timeout in handle_timeout_trip
  Author: sarangr7
  Date:   2025-12-18

  When dial attempts timeout in the core dialing API, the channel's hangup
  cause was not being set before hanging up. Only the ast_dial_channel
  structure's internal cause field was updated, but the actual ast_channel
  hangup cause remained unset.

  This resulted in incorrect or missing hangup cause information being
  reported through CDRs, AMI events, and other mechanisms that read the
  channel's hangup cause when dial timeouts occurred via applications
  using the dialing API (FollowMe, Page, etc.).

  The fix adds proper channel locking and sets AST_CAUSE_NO_ANSWER on
  the channel before calling ast_hangup(), ensuring consistent hangup
  cause reporting across all interfaces.

  Resolves: #1660

#### cel: Add missing manager documentation.
  Author: Sean Bright
  Date:   2025-12-12

  The LOCAL_OPTIMIZE_BEGIN, STREAM_BEGIN, STREAM_END, and DTMF CEL
  events were not all documented in the CEL configuration file or the
  manager documentation for the CEL event.

#### res_odbc: Use SQL_SUCCEEDED() macro where applicable.
  Author: Sean Bright
  Date:   2025-12-17

  This is just a cleanup of some repetitive code.

#### rtp/rtcp: Configure dual-stack behavior via IPV6_V6ONLY
  Author: Justin T. Gibbs
  Date:   2025-12-21

  Dual-stack behavior (simultaneous listening for IPV4 and IPV6
  connections on a single socket) is required by Asterisk's ICE
  implementation.  On systems with the IPV6_V6ONLY sockopt, set
  the option to 0 (dual-stack enabled) when binding to the IPV6
  any address. This ensures correct behavior regardless of the
  system's default dual-stack configuration.

#### http.c: Include remote address in URI handler message.
  Author: Sean Bright
  Date:   2025-12-22

  Resolves: #1662

#### Disable device state caching for ephemeral channels
  Author: phoneben
  Date:   2025-12-09

  chan_audiosocket/chan_rtp/res_stasis_snoop: Disable device state caching for ephemeral channels

  Resolves: #1638

#### chan_websocket: Add locking in send_event and check for NULL websocket handle.
  Author: George Joseph
  Date:   2025-12-10

  On an outbound websocket connection, when the triggering caller hangs up,
  webchan_hangup() closes the outbound websocket session and sets the websocket
  session handle to NULL.  If the hangup happened in the tiny window between
  opening the outbound websocket connection and before read_thread_handler()
  was able to send the MEDIA_START message, it could segfault because the
  websocket session handle was NULL.  If it didn't actually segfault, there was
  also the possibility that the websocket instance wouldn't get cleaned up which
  could also cause the channel snapshot to not get cleaned up.  That could
  cause memory leaks and `core show channels` to list phantom WebSocket
  channels.

  To prevent the race, the send_event() macro now locks the websocket_pvt
  instance and checks the websocket session handle before attempting to send
  the MEDIA_START message.

  Resolves: #1643
  Resolves: #1645

#### Fix false null-deref warning in channel_state
  Author: phoneben
  Date:   2025-12-08

  Resolve analyzer warning in channel_state by checking AST_FLAG_DEAD on snapshot, which is guaranteed non-NULL.

  Resolves: #1430

#### endpoint.c: Plug a memory leak in ast_endpoint_shutdown().
  Author: George Joseph
  Date:   2025-12-08

  Commit 26795be introduced a memory leak of ast_endpoint when
  ast_endpoint_shutdown() was called. The leak occurs only if a configuration
  change removes an endpoint and isn't related to call volume or the length of
  time asterisk has been running.  An ao2_ref(-1) has been added to
  ast_endpoint_shutdown() to plug the leak.

  Resolves: #1635

#### Revert "func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()"
  Author: Sean Bright
  Date:   2025-12-03

  This reverts commit 517766299093d7a9798af68b39951ed8b2469836.

  For rationale, see #1621 and #1606

#### cel_manager.c: Correct manager event mask for CEL events.
  Author: Sean Bright
  Date:   2025-12-05

  There is no EVENT_FLAG_CEL and these events are raised with as
  EVENT_FLAG_CALL.

#### app_queue.c: Update docs to correct QueueMemberPause event name.
  Author: Sean Bright
  Date:   2025-12-04


#### taskprocessors: Improve logging and add new cli options
  Author: Mike Bradeen
  Date:   2025-10-28

  This change makes some small changes to improve log readability in
  addition to the following changes:

  Modified 'core show taskprocessors' to now show Low time and High time
  for task execution.

  New command 'core show taskprocessor name <taskprocessor-name>' to dump
  taskprocessor info and current queue.

  Addionally, a new test was added to demonstrate the 'show taskprocessor
  name' functionality:
  test execute category /main/taskprocessor/ name taskprocessor_cli_show

  Setting 'core set debug 3 taskprocessor.c' will now log pushed tasks.
  (Warning this is will cause extremely high levels of logging at even
  low traffic levels.)

  Resolves: #1566

  UserNote: New CLI command has been added -
  core show taskprocessor name <taskprocessor-name>

#### manager: fix double free of criteria variable when adding filter
  Author: Michal Hajek
  Date:   2025-10-13

  Signed-off-by: Michal Hajek <michal.hajek@daktela.com>

  Fixes: #1531

#### app_stream_echo.c: Check that stream is non-NULL before dereferencing.
  Author: Sean Bright
  Date:   2025-12-01

  Also re-order and rename the arguments of `stream_echo_write_error` to
  match those of `ast_write_stream` for consistency.

  Resolves: #1427

#### abstract_jb.c: Remove redundant timer check per static analysis.
  Author: Sean Bright
  Date:   2025-12-01

  While this check is technically unnecessary, it also was not harmful.

  The 2 other items mentioned in the linked issue are false positives
  and require no action.

  Resolves: #1417

#### channelstorage_cpp: Fix fallback return value in channelstorage callback
  Author: phoneben
  Date:   2025-11-26

  callback returned the last iterated channel when no match existed, causing invalid channel references and potential double frees. Updated to correctly return NULL when there is no match.

  Resolves: #1609

#### ccss:  Add option to ccss.conf to globally disable it.
  Author: George Joseph
  Date:   2025-11-19

  The Call Completion Supplementary Service feature is rarely used but many of
  it's functions are called by app_dial and channel.c "just in case".  These
  functions lock and unlock the channel just to see if CCSS is enabled on it,
  which it isn't 99.99% of the time.

  UserNote: A new "enabled" parameter has been added to ccss.conf.  It defaults
  to "yes" to preserve backwards compatibility but CCSS is rarely used so
  setting "enabled = no" in the "general" section can save some unneeded channel
  locking operations and log message spam.  Disabling ccss will also prevent
  the func_callcompletion and chan_dahdi modules from loading.

  DeveloperNote: A new API ast_is_cc_enabled() has been added.  It should be
  used to ensure that CCSS is enabled before making any other ast_cc_* calls.

#### app_directed_pickup.c: Change some log messages from NOTICE to VERBOSE.
  Author: George Joseph
  Date:   2025-11-20

  UpgradeNote: In an effort to reduce log spam, two normal progress
  "pickup attempted" log messages from app_directed_pickup have been changed
  from NOTICE to VERBOSE(3).  This puts them on par with other normal
  dialplan progress messages.

#### chan_websocket: Fix crash on DTMF_END event.
  Author: Sean Bright
  Date:   2025-11-20

  Resolves: #1604
#### chan_websocket.c: Tolerate other frame types
  Author: Joe Garlick
  Date:   2025-11-12

  Currently, if chan_websocket receives an un supported frame like comfort noise it will exit the websocket. The proposed change is to tolerate the other frames by not sending them down the websocket but instead just ignoring them.

  Resolves: #1587

#### app_reload: Fix Reload() without arguments.
  Author: Naveen Albert
  Date:   2025-11-17

  Calling Reload() without any arguments is supposed to reload
  everything (equivalent to a 'core reload'), but actually does
  nothing. This is because it was calling ast_module_reload with
  an empty string, and the argument needs to explicitly be NULL.

  Resolves: #1597

#### pbx.c: Print new context count when reloading dialplan.
  Author: Naveen Albert
  Date:   2025-11-17

  When running "dialplan reload", the number of contexts reported
  is initially wrong, as it is the old context count. Running
  "dialplan reload" a second time returns the correct number of
  contexts that are loaded. This can confuse users into thinking
  that the reload didn't work successfully the first time.

  This counter is currently only incremented when iterating the
  old contexts prior to the context merge; at the very end, get
  the current number of elements in the context hash table and
  report that instead. This way, the count is correct immediately
  whenever a reload occurs.

  Resolves: #1599

#### Makefile: Add module-list-* targets.
  Author: C. Maj
  Date:   2025-11-17

  Convenience wrappers for showing modules at various support levels.

  * module-list-core
  * module-list-extended
  * module-list-deprecated

  Resolves: #1572

  UserNote: Try "make module-list-deprecated" to see what modules
  are on their way out the door.

#### app_disa: Avoid use of removed ResetCDR() option.
  Author: Naveen Albert
  Date:   2025-11-14

  Commit a46d5f9b760f84b9f27f594b62507c1443aa661b removed the deprecated
  'e' option to ResetCDR; this now causes DISA() to emit a warning
  if attempting to call ResetCDR() with the deprecated option (in
  all cases except when the no answer option is provided). Rewrite
  the code to do this the current way.

  Resolves: #1592

#### core_unreal.c: Use ast instead of p->chan to get the DIALSTATUS variable
  Author: Tinet-mucw
  Date:   2025-11-13

  After p->chan = NULL, ast still points to the valid channel object,
  using ast safely accesses the channel's DIALSTATUS variable before it's fully destroyed

  Resolves: #1590

#### ast_coredumper: Fix multiple issues
  Author: George Joseph
  Date:   2025-11-07

  * Fixed an issue with tarball-coredumps when asterisk was invoked without an
  absolute path.

  * Fixed an issue with gdb itself segfaulting when trying to get symbols from
  separate debuginfo files.  The command line arguments needed to be altered
  such that the gdbinit files is loaded before anything else but the
  `dump-asterisk` command is run after full initialization.

  In the embedded gdbinit script:

  * The extract_string_symbol function needed a `char *` cast to work properly.

  * The s_strip function needed to be updated to continue to work with the
  cpp_map_name_id channel storage backend.

  * A new function was added to dump the channels when cpp_map_name_id was
  used.

  * The Channel object was updated to account for the new channel storage
  backends

  * The show_locks function was refactored to work correctly.

#### app_mixmonitor: Add 's' (skip) option to delay recording.
  Author: Daouda Taha
  Date:   2025-10-28

  The 's' (skip) option delays MixMonitor recording until the specified number of seconds
  (can be fractional) have elapsed since MixMonitor was invoked.

  No audio is written to the recording file during this time. If the call ends before this
  period, no audio will be saved. This is useful for avoiding early audio such as
  announcements, ringback tones, or other non-essential sounds.

  UserNote: This change introduces a new 's(<seconds>)' (skip) option to the MixMonitor
  application. Example:
    MixMonitor(${UNIQUEID}.wav,s(3))

  This skips recording for the first 3 seconds before writing audio to the file.
  Existing MixMonitor behavior remains unchanged when the 's' option is not used.

#### stasis: switch stasis show topics temporary container from list - RBtree
  Author: phoneben
  Date:   2025-11-11

  switch stasis show topics temporary container from list to RB-tree
  minimizing lock time

  Resolves: #1585

#### app_dtmfstore: Avoid a potential buffer overflow.
  Author: Sean Bright
  Date:   2025-11-07

  Prefer snprintf() so we can readily detect if our output was
  truncated.

  Resolves: #1421

#### main: Explicitly mark case statement fallthrough as such.
  Author: Sean Bright
  Date:   2025-11-07

  Resolves: #1442

#### bridge_softmix: Return early on topology allocation failure.
  Author: Sean Bright
  Date:   2025-11-07

  Resolves: #1446

#### bridge_simple: Increase code verbosity for clarity.
  Author: Sean Bright
  Date:   2025-11-07

  There's no actual problem here, but I can see how it might by
  confusing.

  Resolves: #1444

#### app_queue.c: Only announce to head caller if announce_to_first_user
  Author: Kristian F. Høgh
  Date:   2025-10-30

  Only make announcements to head caller if announce_to_first_user is true

  Fixes: #1568

  UserNote: When announce_to_first_user is false, no announcements are played to the head caller

#### chan_websocket: Add ability to place a MARK in the media stream.
  Author: George Joseph
  Date:   2025-11-05

  Also cleaned up a few unused #if blocks, and started sending a few ERROR
  events back to the apps.

  Resolves: #1574

  DeveloperNote: Apps can now send a `MARK_MEDIA` command with an optional
  `correlation_id` parameter to chan_websocket which will be placed in the
  media frame queue. When that frame is dequeued after all intervening media
  has been played to the core, chan_websocket will send a
  `MEDIA_MARK_PROCESSED` event to the app with the same correlation_id
  (if any).

#### chan_websocket: Add capability for JSON control messages and events.
  Author: George Joseph
  Date:   2025-10-22

  With recent enhancements to chan_websocket, the original plain-text
  implementation of control messages and events is now too limiting.  We
  probably should have used JSON initially but better late than never.  Going
  forward, enhancements that require control message or event changes will
  only be done to the JSON variants and the plain-text variants are now
  deprecated but not yet removed.

  * Added the chan_websocket.conf config file that allows setting which control
  message format to use globally: "json" or "plain-text".  "plain-text" is the
  default for now to preserve existing behavior.

  * Added a dialstring option `f(json|plain-text)` to allow the format to be
  overridden on a call-by-call basis.  Again, 'plain-text' is the default for
  now to preserve existing behavior.

  The JSON for commands sent by the app to Asterisk must be...
  `{ "command": "<command>" ... }` where `<command>` is one of `ANSWER`, `HANGUP`,
  `START_MEDIA_BUFFERING`, etc.  The `STOP_MEDIA_BUFFERING` command takes an
  additional, optional parameter to be returned in the corresponding
  `MEDIA_BUFFERING_COMPLETED` event:
  `{ "command": "STOP_MEDIA_BUFFERING", "correlation_id": "<correlation id>" }`.

  The JSON for events sent from Asterisk to the app will be...
  `{ "event": "<event>", "channel_id": "<channel_id>" ... }`.
  The `MEDIA_START` event will now look like...

  ```
  {
    "event": "MEDIA_START",
    "connection_id": "media_connection1",
    "channel": "WebSocket/media_connection1/0x5140001a0040",
    "channel_id": "1761245643.1",
    "format": "ulaw",
    "optimal_frame_size": 160,
    "ptime": 20,
    "channel_variables": {
      "DIALEDPEERNUMBER": "media_connection1/c(ulaw)",
      "MEDIA_WEBSOCKET_CONNECTION_ID": "media_connection1",
      "MEDIA_WEBSOCKET_OPTIMAL_FRAME_SIZE": "160"
    }
  }
  ```

  Note the addition of the channel variables which can't be supported
  with the plain-text formatting.

  The documentation will be updated with the exact formats for all commands
  and events.

  Resolves: #1546
  Resolves: #1563

  DeveloperNote: The chan_websocket plain-text control and event messages are now
  deprecated (but remain the default) in favor of JSON formatted messages.
  See https://docs.asterisk.org/Configuration/Channel-Drivers/WebSocket for
  more information.

  DeveloperNote: A "transport_data" parameter has been added to the
  channels/externalMedia ARI endpoint which, for websocket, allows the caller
  to specify parameters to be added to the dialstring for the channel.  For
  instance, `"transport_data": "f(json)"`.

#### build: Add menuselect options to facilitate code tracing and coverage
  Author: George Joseph
  Date:   2025-10-30

  The following options have been added to the menuselect "Compiler Flags"
  section...

  CODE_COVERAGE: The ability to enable code coverage via the `--enable-coverage`
  configure flag has existed for many years but changing it requires
  re-running ./configure which is painfully slow.  With this commit, you can
  now enable and disable it via menuselect. Setting this option adds the
  `-ftest-coverage` and `-fprofile-arcs` flags on the gcc and ld command lines.
  It also sets DONT_OPTIMIZE. Note: If you use the `--enable-coverage` configure
  flag, you can't turn it off via menuselect so choose one method and stick to
  it.

  KEEP_FRAME_POINTERS: This option sets `-fno-omit-frame-pointers` on the gcc
  command line which can facilitate debugging with 'gdb' and tracing with 'perf'.
  Unlike CODE_COVERAGE, this option doesn't depend on optimization being
  disabled.  It does however conflict with COMPILE_DOUBLE.

#### channelstorage:  Allow storage driver read locking to be skipped.
  Author: George Joseph
  Date:   2025-11-06

  After PR #1498 added read locking to channelstorage_cpp_map_name_id, if ARI
  channels/externalMedia was called with a custom channel id AND the
  cpp_map_name_id channel storage backend is in use, a deadlock can occur when
  hanging up the channel. It's actually triggered in
  channel.c:__ast_channel_alloc_ap() when it gets a write lock on the
  channelstorage driver then subsequently does a lookup for channel uniqueid
  which now does a read lock. This is an invalid operation and causes the lock
  state to get "bad". When the channels try to hang up, a write lock is
  attempted again which hangs and causes the deadlock.

  Now instead of the cpp_map_name_id channelstorage driver "get" APIs
  automatically performing a read lock, they take a "lock" parameter which
  allows a caller who already has a write lock to indicate that the "get" API
  must not attempt its own lock.  This prevents the state from getting mesed up.

  The ao2_legacy driver uses the ao2 container's recursive mutex so doesn't
  have this issue but since it also implements the common channelstorage API,
  it needed its "get" implementations updated to take the lock parameter. They
  just don't use it.

  Resolves: #1578

#### res_audiosocket: fix temporarily unavailable
  Author: Roman Pertsev
  Date:   2025-10-07

  Operations on non-blocking sockets may return a resource temporarily unavailable error (EAGAIN or EWOULDBLOCK). This is not a fatal error but a normal condition indicating that the operation would block.

  This patch corrects the handling of this case. Instead of incorrectly treating it as a reason to terminate the connection, the code now waits for data to arrive on the socket.

#### safe_asterisk: Resolve a POSIX sh problem and restore globbing behavior.
  Author: Sean Bright
  Date:   2025-10-22

  * Using `==` with the POSIX sh `test` utility is UB.
  * Switch back to using globs instead of using `$(find … | sort)`.
  * Fix a missing redirect when checking for the OS type.

  Resolves: #1554

#### res_stir_shaken: Add STIR_SHAKEN_ATTESTATION dialplan function.
  Author: George Joseph
  Date:   2025-10-24

  Also...

  * Refactored the verification datastore process so instead of having
  a separate channel datastore for each verification result, there's only
  one channel datastore with a vector of results.

  * Refactored some log messages to include channel name and removed
  some that would be redundant if a memory allocation failed.

  Resolves: #781

  UserNote: The STIR_SHAKEN_ATTESTATION dialplan function has been added
  which will allow suppressing attestation on a call-by-call basis
  regardless of the profile attached to the outgoing endpoint.

#### iostream.c: Handle TLS handshake attacks in order to resolve the issue of exceeding the maximum number of HTTPS sessions.
  Author: Tinet-mucw
  Date:   2025-10-26

  The TCP three-way handshake completes, but if the server is under a TLS handshake attack, asterisk will get stuck at SSL_do_handshake().
  In this case, a timeout mechanism should be set for the SSL/TLS handshake process to prevent indefinite waiting during the SSL handshake.

  Resolves: #1559

#### chan_pjsip: Disable SSRC change for WebRTC endpoints.
  Author: George Joseph
  Date:   2025-10-21

  Commit b333ee3b introduced a fix to chan_pjsip that addressed RTP issues with
  blind transfers and some SBCs.  Unfortunately, the fix broke some WebRTC
  clients that are sensitive to SSRC changes and non-monotonic timestamps so
  the fix is now disabled for endpoints with the "bundle" parameter set to true.

  Resolves: #1535

#### chan_websocket: Add channel_id to MEDIA_START, DRIVER_STATUS and DTMF_END events.
  Author: gauravs456
  Date:   2025-10-21

  Resolves: #1544

#### safe_asterisk:  Fix logging and sorting issue.
  Author: George Joseph
  Date:   2025-10-17

  Re-enabled "TTY=9" which was erroneously disabled as part of a recent
  security fix and removed another logging "fix" that was added.

  Also added a sort to the "find" that enumerates the scripts to be sourced so
  they're sourced in the correct order.

  Resolves: #1539

#### Fix Endianness detection in utils.h for non-Linux
  Author: Christoph Moench-Tegeder
  Date:   2025-10-19

  Commit 43bf8a4ded7a65203b766b91eaf8331a600e9d8d introduced endian
  dependend byte-swapping code in include/asterisk/utils.h, where the
  endianness was detected using the __BYTE_ORDER macro. This macro
  lives in endian.h, which on Linux is included implicitely (by the
  network-related headers, I think), but on FreeBSD the headers are
  laid out differently and we do not get __BYTE_ORDER the implicit way.

  Instead, this makes the usage of endian.h explicit by including it
  where we need it, and switches the BYTE_ORDER/*ENDIAN macros to the
  POSIX-defined ones (see
  https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/endian.h.html
  for standard compliance). Additionally, this adds a compile-time check
  for the endianness-logic: compilation will fail if neither big nor
  little endian can be detected.

  Fixes: #1536

#### app_queue.c: Fix error in Queue parameter documentation.
  Author: Ben Ford
  Date:   2025-10-20

  When macro was removed in Asterisk 21, the parameter documentation in
  code was not updated to reflect the correct numerization for gosub. It
  still stated that it was the seventh parameter, but got shifted to the
  sixth due to the removal of macro. This has been updated to correctly
  reflect the parameter order, and a note has been added to the XML that
  states this was done after the initial commit.

  Fixes: #1534

  UpgradeNote: As part of Asterisk 21, macros were removed from Asterisk.
  This resulted in argument order changing for the Queue dialplan
  application since the macro argument was removed. Upgrade notice was
  missed when this was done, so this upgrade note has been added to
  provide a record of such and a notice to users who may have not upgraded
  yet.

#### devicestate: Don't publish redundant device state messages.
  Author: Joshua C. Colp
  Date:   2025-10-17

  When publishing device state check the local cache for the
  existing device state. If the new device state is unchanged
  from the prior one, don't bother publishing the update. This
  can reduce the work done by consumers of device state, such
  as hints and app_queue, by not publishing a message to them.

  These messages would most often occur with devices that are
  seeing numerous simultaneous channels. The underlying device
  state would remain as in use throughout, but an update would
  be published as channels are created and hung up.

#### chan_pjsip: Add technology-specific off-nominal hangup cause to events.
  Author: George Joseph
  Date:   2025-10-14

  Although the ISDN/Q.850/Q.931 hangup cause code is already part of the ARI
  and AMI hangup and channel destroyed events, it can be helpful to know what
  the actual channel technology code was if the call was unsuccessful.
  For PJSIP, it's the SIP response code.

  * A new "tech_hangupcause" field was added to the ast_channel structure along
  with ast_channel_tech_hangupcause() and ast_channel_tech_hangupcause_set()
  functions.  It should only be set for off-nominal terminations.

  * chan_pjsip was modified to set the tech hangup cause in the
  chan_pjsip_hangup() and chan_pjsip_session_end() functions.  This is a bit
  tricky because these two functions aren't always called in the same order.
  The channel that hangs up first will get chan_pjsip_session_end() called
  first which will trigger the core to call chan_pjsip_hangup() on itself,
  then call chan_pjsip_hangup() on the other channel.  The other channel's
  chan_pjsip_session_end() function will get called last.  Unfortunately,
  the other channel's HangupRequest events are sent before chan_pjsip has had a
  chance to set the tech hangupcause code so the HangupRequest events for that
  channel won't have the cause code set.  The ChannelDestroyed and Hangup
  events however will have the code set for both channels.

  * A new "tech_cause" field was added to the ast_channel_snapshot_hangup
  structure. This is a public structure so a bit of refactoring was needed to
  preserve ABI compatibility.

  * The ARI ChannelHangupRequest and ChannelDestroyed events were modified to
  include the "tech_cause" parameter in the JSON for off-nominal terminations.
  The parameter is suppressed for nominal termination.

  * The AMI SoftHangupRequest, HangupRequest and Hangup events were modified to
  include the "TechCause" parameter for off-nominal terminations. Like their ARI
  counterparts, the parameter is suppressed for nominal termination.

  DeveloperNote: A "tech_cause" parameter has been added to the
  ChannelHangupRequest and ChannelDestroyed ARI event messages and a "TechCause"
  parameter has been added to the HangupRequest, SoftHangupRequest and Hangup
  AMI event messages.  For chan_pjsip, these will be set to the last SIP
  response status code for off-nominally terminated calls.  The parameter is
  suppressed for nominal termination.

#### res_audiosocket: add message types for all slin sample rates
  Author: Sven Kube
  Date:   2025-10-10

  Extend audiosocket messages with types 0x11 - 0x18 to create asterisk
  frames in slin12, slin16, slin24, slin32, slin44, slin48, slin96, and
  slin192 format, enabling the transmission of audio at a higher sample
  rates. For audiosocket messages sent by Asterisk, the message kind is
  determined by the format of the originating asterisk frame.

  UpgradeNote: New audiosocket message types 0x11 - 0x18 has been added
  for slin12, slin16, slin24, slin32, slin44, slin48, slin96, and
  slin192 audio. External applications using audiosocket may need to be
  updated to support these message types if the audiosocket channel is
  created with one of these audio formats.

#### res_fax.c: lower FAXOPT read warning to debug level
  Author: phoneben
  Date:   2025-10-03

  Reading ${FAXOPT()} before a fax session is common in dialplans to check fax state.
  Currently this logs an error even when no fax datastore exists, creating excessive noise.
  Change these messages to ast_debug(3, …) so they appear only with debug enabled.

  Resolves: #1509

#### endpoints: Remove need for stasis subscription.
  Author: Joshua C. Colp
  Date:   2025-10-10

  When an endpoint is created in the core of Asterisk a subscription
  was previously created alongside it to monitor any channels being
  destroyed that were related to it. This was done by receiving all
  channel snapshot updates for every channel and only reacting when
  it was indicated that the channel was dead.

  This change removes this logic and instead provides an API call
  for directly removing a channel from an endpoint. This is called
  when channels are destroyed. This operation is fast, so blocking
  the calling thread for a short period of time doesn't have any
  noticeable impact.

#### app_queue: Allow stasis message filtering to work.
  Author: Joshua C. Colp
  Date:   2025-10-10

  The app_queue module subscribes on a per-dialed agent basis to both
  the bridge all and channel all topics to keep apprised of things going
  on involving them. This subscription has associated state that must
  be cleaned up when the subscription ends. This was done by setting
  a default router callback that only had logic to handle the case
  where the subscription ends. By using the default router callback
  all filtering for the subscription was disabled, causing unrelated
  messages to get published and handled by it.

  This change makes it so that an explicit route is added for the
  message type used for the message indicating the subscription has
  ended and removes the default router callback. This allows message
  filtering to occur on publishing reducing the messages to app_queue
  to only those it is interested in.

#### taskpool:  Fix some references to threadpool that should be taskpool.
  Author: George Joseph
  Date:   2025-10-10

  Resolves: #1478

#### Update contact information for anthm
  Author: Anthony Minessale
  Date:   2025-10-10


#### chan_websocket.c: Change payload references to command instead.
  Author: George Joseph
  Date:   2025-10-08

  Some of the tests in process_text_message() were still comparing to the
  websocket message payload instead of the "command" string.

  Resolves: #1525

#### func_callerid: Document limitation of DNID fields.
  Author: Naveen Albert
  Date:   2025-10-06

  The Dial() application does not propagate DNID fields, which is counter
  to the behavior of the other Caller ID fields. This behavior is likely
  intentional since the use of Dial theoretically suggests a new dialed
  number, but document this caveat to inform users of it.

  Resolves: #1519

#### func_channel: Allow R/W of ADSI CPE capability setting.
  Author: Naveen Albert
  Date:   2025-10-06

  Allow retrieving and setting the channel's ADSI capability from the
  dialplan.

  Resolves: #1514

  UserNote: CHANNEL(adsicpe) can now be read or written to change
  the channels' ADSI CPE capability setting.

#### core_unreal: Preserve ADSI capability when dialing Local channels.
  Author: Naveen Albert
  Date:   2025-10-06

  Dial() already preserves the ADSI capability by copying it to the new
  channel, but since Local channel pairs consist of two channels, we
  also need to copy the capability to the second channel.

  Resolves: #1517

#### func_hangupcause.c: Add access to Reason headers via HANGUPCAUSE()
  Author: Igor Goncharovsky
  Date:   2025-09-04

  As soon as SIP call may end with several Reason headers, we
  want to make all of them available through the HAGUPCAUSE() function.
  This implementation uses the same ao2 hash for cause codes storage
  and adds a flag to make difference between last processed sip
  message and content of reason headers.

  UserNote: Added a new option to HANGUPCAUSE to access additional
  information about hangup reason. Reason headers from pjsip
  could be read using 'tech_extended' cause type.

#### sig_analog: Allow '#' to end the inter-digit timeout when dialing.
  Author: Naveen Albert
  Date:   2025-10-03

  It is customary to allow # to terminate digit collection immediately
  when there would normally be a timeout. However, currently, users are
  forced to wait for the timeout to expire when dialing numbers that
  are prefixes of other valid matches, and there is no way to end the
  timeout early. Customarily, # terminates the timeout, but at the moment,
  this is just rejected unless there happens to be a matching extension
  ending in #.

  Allow # to terminate the timeout in cases where there is no dialplan
  match. This ensures that the dialplan is always respected, but if a
  valid extension has been dialed that happens to prefix other valid
  matches, # can be used to dial it immediately.

  Resolves: #1510

#### func_math: Add DIGIT_SUM function.
  Author: Naveen Albert
  Date:   2025-10-01

  Add a function (DIGIT_SUM) which returns the digit sum of a number.

  Resolves: #1499

  UserNote: The DIGIT_SUM function can be used to return the digit sum of
  a number.

#### app_sf: Add post-digit timer option to ReceiveSF.
  Author: Naveen Albert
  Date:   2025-10-01

  Add a sorely needed option to set a timeout between digits, rather than
  for receiving the entire number. This is needed if the number of digits
  being sent is unknown by the receiver in advance. Previously, we had
  to wait for the entire timer to expire.

  Resolves: #1493

  UserNote: The 't' option for ReceiveSF now allows for a timer since
  the last digit received, in addition to the number-wide timeout.

#### codec_builtin.c: Adjust some of the quality scores to reflect reality.
  Author: Naveen Albert
  Date:   2025-10-02

  Among the lower-quality voice codecs, some of the quality scores did
  not make sense relative to each other.

  For instance, quality-wise, G.729 > G.723 > PLC10.
  However, current scores do not uphold these relationships.

  Tweak the scores slightly to reflect more accurate relationships.

  Resolves: #1501

#### res_tonedetect: Fix formatting of XML documentation.
  Author: Naveen Albert
  Date:   2025-10-02

  Fix the indentation in the documentation for the variable list.

  Resolves: #1507

#### res_fax: Add XML documentation for channel variables.
  Author: Naveen Albert
  Date:   2025-10-02

  Document the channel variables currently set by SendFAX and ReceiveFAX.

  Resolves: #1505

#### channelstorage_cpp_map_name_id: Add read locking around retrievals.
  Author: George Joseph
  Date:   2025-10-01

  When we retrieve a channel from a C++ map, we actually get back a wrapper
  object that points to the channel then right after we retrieve it, we bump its
  reference count.  There's a tiny chance however that between those two
  statements a delete and/or unref might happen which would cause the wrapper
  object or the channel itself to become invalid resulting in a SEGV.  To avoid
  this we now perform a read lock on the driver around those statements.

  Resolves: #1491

#### app_dial: Allow fractional seconds for dial timeouts.
  Author: Naveen Albert
  Date:   2025-09-30

  Even though Dial() internally uses milliseconds for its dial timeouts,
  this capability has been mostly obscured from users as the argument is
  only parsed as an integer, thus forcing the use of whole seconds for
  timeouts.

  Parse it as a decimal instead so that timeouts can now truly have
  millisecond precision.

  Resolves: #1487

  UserNote: The answer and progress dial timeouts now have millisecond
  precision, instead of having to be whole numbers.

#### dsp.c: Make minor fixes to debug log messages.
  Author: Naveen Albert
  Date:   2025-10-01

  Commit dc8e3eeaaf094a3d16991289934093d5e7127680 improved the debug log
  messages in dsp.c. This makes two minor corrections to it:

  * Properly guard an added log statement in a conditional.
  * Don't add one to the hit count if there was no hit (however, we do
    still want to do this for the case where this is one).

  Resolves: #1496

#### config_options.c: Improve misleading warning.
  Author: Naveen Albert
  Date:   2025-09-30

  When running "config show help <module>", if no XML documentation exists
  for the specified module, "Module <module> not found." is returned,
  which is misleading if the module is loaded but simply has no XML
  documentation for its config. Improve the message to clarify that the
  module may simply have no config documentation.

  Resolves: #1489

#### func_scramble: Add example to XML documentation.
  Author: Naveen Albert
  Date:   2025-09-29

  The previous lack of an example made it ambiguous if the arguments went
  inside the function arguments or were part of the right-hand value.

  Resolves: #1485

#### sig_analog: Eliminate potential timeout with Last Number Redial.
  Author: Naveen Albert
  Date:   2025-09-29

  If Last Number Redial is used to redial, ensure that we do not wait
  for further digits. This was possible if the number that was last
  dialed is a prefix of another possible dialplan match. Since all we
  did is copy the number into the extension buffer, if other matches
  are now possible, there would thus be a timeout before the call went
  through. We now complete redialed calls immediaetly in all cases.

  Resolves: #1483

#### ARI: The bridges play and record APIs now handle sample rates > 8K correctly.
  Author: George Joseph
  Date:   2025-09-25

  The bridge play and record APIs were forcing the Announcer/Recorder channel
  to slin8 which meant that if you played or recorded audio with a sample
  rate > 8K, it was downsampled to 8K limiting the bandwidth.

  * The /bridges/play REST APIs have a new "announcer_format" parameter that
    allows the caller to explicitly set the format on the "Announcer" channel
    through which the audio is played into the bridge.  If not specified, the
    default depends on how many channels are currently in the bridge.  If
    a single channel is in the bridge, then the Announcer channel's format
    will be set to the same as that channel's.  If multiple channels are in the
    bridge, the channels will be scanned to find the one with the highest
    sample rate and the Announcer channel's format will be set to the slin
    format that has an equal to or greater than sample rate.

  * The /bridges/record REST API has a new "recorder_format" parameter that
    allows the caller to explicitly set the format on the "Recorder" channel
    from which audio is retrieved to write to the file.  If not specified,
    the Recorder channel's format will be set to the format that was requested
    to save the audio in.

  Resolves: #1479

  DeveloperNote: The ARI /bridges/play and /bridges/record REST APIs have new
  parameters that allow the caller to specify the format to be used on the
  "Announcer" and "Recorder" channels respecitvely.

#### res_pjsip_geolocation: Add support for Geolocation loc-src parameter
  Author: Max Grobecker
  Date:   2025-09-21

  This adds support for the Geolocation 'loc-src' parameter to res_pjsip_geolocation.
  The already existing config option 'location_source` in res_geolocation is documented to add a 'loc-src' parameter containing a user-defined FQDN to the 'Geolocation:' header,
  but that option had no effect as it was not implemented by res_pjsip_geolocation.

  If the `location_source` configuration option is not set or invalid, that parameter will not be added (this is already checked by res_geolocation).

  This commits adds already documented functionality.

#### sorcery: Move from threadpool to taskpool.
  Author: Joshua C. Colp
  Date:   2025-09-23

  This change moves observer invocation from the use of
  a threadpool to a taskpool. The taskpool options have also
  been adjusted to ensure that at least one taskprocessor
  remains available at all times.

#### stasis_channels.c: Make protocol_id optional to enable blind transfer via ari
  Author: Sven Kube
  Date:   2025-09-22

  When handling SIP transfers via ARI, there is no protocol_id in case of
  a blind transfer.

  Resolves: #1467

#### Fix some doxygen, typos and whitespace
  Author: Bastian Triller
  Date:   2025-09-21


#### stasis_channels.c: Add null check for referred_by in ast_ari_transfer_message_create
  Author: Sven Kube
  Date:   2025-09-18

  When handling SIP transfers via ARI, the `referred_by` field in
  `transfer_ari_state` may be null, since SIP REFER requests are not
  required to include a `Referred-By` header. Without this check, a null
  value caused the transfer to fail and triggered a NOTIFY with a 500
  Internal Server Error.

#### app_queue: Add NULL pointer checks in app_queue
  Author: phoneben
  Date:   2025-09-11

  Add NULL check for word_list before calling word_in_list()
  Add NULL checks for channel snapshots from ast_multi_channel_blob_get_channel()

  Resolves: #1425

#### app_externalivr: Prevent out-of-bounds read during argument processing.
  Author: Sean Bright
  Date:   2025-09-17

  Resolves: #1422

#### chan_dahdi: Add DAHDI_CHANNEL function.
  Author: Naveen Albert
  Date:   2025-09-11

  Add a dialplan function that can be used to get/set properties of
  DAHDI channels (as opposed to Asterisk channels). This exposes
  properties that were not previously available, allowing for certain
  operations to now be performed in the dialplan.

  Resolves: #1455

  UserNote: The DAHDI_CHANNEL function allows for getting/setting
  certain properties about DAHDI channels from the dialplan.

#### taskpool: Update versions for taskpool stasis options.
  Author: Joshua C. Colp
  Date:   2025-09-16


#### taskpool: Add taskpool API, switch Stasis to using it.
  Author: Joshua C. Colp
  Date:   2025-08-06

  This change introduces a new API called taskpool. This is a pool
  of taskprocessors. It provides the following functionality:

  1. Task pushing to a pool of taskprocessors
  2. Synchronous tasks
  3. Serializers for execution ordering of tasks
  4. Growing/shrinking of number of taskprocessors in pool

  This functionality already exists through the combination of
  threadpool+taskprocessors but through investigating I determined
  that this carries substantial overhead for short to medium duration
  tasks. The threadpool uses a single queue of work, and for management
  of threads it involves additional tasks.

  I wrote taskpool to eliminate the extra overhead and management
  as much as possible. Instead of a single queue of work each
  taskprocessor has its own queue and at push time a selector chooses
  the taskprocessor to queue the task to. Each taskprocessor also
  has its own thread like normal. This spreads out the tasks immediately
  and reduces contention on shared resources.

  Using the included efficiency tests the number of tasks that can be
  executed per second in a taskpool is 6-12 times more than an equivalent
  threadpool+taskprocessor setup.

  Stasis has been moved over to using this new API as it is a heavy consumer
  of threadpool+taskprocessors and produces a lot of tasks.

  UpgradeNote: The threadpool_* options in stasis.conf have now been deprecated
  though they continue to be read and used. They have been replaced with taskpool
  options that give greater control over the underlying taskpool used for stasis.

  DeveloperNote: The taskpool API has been added for common usage of a
  pool of taskprocessors. It is suggested to use this API instead of the
  threadpool+taskprocessor approach.

#### app_adsiprog: Fix possible NULL dereference.
  Author: Naveen Albert
  Date:   2025-09-10

  get_token can return NULL, but process_token uses this result without
  checking for NULL; as elsewhere, check for a NULL result to avoid
  possible NULL dereference.

  Resolves: #1419

#### manager.c: Fix presencestate object leak
  Author: Nathan Monfils
  Date:   2025-09-08

  ast_presence_state allocates subtype and message. We straightforwardly
  need to clean those up.

#### audiohook.c: Ensure correct AO2 reference is dereffed.
  Author: Sean Bright
  Date:   2025-09-10

  Part of #1440.

#### res_cliexec: Remove unnecessary casts to char*.
  Author: Naveen Albert
  Date:   2025-09-09

  Resolves: #1436

#### rtp_engine.c: Add exception for comfort noise payload.
  Author: Ben Ford
  Date:   2025-09-09

  In a previous commit, a change was made to
  ast_rtp_codecs_payload_code_tx_sample_rate to check for differing sample
  rates. This ended up returning an invalid payload int for comfort noise.
  A check has been added that returns early if the payload is in fact
  supposed to be comfort noise.

  Fixes: #1340

#### pbx_variables.c: Create real channel for "dialplan eval function".
  Author: Naveen Albert
  Date:   2025-09-09

  "dialplan eval function" has been using a dummy channel for function
  evaluation, much like many of the unit tests. However, sometimes, this
  can cause issues for functions that are not expecting dummy channels.
  As an example, ast_channel_tech(chan) is NULL on such channels, and
  ast_channel_tech(chan)->type consequently results in a NULL dereference.
  Normally, functions do not worry about this since channels executing
  dialplan aren't dummy channels.

  While some functions are better about checking for these sorts of edge
  cases, use a real channel with a dummy technology to make this CLI
  command inherently safe for any dialplan function that could be evaluated
  from the CLI.

  Resolves: #1434

#### res_rtp_asterisk.c: Use rtp->dtls in __rtp_sendto when rtcp mux is used.
  Author: George Joseph
  Date:   2025-09-23

  In __rtp_sendto(), the check for DTLS negotiation completion for rtcp packets
  needs to use the rtp->dtls structure instead of rtp->rtcp->dtls when
  AST_RTP_INSTANCE_RTCP_MUX is set.

  Resolves: #1474

#### chan_websocket: Fix codec validation and add passthrough option.
  Author: George Joseph
  Date:   2025-09-17

  * Fixed an issue in webchan_write() where we weren't detecting equivalent
    codecs properly.
  * Added the "p" dialstring option that puts the channel driver in
    "passthrough" mode where it will not attempt to re-frame or re-time
    media coming in over the websocket from the remote app.  This can be used
    for any codec but MUST be used for codecs that use packet headers or whose
    data stream can't be broken up on arbitrary byte boundaries. In this case,
    the remote app is fully responsible for correctly framing and timing media
    sent to Asterisk and the MEDIA text commands that could be sent over the
    websocket are disabled.  Currently, passthrough mode is automatically set
    for the opus, speex and g729 codecs.
  * Now calling ast_set_read_format() after ast_channel_set_rawreadformat() to
    ensure proper translation paths are set up when switching between native
    frames and slin silence frames.  This fixes an issue with codec errors
    when transcode_via_sln=yes.

  Resolves: #1462

#### res_ari: Ensure outbound websocket config has a websocket_client_id.
  Author: George Joseph
  Date:   2025-09-12

  Added a check to outbound_websocket_apply() that makes sure an outbound
  websocket config object in ari.conf has a websocket_client_id parameter.

  Resolves: #1457

#### chan_websocket.c: Add DTMF messages
  Author: Joe Garlick
  Date:   2025-09-04

  Added DTMF messages to the chan_websocket feature.

  When a user presses DTMF during a call over chan_websocket it will send a message like:
  "DTMF_END digit:1"

  Resolves: https://github.com/asterisk/asterisk-feature-requests/issues/70

#### app_queue.c: Add new global 'log_unpause_on_reason_change'
  Author: Igor Goncharovsky
  Date:   2025-09-02

  In many asterisk-based systems, the pause reason is used to separate
  pauses by type,and logically, changing the reason defines two intervals
  that should be accounted for separately. The introduction of a new
  option allows me to separate the intervals of operator inactivity in
  the log by the event of unpausing.

  UserNote: Add new global option 'log_unpause_on_reason_change' that
  is default disabled. When enabled cause addition of UNPAUSE event on
  every re-PAUSE with reason changed.


#### app_waitforsilence.c: Use milliseconds to calculate timeout time
  Author: Igor Goncharovsky
  Date:   2025-09-04

  The functions WaitForNoise() and WaitForSilence() use the time()
  functions to calculate elapsed time, which causes the timer to fire on
  a whole second boundary, and the actual function execution time to fire
  the timer may be 1 second less than expected. This fix replaces time()
  with ast_tvnow().

  Fixes: #1401

#### Fix missing ast_test_flag64 in extconf.c
  Author: Artem Umerov
  Date:   2025-08-29

  Fix missing ast_test_flag64 after https://github.com/asterisk/asterisk/commit/43bf8a4ded7a65203b766b91eaf8331a600e9d8d


#### pbx_builtins: Allow custom tone for WaitExten.
  Author: Naveen Albert
  Date:   2025-08-25

  Currently, the 'd' option will play dial tone while waiting
  for digits. Allow it to accept an argument for any tone from
  indications.conf.

  Resolves: #1396

  UserNote: The tone used while waiting for digits in WaitExten
  can now be overridden by specifying an argument for the 'd'
  option.


#### res_tonedetect: Add option for TONE_DETECT detection to auto stop.
  Author: Naveen Albert
  Date:   2025-08-22

  One of the problems with TONE_DETECT as it was originally written
  is that if a tone is detected multiple times, it can trigger
  the redirect logic multiple times as well. For example, if we
  do an async goto in the dialplan after detecting a tone, because
  the detector is still active until explicitly disabled, if we
  detect the tone again, we will branch again and start executing
  that dialplan a second time. This is rarely ever desired behavior,
  and can happen if the detector is not removed quickly enough.

  Add a new option, 'e', which automatically disables the detector
  once the desired number of matches have been heard. This eliminates
  the potential race condition where previously the detector would
  need to be disabled immediately, but doing so quickly enough
  was not guaranteed. This also allows match criteria to be retained
  longer if needed, so the detector does not need to be destroyed
  prematurely.

  Resolves: #1390

  UserNote: The 'e' option for TONE_DETECT now allows detection to
  be disabled automatically once the desired number of matches have
  been fulfilled, which can help prevent race conditions in the
  dialplan, since TONE_DETECT does not need to be disabled after
  a hit.


#### app_queue: fix comparison for announce-position-only-up
  Author: Stuart Henderson
  Date:   2025-08-21

  Numerically comparing that the current queue position is less than
  last_pos_said can only be done after at least one announcement has been
  made, otherwise last_pos_said is at the default (0).

  Fixes: #1386

#### sorcery: Prevent duplicate objects and ensure missing objects are created on update
  Author: Alexei Gradinari
  Date:   2025-07-07

  This patch resolves two issues in Sorcery objectset handling with multiple
  backends:

  1. Prevent duplicate objects:
     When an object exists in more than one backend (e.g., a contact in both
     'astdb' and 'realtime'), the objectset previously returned multiple instances
     of the same logical object. This caused logic failures in components like the
     PJSIP registrar, where duplicate contact entries led to overcounting and
     incorrect deletions, when max_contacts=1 and remove_existing=yes.

     This patch ensures only one instance of an object with a given key is added
     to the objectset, avoiding these duplicate-related side effects.

  2. Ensure missing objects are created:
     When using multiple writable backends, a temporary backend failure can lead
     to objects missing permanently from that backend.
     Currently, .update() silently fails if the object is not present,
     and no .create() is attempted.
     This results in inconsistent state across backends (e.g. astdb vs. realtime).

     This patch introduces a new global option in sorcery.conf:
       [general]
       update_or_create_on_update_miss = yes|no

     Default: no (preserves existing behavior).

     When enabled: if .update() fails with no data found, .create() is attempted
     in that backend. This ensures that objects missing due to temporary backend
     outages are re-synchronized once the backend is available again.

     Added a new CLI command:
       sorcery show settings
     Displays global Sorcery settings, including the current value of
     update_or_create_on_update_miss.

     Updated tests to validate both flag enabled/disabled behavior.

  Fixes: #1289

  UserNote: Users relying on Sorcery multiple writable backends configurations
  (e.g., astdb + realtime) may now enable update_or_create_on_update_miss = yes
  in sorcery.conf to ensure missing objects are recreated after temporary backend
  failures. Default behavior remains unchanged unless explicitly enabled.


#### sig_analog: Skip Caller ID spill if usecallerid=no.
  Author: Naveen Albert
  Date:   2025-08-25

  If Caller ID is disabled for an FXS port, then we should not send any
  Caller ID spill on the line, as we have no Caller ID information that
  we can/should be sending.

  Resolves: #1394

#### chan_dahdi: Fix erroneously persistent dialmode.
  Author: Naveen Albert
  Date:   2025-08-18

  It is possible to modify the dialmode setting in the chan_dahdi/sig_analog
  private using the CHANNEL function, to modify it during calls. However,
  it was not being reset between calls, meaning that if, for example, tone
  dialing was disabled, it would never work again unless explicitly enabled.

  This fixes the setting by pairing it with a "perm" version of the setting,
  as a few other features have, so that it can be reset to the permanent
  setting between calls. The documentation is also clarified to explain
  the interaction of this setting and the digitdetect setting more clearly.

  Resolves: #1378

#### chan_websocket: Allow additional URI parameters to be added to the outgoing URI.
  Author: George Joseph
  Date:   2025-08-13

  * Added a new option to the WebSocket dial string to capture the additional
    URI parameters.
  * Added a new API ast_uri_verify_encoded() that verifies that a string
    either doesn't need URI encoding or that it has already been encoded.
  * Added a new API ast_websocket_client_add_uri_params() to add the params
    to the client websocket session.
  * Added XML documentation that will show up with `core show application Dial`
    that shows how to use it.

  Resolves: #1352

  UserNote: A new WebSocket channel driver option `v` has been added to the
  Dial application that allows you to specify additional URI parameters on
  outgoing connections. Run `core show application Dial` from the Asterisk CLI
  to see how to use it.


#### chan_websocket: Fix buffer overrun when processing TEXT websocket frames.
  Author: George Joseph
  Date:   2025-08-19

  ast_websocket_read() receives data into a fixed 64K buffer then continually
  reallocates a final buffer that, after all continuation frames have been
  received, is the exact length of the data received and returns that to the
  caller.  process_text_message() in chan_websocket was attempting to set a
  NULL terminator on the received payload assuming the payload buffer it
  received was the large 64K buffer.  The assumption was incorrect so when it
  tried to set a NULL terminator on the payload, it could, depending on the
  state of the heap at the time, cause heap corruption.

  process_text_message() now allocates its own payload_len + 1 sized buffer,
  copies the payload received from ast_websocket_read() into it then NULL
  terminates it prevent the possibility of the overrun and corruption.

  Resolves: #1384

#### sig_analog: Fix SEGV due to calling strcmp on NULL.
  Author: Naveen Albert
  Date:   2025-08-18

  Add an additional check to guard against the channel application being
  NULL.

  Resolves: #1380

#### ARI: Add command to indicate progress to a channel
  Author: Sven Kube
  Date:   2025-07-30

  Adds an ARI command to send a progress indication to a channel.

  DeveloperNote: A new ARI endpoint is available at `/channels/{channelId}/progress` to indicate progress to a channel.

#### dsp.c: Improve debug logging in tone_detect().
  Author: Naveen Albert
  Date:   2025-08-15

  The debug logging during DSP processing has always been kind
  of overwhelming and annoying to troubleshoot. Simplify and
  improve the logging in a few ways to aid DSP debugging:

  * If we had a DSP hit, don't also emit the previous debug message that
    was always logged. It is duplicated by the hit message, so this can
    reduce the number of debug messages during detection by 50%.
  * Include the hit count and required number of hits in the message so
    on partial detections can be more easily troubleshot.
  * Use debug level 9 for hits instead of 10, so we can focus on hits
    without all the noise from the per-frame debug message.
  * 1-index the hit count in the debug messages. On the first hit, it
    currently logs '0', just as when we are not detecting anything,
    which can be confusing.

  Resolves: #1375

#### res_stasis_device_state: Fix delete ARI Devicestates after asterisk restart.
  Author: Jose Lopes
  Date:   2025-07-30

  After an asterisk restart, the deletion of ARI Devicestates didn't
  return error, but the devicestate was not deleted.
  Found a typo on populate_cache function that created wrong cache for
  device states.
  This bug caused wrong assumption that devicestate didn't exist,
  since it was not in cache, so deletion didn't returned error.

  Fixes: #1327

#### app_chanspy: Add option to not automatically answer channel.
  Author: Naveen Albert
  Date:   2025-08-13

  Add an option for ChanSpy and ExtenSpy to not answer the channel
  automatically. Most applications that auto-answer by default
  already have an option to disable this behavior if unwanted.

  Resolves: #1358

  UserNote: ChanSpy and ExtenSpy can now be configured to not
  automatically answer the channel by using the 'N' option.


#### xmldoc.c: Fix rendering of CLI output.
  Author: George Joseph
  Date:   2025-08-14

  If you do a `core show application Dial`, you'll see it's kind of a mess.
  Indents are wrong is some places, examples are printed in black which makes
  them invisible on most terminals, and the lack of line breaks in some cases
  makes it hard to follow.

  * Fixed the rendering of examples so they are indented properly and changed
  the color so they can be seen.
  * There is now a line break before each option.
  * Options are now printed on their own line with all option content indented
  below them.

  Example from Dial before fixes:
  ```
      Example: Dial 555-1212 on first available channel in group 1, searching
      from highest to lowest

      Example: Ringing FXS channel 4 with ring cadence 2

      Example: Dial 555-1212 on channel 3 and require answer confirmation

  ...

      O([mode]):
          mode - With <mode> either not specified or set to '1', the originator
          hanging up will cause the phone to ring back immediately.
   - With <mode> set to '2', when the operator flashes the trunk, it will ring
   their phone back.
  Enables *operator services* mode.  This option only works when bridging a DAHDI
  channel to another DAHDI channel only. If specified on non-DAHDI interfaces, it
  will be ignored. When the destination answers (presumably an operator services
  station), the originator no longer has control of their line. They may hang up,
  but the switch will not release their line until the destination party (the
  operator) hangs up.

      p: This option enables screening mode. This is basically Privacy mode
      without memory.
  ```

  After:
  ```
      Example: Dial 555-1212 on first available channel in group 1, searching
      from highest to lowest

       same => n,Dial(DAHDI/g1/5551212)

      Example: Ringing FXS channel 4 with ring cadence 2

       same => n,Dial(DAHDI/4r2)

      Example: Dial 555-1212 on channel 3 and require answer confirmation

       same => n,Dial(DAHDI/3c/5551212)

  ...

      O([mode]):
          mode - With <mode> either not specified or set to '1', the originator
          hanging up will cause the phone to ring back immediately.
          With <mode> set to '2', when the operator flashes the trunk, it will
          ring their phone back.
          Enables *operator services* mode.  This option only works when bridging
          a DAHDI channel to another DAHDI channel only. If specified on
          non-DAHDI interfaces, it will be ignored. When the destination answers
          (presumably an operator services station), the originator no longer has
          control of their line. They may hang up, but the switch will not
          release their line until the destination party (the operator) hangs up.

      p:
          This option enables screening mode. This is basically Privacy mode
          without memory.
  ```

  There are still things we can do to make this more readable but this is a
  start.


#### func_frame_drop: Add debug messages for dropped frames.
  Author: Naveen Albert
  Date:   2025-08-14

  Add debug messages in scenarios where frames that are usually processed
  are dropped or skipped.

  Resolves: #1371

#### test_res_prometheus: Fix compilation failure on Debian 13.
  Author: Naveen Albert
  Date:   2025-08-14

  curl_easy_setopt expects long types, so be explicit.

  Resolves: #1369

#### func_frame_drop: Handle allocation failure properly.
  Author: Naveen Albert
  Date:   2025-08-14

  Handle allocation failure and simplify the allocation using asprintf.

  Resolves: #1366

#### pbx_lua.c: segfault when pass null data to term_color function
  Author: Alexey Khabulyak
  Date:   2025-08-14

  This can be reproduced under certain curcomstences.
  For example: call app.playback from lua with invalid data: app.playback({}).
  pbx_lua.c will try to get data for this playback using lua_tostring function.
  This function returs NULL for everything but strings and numbers.
  Then, it calls term_color with NULL data.
  term_color function can call(if we don't use vt100 compat term)
  ast_copy_string with NULL inbuf which cause segfault. bt example:
  ast_copy_string (size=8192, src=0x0, dst=0x7fe44b4be8b0)
  at /usr/src/asterisk/asterisk-20.11.0/include/asterisk/strings.h:412

  Resolves: https://github.com/asterisk/asterisk/issues/1363

#### bridge.c: Obey BRIDGE_NOANSWER variable to skip answering channel.
  Author: Naveen Albert
  Date:   2025-08-14

  If the BRIDGE_NOANSWER variable is set on a channel, it is not supposed
  to answer when another channel bridges to it using Bridge(), and this is
  checked when ast_bridge_call* is called. However, another path exists
  (bridge_exec -> ast_bridge_add_channel) where this variable was not
  checked and channels would be answered. We now check the variable there.

  Resolves: #401
  Resolves: #1364

#### res_rtp_asterisk: Don't send RTP before DTLS has negotiated.
  Author: Ben Ford
  Date:   2025-08-04

  There was no check in __rtp_sendto that prevented Asterisk from sending
  RTP before DTLS had finished negotiating. This patch adds logic to do
  so.

  Fixes: #1260

#### app_dial.c: Moved channel lock to prevent deadlock
  Author: Alexey Khabulyak
  Date:   2025-08-04

  It's reproducible with pbx_lua, not regular dialplan.

  deadlock description:
  1. asterisk locks a channel
  2. calls function onedigit_goto
  3. calls ast_goto_if_exists funciton
  4. checks ast_exists_extension -> pbx_extension_helper
  5. pbx_extension_helper calls pbx_find_extension
  6. Then asterisk starts autoservice in a new thread
  7. autoservice run tries to lock the channel again

  Because our channel is locked already, autoservice can't lock.
  Autoservice can't lock -> autoservice stop is waiting forever.
  onedigit_goto waits for autoservice stop.

  Resolves: https://github.com/asterisk/asterisk/issues/1335

#### res_pjsip_diversion: resolve race condition between Diversion header processing and redirect
  Author: Mike Bradeen
  Date:   2025-08-07

  Based on the firing order of the PJSIP call-backs on a redirect, it was possible for
  the Diversion header to not be included in the outgoing 181 response to the UAC and
  the INVITE to the UAS.

  This change moves the Diversion header processing to an earlier PJSIP callback while also
  preventing the corresponding update that can cause a duplicate 181 response when processing
  the header at that time.

  Resolves: #1349

#### file.c: with "sounds_search_custom_dir = yes", search "custom" directory
  Author: Allan Nathanson
  Date:   2025-08-10

  With `sounds_search_custom_dir = yes`, we are supposed to search for sounds
  in the `AST_DATA_DIR/sounds/custom` directory before searching the normal
  directories.  Unfortunately, a recent change
  (https://github.com/asterisk/asterisk/pull/1172) had a typo resulting in
  the "custom" directory not being searched.  This change restores this
  expected behavior.

  Resolves: #1353

#### cel: Add STREAM_BEGIN, STREAM_END and DTMF event types.
  Author: Sperl Viktor
  Date:   2025-06-30

  Fixes: #1280

  UserNote: Enabling the tracking of the
  STREAM_BEGIN and the STREAM_END event
  types in cel.conf will log media files and
  music on hold played to each channel.
  The STREAM_BEGIN event's extra field will
  contain a JSON with the file details (path,
  format and language), or the class name, in
  case of music on hold is played. The DTMF
  event's extra field will contain a JSON with
  the digit and the duration in milliseconds.


#### channelstorage_cpp_map_name_id.cc: Refactor iterators for thread-safety.
  Author: George Joseph
  Date:   2025-07-30

  The fact that deleting an object from a map invalidates any iterator
  that happens to currently point to that object was overlooked in the initial
  implementation.  Unfortunately, there's no way to detect that an iterator
  has been invalidated so the result was an occasional SEGV triggered by modules
  like app_chanspy that opens an iterator and can keep it open for a long period
  of time.  The new implementation doesn't keep the underlying C++ iterator
  open across calls to ast_channel_iterator_next() and uses a read lock
  on the map to ensure that, even for the few microseconds we use the
  iterator, another thread can't delete a channel from under it.  Even with
  this change, the iterators are still WAY faster than the ao2_legacy
  storage driver.

  Full details about the new implementation are located in the comments for
  iterator_next() in channelstorage_cpp_map_name_id.cc.

  Resolves: #1309

#### res_srtp: Add menuselect options to enable AES_192, AES_256 and AES_GCM
  Author: George Joseph
  Date:   2025-08-05

  UserNote: Options are now available in the menuselect "Resource Modules"
  category that allow you to enable the AES_192, AES_256 and AES_GCM
  cipher suites in res_srtp. Of course, libsrtp and OpenSSL must support
  them but modern versions do.  Previously, the only way to enable them was
  to set the CFLAGS environment variable when running ./configure.
  The default setting is to disable them preserving existing behavior.


#### cdr: add CANCEL dispostion in CDR
  Author: zhou_jiajian
  Date:   2025-07-24

  In the original implementation, both CANCEL and NO ANSWER states were
  consolidated under the NO ANSWER disposition. This patch introduces a
  separate CANCEL disposition, with an optional configuration switch to
  enable this new disposition.

  Resolves: #1323

  UserNote: A new CDR option "canceldispositionenabled" has been added
  that when set to true, the NO ANSWER disposition will be split into
  two dispositions: CANCEL and NO ANSWER. The default value is 'no'


#### func_curl: Allow auth methods to be set.
  Author: Naveen Albert
  Date:   2025-08-01

  Currently the CURL function only supports Basic Authentication,
  the default auth method in libcurl. Add an option that also
  allows enabling digest authentication.

  Resolves: #1332

  UserNote: The httpauth field in CURLOPT now allows the authentication
  methods to be set.


#### options:  Change ast_options from ast_flags to ast_flags64.
  Author: George Joseph
  Date:   2025-07-21

  DeveloperNote: The 32-bit ast_options has no room left to accomodate new
  options and so has been converted to an ast_flags64 structure. All internal
  references to ast_options have been updated to use the 64-bit flag
  manipulation macros.  External module references to the 32-bit ast_options
  should continue to work on little-endian systems because the
  least-significant bytes of a 64 bit integer will be in the same location as a
  32-bit integer.  Because that's not the case on big-endian systems, we've
  swapped the bytes in the flags manupulation macros on big-endian systems
  so external modules should still work however you are encouraged to test.


#### res_config_odbc: Prevent Realtime fallback on record-not-found (SQL_NO_DATA)
  Author: Alexei Gradinari
  Date:   2025-07-15

  This patch fixes an issue in the ODBC Realtime engine where Asterisk incorrectly
  falls back to the next configured backend when the current one returns
  SQL_NO_DATA (i.e., no record found).
  This is a logical error and performance risk in multi-backend configurations.

  Solution:
  Introduced CONFIG_RT_NOT_FOUND ((void *)-1) as a special return marker.
  ODBC Realtime backend now return CONFIG_RT_NOT_FOUND when no data is found.
  Core engine stops iterating on this marker, avoiding unnecessary fallback.

  Notes:
  Other Realtime backends (PostgreSQL, LDAP, etc.) can be updated similarly.
  This patch only covers ODBC.

  Fixes: #1305

#### resource_channels.c: Don't call ast_channel_get_by_name on empty optional arguments
  Author: Sven Kube
  Date:   2025-07-30

  `ast_ari_channels_create` and `ast_ari_channels_dial` called the
  `ast_channel_get_by_name` function with optional arguments. Since
  8f1982c4d6, this function logs an error for empty channel names.
  This commit adds checks for empty optional arguments that are used
  to call `ast_channel_get_by_name` to prevent these error logs.


#### app_agent_pool: Remove documentation for removed option.
  Author: Naveen Albert
  Date:   2025-07-28

  The already-deprecated "password" option for the AGENT function was
  removed in commit d43b17a872e8227aa8a9905a21f90bd48f9d5348 for
  Asterisk 12, but the documentation for it wasn't removed then.

  Resolves: #1321

#### pbx.c: When the AST_SOFTHANGUP_ASYNCGOTO flag is set, pbx_extension_helper should return directly.
  Author: Tinet-mucw
  Date:   2025-07-22

  Under certain circumstances the context/extens/prio are set in the ast_async_goto, for example action Redirect.
  In the situation that action Redirect is broken by pbx_extension_helper this info is changed.
  This will cause the current dialplan location to be executed twice.
  In other words, the Redirect action does not take effect.

  Resolves: #1315

#### res_agi: Increase AGI command buffer size from 2K to 8K
  Author: Sperl Viktor
  Date:   2025-07-22

  Fixes: #1317

#### ast_tls_cert: Make certificate validity configurable.
  Author: Naveen Albert
  Date:   2025-07-16

  Currently, the ast_tls_cert script is hardcoded to produce certificates
  with a validity of 365 days, which is not generally desirable for self-
  signed certificates. Make this parameter configurable.

  Resolves: #1307

#### cdr.c: Set tenantid from party_a->base instead of chan->base.
  Author: George Joseph
  Date:   2025-07-17

  The CDR tenantid was being set in cdr_object_alloc from the channel->base
  snapshot.  Since this happens at channel creation before the dialplan is even
  reached, calls to `CHANNEL(tenantid)=<something>` in the dialplan were being
  ignored.  Instead we now take tenantid from party_a when
  cdr_object_create_public_records() is called which is after the call has
  ended and all channel snapshots rebuilt.  This is exactly how accountcode
  and amaflags, which can also be set in tha dialplpan, are handled.

  Resolves: #1259

#### app_mixmonitor:  Update the documentation concerning the "D" option.
  Author: George Joseph
  Date:   2025-07-16

  When using the "D" option to output interleaved audio, the file extension
  must be ".raw".  That info wasn't being properly rendered in the markdown
  and HTML on the documentation site.  The XML was updated to move the
  note in the option section to a warning in the description.

  Resolves: #1269

#### sig_analog: Properly handle STP, ST2P, and ST3P for fgccamamf.
  Author: Naveen Albert
  Date:   2025-07-14

  Previously, we were only using # (ST) as a terminator, and not handling
  A (STP), B (ST2P), or C (ST3P), which erroneously led to it being
  treated as part of the dialed number. Parse any of these as the start
  digit.

  Resolves: #1301

#### chan_websocket: Reset frame_queue_length to 0 after FLUSH_MEDIA
  Author: kodokaii
  Date:   2025-07-03

  In the WebSocket channel driver, the FLUSH_MEDIA command clears all frames from
  the queue but does not reset the frame_queue_length counter.

  As a result, the driver incorrectly thinks the queue is full after flushing,
  which prevents new multimedia frames from being sent, especially after multiple
  flush commands.

  This fix sets frame_queue_length to 0 after flushing, ensuring the queue state
  is consistent with its actual content.

  Fixes: #1304

#### chan_pjsip.c: Change SSRC after media source change
  Author: Martin Tomec
  Date:   2025-06-25

  When the RTP media source changes, such as after a blind transfer, the new source introduces a discontinuous timestamp. According to RFC 3550, Section 5.1, an RTP stream's timestamp for a given SSRC must increment monotonically and linearly.
  To comply with the standard and avoid a large timestamp jump on the existing SSRC, a new SSRC is generated for the new media stream.
  This change resolves known interoperability issues with certain SBCs (like Sonus/Ribbon) that stop forwarding media when they detect such a timestamp violation. This code uses the existing implementation from chan_sip.

  Resolves: #927

#### Media over Websocket Channel Driver
  Author: George Joseph
  Date:   2025-04-28

  * Created chan_websocket which can exchange media over both inbound and
  outbound websockets which the driver will frame and time.
  See http://s.asterisk.net/mow for more information.

  * res_http_websocket: Made defines for max message size public and converted
  a few nuisance verbose messages to debugs.

  * main/channel.c: Changed an obsolete nuisance error to a debug.

  * ARI channels: Updated externalMedia to include chan_websocket as a supported
  transport.

  UserNote: A new channel driver "chan_websocket" is now available. It can
  exchange media over both inbound and outbound websockets and will both frame
  and re-time the media it receives.
  See http://s.asterisk.net/mow for more information.

  UserNote: The ARI channels/externalMedia API now includes support for the
  WebSocket transport provided by chan_websocket.


#### bundled_pjproject: Avoid deadlock between transport and transaction
  Author: Stanislav Abramenkov
  Date:   2025-07-01

  Backport patch from upstream
  * Avoid deadlock between transport and transaction
  https://github.com/pjsip/pjproject/commit/edde06f261ac

  Issue described in
  https://github.com/pjsip/pjproject/issues/4442


#### utils.h: Add rounding to float conversion to int.
  Author: mkmer
  Date:   2025-03-23

  Quote from an audio engineer NR9V:
  There is a minor issue of a small amount of crossover distortion though as a result of `ast_slinear_saturated_multiply_float()` not rounding the float. This could result in some quiet but potentially audible distortion artifacts in lower volume parts of the signal. If you have for example a sign wave function with a max amplitude of just a few samples, all samples between -1 and 1 will be truncated to zero, resulting in the waveform no longer being a sine wave and in harmonic distortion.

  Resolves: #1176

#### pbx.c: when set flag AST_SOFTHANGUP_ASYNCGOTO, ast_explicit_goto should return -1.
  Author: Tinet-mucw
  Date:   2025-06-18

  Under certain circumstances the context/extens/prio are set in the ast_async_goto, for example action Redirect.
  In the situation that action Redirect is broken by GotoIf this info is changed.
  that will causes confusion in dialplan execution.

  Resolves: #1273

#### res_musiconhold.c: Ensure we're always locked around music state access.
  Author: Sean Bright
  Date:   2025-04-08


#### res_musiconhold.c: Annotate when the channel is locked.
  Author: Sean Bright
  Date:   2025-04-08


#### res_musiconhold: Appropriately lock channel during start.
  Author: Jaco Kroon
  Date:   2024-12-19

  This relates to #829

  This doesn't sully solve the Ops issue, but it solves the specific crash
  there.  Further PRs to follow.

  In the specific crash the generator was still under construction when
  moh was being stopped, which then proceeded to close the stream whilst
  it was still in use.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### res_pjsip_authenticator_digest: Fix SEGV if get_authorization_hdr returns NULL.
  Author: George Joseph
  Date:   2025-08-28

  In the highly-unlikely event that get_authorization_hdr() couldn't find an
  Authorization header in a request, trying to get the digest algorithm
  would cauase a SEGV.  We now check that we have an auth header that matches
  the realm before trying to get the algorithm from it.

  Resolves: #GHSA-64qc-9x89-rx5j

#### safe_asterisk: Add ownership checks for /etc/asterisk/startup.d and its files.
  Author: ThatTotallyRealMyth
  Date:   2025-06-10

  UpgradeNote: The safe_asterisk script now checks that, if it was run by the
  root user, the /etc/asterisk/startup.d directory and all the files it contains
  are owned by root.  If the checks fail, safe_asterisk will exit with an error
  and Asterisk will not be started.  Additionally, the default logging
  destination is now stderr instead of tty "9" which probably won't exist
  in modern systems.

  Resolves: #GHSA-v9q8-9j8m-5xwp

#### res_stir_shaken: Test for missing semicolon in Identity header.
  Author: George Joseph
  Date:   2025-07-31

  ast_stir_shaken_vs_verify() now makes sure there's a semicolon in
  the Identity header to prevent a possible segfault.

  Resolves: #GHSA-mrq5-74j5-f5cr

#### channelstorage: Rename callbacks that conflict with DEBUG_FD_LEAKS.
  Author: George Joseph
  Date:   2025-07-08

  DEBUG_FD_LEAKS replaces calls to "open" and "close" with functions that keep
  track of file descriptors, even when those calls are actually callbacks
  defined in structures like ast_channelstorage_instance->open and don't touch
  file descriptors.  This causes compilation failures.  Those callbacks
  have been renamed to "open_instance" and "close_instance" respectively.

  Resolves: #1287

#### channelstorage_cpp_map_name_id: Fix callback returning non-matching channels.
  Author: George Joseph
  Date:   2025-07-09

  When the callback() API was invoked but no channel passed the test, callback
  would return the last channel tested instead of NULL.  It now correctly
  returns NULL when no channel matches.

  Resolves: #1288

#### audiohook.c: Improve frame pairing logic to avoid MixMonitor breakage with mixed codecs
  Author: Michal Hajek
  Date:   2025-05-21

  This patch adjusts the read/write synchronization logic in audiohook_read_frame_both()
  to better handle calls where participants use different codecs or sample sizes
  (e.g., alaw vs G.722). The previous hard threshold of 2 * samples caused MixMonitor
  recordings to break or stutter when frames were not aligned between both directions.

  The new logic uses a more tolerant limit (1.5 * samples), which prevents audio tearing
  without causing excessive buffer overruns. This fix specifically addresses issues
  with MixMonitor when recording directly on a channel in a bridge using mixed codecs.

  Reported-by: Michal Hajek <michal.hajek@daktela.com>

  Resolves: #1276
  Resolves: #1279

#### channelstorage_makeopts.xml: Remove errant XML character.
  Author: Sean Bright
  Date:   2025-06-30

  Resolves: #1282

#### res_stir_shaken.so: Handle X5U certificate chains.
  Author: George Joseph
  Date:   2025-06-18

  The verification process will now load a full certificate chain retrieved
  via the X5U URL instead of loading only the end user cert.

  * Renamed crypto_load_cert_from_file() and crypto_load_cert_from_memory()
  to crypto_load_cert_chain_from_file() and crypto_load_cert_chain_from_memory()
  respectively.

  * The two load functions now continue to load certs from the file or memory
  PEMs and store them in a separate stack of untrusted certs specific to the
  current verification context.

  * crypto_is_cert_trusted() now uses the stack of untrusted certs that were
  extracted from the PEM in addition to any untrusted certs that were passed
  in from the configuration (and any CA certs passed in from the config of
  course).

  Resolves: #1272

  UserNote: The STIR/SHAKEN verification process will now load a full
  certificate chain retrieved via the X5U URL instead of loading only
  the end user cert.

#### res_stir_shaken: Add "ignore_sip_date_header" config option.
  Author: George Joseph
  Date:   2025-06-15

  UserNote: A new STIR/SHAKEN verification option "ignore_sip_date_header" has
  been added that when set to true, will cause the verification process to
  not consider a missing or invalid SIP "Date" header to be a failure.  This
  will make the IAT the sole "truth" for Date in the verification process.
  The option can be set in the "verification" and "profile" sections of
  stir_shaken.conf.

  Also fixed a bug in the port match logic.

  Resolves: #1251
  Resolves: #1271

#### app_record: Add RECORDING_INFO function.
  Author: Naveen Albert
  Date:   2024-01-22

  Add a function that can be used to retrieve info
  about a previous recording, such as its duration.

  This is being added as a function to avoid possibly
  trampling on dialplan variables, and could be extended
  to provide other information in the future.

  Resolves: #548

  UserNote: The RECORDING_INFO function can now be used
  to retrieve the duration of a recording.

#### app_sms.c: Fix sending and receiving SMS messages in protocol 2
  Author: Itzanh
  Date:   2025-04-06

  This fixes bugs in SMS messaging to SMS-capable analog phones that prevented app_sms.c from talking to phones using SMS protocol 2.

  - Fix MORX message reception (from phone to Asterisk) in SMS protocol 2
  - Fix MTTX message transmission (from Asterisk to phone) in SMS protocol 2

  One of the bugs caused messages to have random characters and junk appended at the end up to the character limit. Another bug prevented Asterisk from sending messages from Asterisk to the phone at all. A final bug caused the transmission from Asterisk to the phone to take a long time because app_sms.c did not hang up after correctly sending the message, causing the phone to have to time out and hang up in order to complete the message transmission.

  This was tested with a Linksys PAP2T and with a GrandStream HT814, sending and receiving messages with Telefónica DOMO Mensajes phones from Telefónica Spain. I had to play with both the network jitter buffer and the dB gain to get it to work. One of my phones required the gain to be set to +3dB for it to work, while another required it to be set to +6dB.

  Only MORX and MTTX were tested, I did not test sending and receiving messages to a TelCo SMSC.

#### app_queue: queue rules – Add support for QUEUE_RAISE_PENALTY=rN to raise penalties only for members within min/max range
  Author: phoneben
  Date:   2025-05-26

  This update adds support for a new QUEUE_RAISE_PENALTY format: rN

  When QUEUE_RAISE_PENALTY is set to rN (e.g., r4), only members whose current penalty
  is greater than or equal to the defined min_penalty and less than or equal to max_penalty
  will have their penalty raised to N.

  Members with penalties outside the min/max range remain unchanged.

  Example behaviors:

  QUEUE_RAISE_PENALTY=4     → Raise all members with penalty < 4 (existing behavior)
  QUEUE_RAISE_PENALTY=r4    → Raise only members with penalty in [min_penalty, max_penalty] to 4

  Implementation details:

  Adds parsing logic to detect the r prefix and sets the raise_respect_min flag

  Modifies the raise logic to skip members outside the defined penalty range when the flag is active

  UserNote: This change introduces QUEUE_RAISE_PENALTY=rN, allowing selective penalty raises
  only for members whose current penalty is within the [min_penalty, max_penalty] range.
  Members with lower or higher penalties are unaffected.
  This behavior is backward-compatible with existing queue rule configurations.

#### res_websocket_client:  Add more info to the XML documentation.
  Author: George Joseph
  Date:   2025-06-05

  Added "see-also" links to chan_websocket and ARI Outbound WebSocket and
  added an example configuration for each.

#### res_odbc: cache_size option to limit the cached connections.
  Author: Jaco Kroon
  Date:   2024-12-13

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

  UserNote: New cache_size option for res_odbc to on a per class basis limit the
  number of cached connections. Please reference the sample configuration
  for details.

#### res_odbc: cache_type option for res_odbc.
  Author: Jaco Kroon
  Date:   2024-12-10

  This enables setting cache_type classes to a round-robin queueing system
  rather than the historic stack mechanism.

  This should result in lower risk of connection drops due to shorter idle
  times (the first connection to go onto the stack could in theory never
  be used again, ever, but sit there consuming resources, there could be
  multiple of these).

  And with a queue rather than a stack, dead connections are guaranteed to
  be detected and purged eventually.

  This should end up better balancing connection_cnt with actual load
  over time, assuming the database doesn't keep connections open
  excessively long from it's side.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

  UserNote: When using res_odbc it should be noted that back-end
  connections to the underlying database can now be configured to re-use
  the cached connections in a round-robin manner rather than repeatedly
  re-using the same connection.  This helps to keep connections alive, and
  to purge dead connections from the system, thus more dynamically
  adjusting to actual load.  The downside is that one could keep too many
  connections active for a longer time resulting in resource also begin
  consumed on the database side.

#### res_pjsip: Fix empty `ActiveChannels` property in AMI responses.
  Author: Sean Bright
  Date:   2025-05-27

  The logic appears to have been reversed since it was introduced in
  05cbf8df.

  Resolves: #1254

#### ARI Outbound Websockets
  Author: George Joseph
  Date:   2025-03-28

  Asterisk can now establish websocket sessions _to_ your ARI applications
  as well as accepting websocket sessions _from_ them.
  Full details: http://s.asterisk.net/ari-outbound-ws

  Code change summary:
  * Added an ast_vector_string_join() function,
  * Added ApplicationRegistered and ApplicationUnregistered ARI events.
  * Converted res/ari/config.c to use sorcery to process ari.conf.
  * Added the "outbound-websocket" ARI config object.
  * Refactored res/ari/ari_websockets.c to handle outbound websockets.
  * Refactored res/ari/cli.c for the sorcery changeover.
  * Updated res/res_stasis.c for the sorcery changeover.
  * Updated apps/app_stasis.c to allow initiating per-call outbound websockets.
  * Added CLI commands to manage ARI websockets.
  * Added the new "outbound-websocket" object to ari.conf.sample.
  * Moved the ARI XML documentation out of res_ari.c into res/ari/ari_doc.xml

  UserNote: Asterisk can now establish websocket sessions _to_ your ARI applications
  as well as accepting websocket sessions _from_ them.
  Full details: http://s.asterisk.net/ari-outbound-ws

#### res_websocket_client: Create common utilities for websocket clients.
  Author: George Joseph
  Date:   2025-05-02

  Since multiple Asterisk capabilities now need to create websocket clients
  it makes sense to create a common set of utilities rather than making
  each of those capabilities implement their own.

  * A new configuration file "websocket_client.conf" is used to store common
  client parameters in named configuration sections.
  * APIs are provided to list and retrieve ast_websocket_client objects created
  from the named configurations.
  * An API is provided that accepts an ast_websocket_client object, connects
  to the remote server with retries and returns an ast_websocket object. TLS is
  supported as is basic authentication.
  * An observer can be registered to receive notification of loaded or reloaded
  client objects.
  * An API is provided to compare an existing client object to one just
  reloaded and return the fields that were changed. The caller can then decide
  what action to take based on which fields changed.

  Also as part of thie commit, several sorcery convenience macros were created
  to make registering common object fields easier.

  UserNote: A new module "res_websocket_client" and config file
  "websocket_client.conf" have been added to support several upcoming new
  capabilities that need common websocket client configuration.

#### asterisk.c: Add option to restrict shell access from remote consoles.
  Author: George Joseph
  Date:   2025-05-19

  UserNote: A new asterisk.conf option 'disable_remote_console_shell' has
  been added that, when set, will prevent remote consoles from executing
  shell commands using the '!' prefix.

  Resolves: #GHSA-c7p6-7mvq-8jq2

#### res_pjsip_messaging.c: Mask control characters in received From display name
  Author: George Joseph
  Date:   2025-03-24

  Incoming SIP MESSAGEs will now have their From header's display name
  sanitized by replacing any characters < 32 (space) with a space.

  Resolves: #GHSA-2grh-7mhv-fcfw

#### frame.c: validate frame data length is less than samples when adjusting volume
  Author: mkmer
  Date:   2025-05-12

  Resolves: #1230

#### res_audiosocket.c: Add retry mechanism for reading data from AudioSocket
  Author: Sven Kube
  Date:   2025-05-13

  The added retry mechanism addresses an issue that arises when fragmented TCP
  packets are received, each containing only a portion of an AudioSocket packet.
  This situation can occur if the external service sending the AudioSocket data
  has Nagle's algorithm enabled.

#### res_audiosocket.c: Set the TCP_NODELAY socket option
  Author: Sven Kube
  Date:   2025-05-13

  Disable Nagle's algorithm by setting the TCP_NODELAY socket option.
  This reduces latency by preventing delays caused by packet buffering.

#### menuselect: Fix GTK menu callbacks for Fedora 42 compatibility
  Author: Thomas B. Clark
  Date:   2025-05-12

  This patch resolves a build failure in `menuselect_gtk.c` when running
  `make menuconfig` on Fedora 42. The new version of GTK introduced stricter
  type checking for callback signatures.

  Changes include:
  - Add wrapper functions to match the expected `void (*)(void)` signature.
  - Update `menu_items` array to use these wrappers.

  Fixes: #1243

#### jansson: Upgrade version to jansson 2.14.1
  Author: Stanislav Abramenkov
  Date:   2025-03-24

  UpgradeNote: jansson has been upgraded to 2.14.1. For more
  information visit jansson Github page: https://github.com/akheron/jansson/releases/tag/v2.14.1

  Resolves: #1178

#### pjproject: Increase maximum SDP formats and attribute limits
  Author: Joe Searle
  Date:   2025-05-15

  Since Chrome 136, using Windows, when initiating a video call the INVITE SDP exceeds the maximum number of allowed attributes, resulting in the INVITE being rejected. This increases the attribute limit and the number of formats allowed when using bundled pjproject.

  Fixes: #1240

#### manager.c: Invalid ref-counting when purging events
  Author: Nathan Monfils
  Date:   2025-05-05

  We have a use-case where we generate a *lot* of events on the AMI, and
  then when doing `manager show eventq` we would see some events which
  would linger for hours or days in there. Obviously something was leaking.
  Testing allowed us to track down this logic bug in the ref-counting on
  the event purge.

  Reproducing the bug was not super trivial, we managed to do it in a
  production-like load testing environment with multiple AMI consumers.

  The race condition itself:

  1. something allocates and links `session`
  2. `purge_sessions` iterates over that `session` (takes ref)
  3. `purge_session` correctly de-referencess that session
  4. `purge_session` re-evaluates the while() loop, taking a reference
  5. `purge_session` exits (`n_max > 0` is false)
  6. whatever allocated the `session` deallocates it, but a reference is
     now lost since we exited the `while` loop before de-referencing.
  7. since the destructor is never called, the session->last_ev->usecount
     is never decremented, leading to events lingering in the queue

  The impact of this bug does not seem major. The events are small and do
  not seem, from our testing, to be causing meaningful additional CPU
  usage. Mainly we wanted to fix this issue because we are internally
  adding prometheus metrics to the eventq and those leaked events were
  causing the metrics to show garbage data.

#### res_pjsip_nat.c: Do not overwrite transfer host
  Author: Mike Bradeen
  Date:   2025-05-08

  When a call is transfered via dialplan behind a NAT, the
  host portion of the Contact header in the 302 will no longer
  be over-written with the external NAT IP and will retain the
  hostname.

  Fixes: #1141

#### chan_pjsip: Serialize INVITE creation on DTMF attended transfer
  Author: Mike Bradeen
  Date:   2025-05-05

  When a call is transfered via DTMF feature code, the Transfer Target and
  Transferer are bridged immediately.  This opens the possibilty of a race
  condition between the creation of an INVITE and the bridge induced colp
  update that can result in the set caller ID being over-written with the
  transferer's default info.

  Fixes: #1234

#### Alternate Channel Storage Backends
  Author: George Joseph
  Date:   2024-12-31

  Full details: http://s.asterisk.net/dc679ec3

  The previous proof-of-concept showed that the cpp_map_name_id alternate
  storage backed performed better than all the others so this final PR
  adds only that option.  You still need to enable it in menuselect under
  the "Alternate Channel Storage Backends" category.

  To select which one is used at runtime, set the "channel_storage_backend"
  option in asterisk.conf to one of the values described in
  asterisk.conf.sample.  The default remains "ao2_legacy".

  UpgradeNote: With this release, you can now select an alternate channel
  storage backend based on C++ Maps.  Using the new backend may increase
  performance and reduce the chances of deadlocks on heavily loaded systems.
  For more information, see http://s.asterisk.net/dc679ec3

#### sig_analog: Add Call Waiting Deluxe support.
  Author: Naveen Albert
  Date:   2023-08-24

  Adds support for Call Waiting Deluxe options to enhance
  the current call waiting feature.

  As part of this change, a mechanism is also added that
  allows a channel driver to queue an audio file for Dial()
  to play, which is necessary for the announcement function.

  ASTERISK-30373 #close

  Resolves: #271

  UserNote: Call Waiting Deluxe can now be enabled for FXS channels
  by enabling its corresponding option.

#### app_sms: Ignore false positive vectorization warning.
  Author: Naveen Albert
  Date:   2025-01-24

  Ignore gcc warning about writing 32 bytes into a region of size 6,
  since we check that we don't go out of bounds for each byte.
  This is due to a vectorization bug in gcc 15, stemming from
  gcc commit 68326d5d1a593dc0bf098c03aac25916168bc5a9.

  Resolves: #1088

#### lock.h: Add include for string.h when DEBUG_THREADS is defined.
  Author: George Joseph
  Date:   2025-05-02

  When DEBUG_THREADS is defined, lock.h uses strerror(), which is defined
  in the libc string.h file, to print warning messages. If the including
  source file doesn't include string.h then strerror() won't be found and
  and compile errors will be thrown. Since lock.h depends on this, string.h
  is now included from there if DEBUG_THREADS is defined.  This way, including
  source files don't have to worry about it.

#### res_pjsip_caller_id: Also parse URI parameters for ANI2.
  Author: Naveen Albert
  Date:   2025-04-26

  If the isup-oli was sent as a URI parameter, rather than a header
  parameter, it was not being parsed. Make sure we parse both if
  needed so the ANI2 is set regardless of which type of parameter
  the isup-oli is sent as.

  Resolves: #1220

#### app_meetme: Remove inaccurate removal version from xmldocs.
  Author: Naveen Albert
  Date:   2025-04-26

  app_meetme is deprecated but wasn't removed as planned in 21,
  so remove the inaccurate removal version.

  Resolves: #1224

#### docs: Fix typos in apps/
  Author: Luz Paz
  Date:   2025-04-09

  Found via codespell


#### stasis/control.c: Set Hangup Cause to No Answer on Dial timeout
  Author: Mike Bradeen
  Date:   2025-04-17

  Other Dial operations (dial, app_dial) use Q.850 cause 19 when a dial timeout occurs,
  but the Dial command via ARI did not set an explicit reason. This resulted in a
  CANCEL with Normal Call Clearing and corresponding ChannelDestroyed.

  This change sets the hangup cause to AST_CAUSE_NO_ANSWER to be consistent with the
  other operations.

  Fixes: #963

  UserNote:  A Dial timeout on POST /channels/{channelId}/dial will now result in a
  CANCEL and ChannelDestroyed with cause 19 / User alerting, no answer.  Previously
  no explicit cause was set, resulting in a cause of 16 / Normal Call Clearing.


#### chan_iax2: Minor improvements to documentation and warning messages.
  Author: Naveen Albert
  Date:   2025-04-18

  * Update Dial() documentation for IAX2 to include syntax for RSA
    public key names.
  * Add additional details to a couple warnings to provide more context
    when an undecodable frame is received.

  Resolves: #1206

#### pbx_ael: unregister AELSub application and CLI commands on module load failure
  Author: Andreas Wehrmann
  Date:   2025-04-18

  This fixes crashes/hangs I noticed with Asterisk 20.3.0 and 20.13.0 and quickly found out,
  that the AEL module doesn't do proper cleanup when it fails to load.
  This happens for example when there are syntax errors and AEL fails to compile in which case pbx_load_module()
  returns an error but load_module() doesn't then unregister CLI cmds and the application.


#### res_pjproject: Fix DTLS client check failing on some platforms
  Author: Albrecht Oster
  Date:   2025-04-10

  Certain platforms (mainly BSD derivatives) have an additional length
  field in `sockaddr_in6` and `sockaddr_in`.
  `ast_sockaddr_from_pj_sockaddr()` does not take this field into account
  when copying over values from the `pj_sockaddr` into the `ast_sockaddr`.
  The resulting `ast_sockaddr` will have an uninitialized value for
  `sin6_len`/`sin_len` while the other `ast_sockaddr` (not converted from
  a `pj_sockaddr`) to check against in `ast_sockaddr_pj_sockaddr_cmp()`
  has the correct length value set.

  This has the effect that `ast_sockaddr_cmp()` will always indicate
  an address mismatch, because it does a bitwise comparison, and all DTLS
  packets are dropped even if addresses and ports match.

  `ast_sockaddr_from_pj_sockaddr()` now checks whether the length fields
  are available on the current platform and sets the values accordingly.

  Resolves: #505

#### Prequisites for ARI Outbound Websockets
  Author: George Joseph
  Date:   2025-04-16

  stasis:
  * Added stasis_app_is_registered().
  * Added stasis_app_control_mark_failed().
  * Added stasis_app_control_is_failed().
  * Fixed res_stasis_device_state so unsubscribe all works properly.
  * Modified stasis_app_unregister() to unsubscribe from all event sources.
  * Modified stasis_app_exec to return -1 if stasis_app_control_is_failed()
    returns true.

  http:
  * Added ast_http_create_basic_auth_header().

  md5:
  * Added define for MD5_DIGEST_LENGTH.

  tcptls:
  * Added flag to ast_tcptls_session_args to suppress connection log messages
    to give callers more control over logging.

  http_websocket:
  * Add flag to ast_websocket_client_options to suppress connection log messages
    to give callers more control over logging.
  * Added username and password to ast_websocket_client_options to support
    outbound basic authentication.
  * Added ast_websocket_result_to_str().


#### contrib: Add systemd service and timer files for malloc trim.
  Author: Ben Ford
  Date:   2025-04-16

  Adds two files to the contrib/systemd/ directory that can be installed
  to periodically run "malloc trim" on Asterisk. These files do nothing
  unless they are explicitly moved to the correct location on the system.
  Users who are experiencing Asterisk memory issues can use this service
  to potentially help combat the problem. These files can also be
  configured to change the start time and interval. See systemd.timer(5)
  and systemd.time(7) for more information.

  UserNote: Service and timer files for systemd have been added to the
  contrib/systemd/ directory. If you are experiencing memory issues,
  install these files to have "malloc trim" periodically run on the
  system.


#### action_redirect: remove after_bridge_goto_info
  Author: Peter Jannesen
  Date:   2025-03-13

  Under certain circumstances the context/extens/prio are stored in the
  after_bridge_goto_info. This info is used when the bridge is broken by
  for hangup of the other party. In the situation that the bridge is
  broken by an AMI Redirect this info is not used but also not removed.
  With the result that when the channel is put back in a bridge and the
  bridge is broken the execution continues at the wrong
  context/extens/prio.

  Resolves: #1144

#### channel: Always provide cause code in ChannelHangupRequest.
  Author: Joshua C. Colp
  Date:   2025-04-16

  When queueing a channel to be hung up a cause code can be
  specified in one of two ways:

  1. ast_queue_hangup_with_cause
  This function takes in a cause code and queues it as part
  of the hangup request, which ultimately results in it being
  set on the channel.

  2. ast_channel_hangupcause_set + ast_queue_hangup
  This combination sets the hangup cause on the channel before
  queueing the hangup instead of as part of that process.

  In the #2 case the ChannelHangupRequest event would not contain
  the cause code. For consistency if a cause code has been set
  on the channel it will now be added to the event.

  Resolves: #1197

#### Add log-caller-id-name option to log Caller ID Name in queue log
  Author: phoneben
  Date:   2025-02-28

  Add log-caller-id-name option to log Caller ID Name in queue log

  This patch introduces a new global configuration option, log-caller-id-name,
  to queues.conf to control whether the Caller ID name is logged when a call enters a queue.

  When log-caller-id-name=yes, the Caller ID name is logged
  as parameter 4 in the queue log, provided it’s allowed by the
  existing log_restricted_caller_id rules. If log-caller-id-name=no (the default),
  the Caller ID name is omitted from the logs.

  Fixes: #1091

  UserNote: This patch adds a global configuration option, log-caller-id-name, to queues.conf
  to control whether the Caller ID name is logged as parameter 4 when a call enters a queue.
  When log-caller-id-name=yes, the Caller ID name is included in the queue log,
  Any '|' characters in the caller ID name will be replaced with '_'.
  (provided it’s allowed by the existing log_restricted_caller_id rules).
  When log-caller-id-name=no (the default), the Caller ID name is omitted.


#### asterisk.c: Add "pre-init" and "pre-module" capability to cli.conf.
  Author: George Joseph
  Date:   2025-04-10

  Commands in the "[startup_commands]" section of cli.conf have historically run
  after all core and module initialization has been completed and just before
  "Asterisk Ready" is printed on the console. This meant that if you
  wanted to debug initialization of a specific module, your only option
  was to turn on debug for everything by setting "debug" in asterisk.conf.

  This commit introduces options to allow you to run CLI commands earlier in
  the asterisk startup process.

  A command with a value of "pre-init" will run just after logger initialization
  but before most core, and all module, initialization.

  A command with a value of "pre-module" will run just after all core
  initialization but before all module initialization.

  A command with a value of "fully-booted" (or "yes" for backwards
  compatibility) will run as they always have been...after all
  initialization and just before "Asterisk Ready" is printed on the console.

  This means you could do this...

  ```
  [startup_commands]
  core set debug 3 res_pjsip.so = pre-module
  core set debug 0 res_pjsip.so = fully-booted
  ```

  This would turn debugging on for res_pjsip.so to catch any module
  initialization debug messages then turn it off again after the module is
  loaded.

  UserNote: In cli.conf, you can now define startup commands that run before
  core initialization and before module initialization.


#### app_confbridge: Prevent crash when publishing channel-less event.
  Author: Sean Bright
  Date:   2025-04-07

  Resolves: #1190

#### ari_websockets: Fix frack if ARI config fails to load.
  Author: George Joseph
  Date:   2025-04-02

  ari_ws_session_registry_dtor() wasn't checking that the container was valid
  before running ao2_callback on it to shutdown registered sessions.


#### ARI: REST over Websocket
  Author: George Joseph
  Date:   2025-03-12

  This commit adds the ability to make ARI REST requests over the same
  websocket used to receive events.

  For full details on how to use the new capability, visit...

  https://docs.asterisk.org/Configuration/Interfaces/Asterisk-REST-Interface-ARI/ARI-REST-over-WebSocket/

  Changes:

  * Added utilities to http.c:
    * ast_get_http_method_from_string().
    * ast_http_parse_post_form().
  * Added utilities to json.c:
    * ast_json_nvp_array_to_ast_variables().
    * ast_variables_to_json_nvp_array().
  * Added definitions for new events to carry REST responses.
  * Created res/ari/ari_websocket_requests.c to house the new request handlers.
  * Moved non-event specific code out of res/ari/resource_events.c into
    res/ari/ari_websockets.c
  * Refactored res/res_ari.c to move non-http code out of ast_ari_callback()
    (which is http specific) and into ast_ari_invoke() so it can be shared
    between both the http and websocket transports.

  UpgradeNote: This commit adds the ability to make ARI REST requests over the same
  websocket used to receive events.
  See https://docs.asterisk.org/Configuration/Interfaces/Asterisk-REST-Interface-ARI/ARI-REST-over-WebSocket/


#### audiohook.c: Add ability to adjust volume with float
  Author: mkmer
  Date:   2025-03-18

  Add the capability to audiohook for float type volume adjustments.  This allows for adjustments to volume smaller than 6dB.  With INT adjustments, the first step is 2 which converts to ~6dB (or 1/2 volume / double volume depending on adjustment sign). 3dB is a typical adjustment level which can now be accommodated with an adjustment value of 1.41.

  This is accomplished by the following:
    Convert internal variables to type float.
    Always use ast_frame_adjust_volume_float() for adjustments.
    Cast int to float in original functions ast_audiohook_volume_set(), and ast_volume_adjust().
    Cast float to int in ast_audiohook_volume_get()
    Add functions ast_audiohook_volume_get_float, ast_audiohook_volume_set_float, and ast_audiohook_volume_adjust_float.

  This update maintains 100% backward compatibility.

  Resolves: #1171

#### audiosocket: added support for DTMF frames
  Author: Florent CHAUVEAU
  Date:   2025-02-28

  Updated the AudioSocket protocol to allow sending DTMF frames.
  AST_FRAME_DTMF frames are now forwarded to the server, in addition to
  AST_FRAME_AUDIO frames. A new payload type AST_AUDIOSOCKET_KIND_DTMF
  with value 0x03 was added to the protocol. The payload is a 1-byte
  ascii representing the DTMF digit (0-9,*,#...).

  UserNote: The AudioSocket protocol now forwards DTMF frames with
  payload type 0x03. The payload is a 1-byte ascii representing the DTMF
  digit (0-9,*,#...).


#### asterisk/channel.h: fix documentation for 'ast_waitfor_nandfds()'
  Author: Norm Harrison
  Date:   2023-04-03

  Co-authored-by: Florent CHAUVEAU <florentch@pm.me>

#### audiosocket: fix timeout, fix dialplan app exit, server address in logs
  Author: Norm Harrison
  Date:   2023-04-03

  - Correct wait timeout logic in the dialplan application.
  - Include server address in log messages for better traceability.
  - Allow dialplan app to exit gracefully on hangup messages and socket closure.
  - Optimize I/O by reducing redundant read()/write() operations.

  Co-authored-by: Florent CHAUVEAU <florentch@pm.me>

#### chan_pjsip:  Add the same details as PJSIPShowContacts to the CLI via 'pjsip show contact'
  Author: Mark Murawski
  Date:   2025-03-23

  CLI 'pjsip show contact' does not show enough information.
  One must telnet to AMI or write a script to ask Asterisk for example what the User-Agent is on a Contact
  This feature adds the same details as PJSIPShowContacts to the CLI

  Resolves: #643

#### Update config.guess and config.sub
  Author: Zhai Liangliang
  Date:   2025-03-26


#### chan_pjsip: set correct Endpoint Device State on multiple channels
  Author: Alexei Gradinari
  Date:   2025-03-25

  1. When one channel is placed on hold, the device state is set to ONHOLD
  without checking other channels states.
  In case of AST_CONTROL_HOLD set the device state as AST_DEVICE_UNKNOWN
  to calculate aggregate device state of all active channels.

  2. The current implementation incorrectly classifies channels in use.
  The only channels that has the states: UP, RING and BUSY are considered as "in use".
  A channel should be considered "in use" if its state is anything other than
  DOWN or RESERVED.

  3. Currently, if the number of channels "in use" is greater than device_state_busy_at,
  the system does not set the state to BUSY. Instead, it incorrectly assigns an aggregate
  device state.
  The endpoint device state should be BUSY if the number of channels "in use" is greater
  than or equal to device_state_busy_at.

  Fixes: #1181

#### file.c: missing "custom" sound files should not generate warning logs
  Author: Allan Nathanson
  Date:   2025-03-18

  With `sounds_search_custom_dir = yes` we first look to see if a sound file
  is present in the "custom" sound directory before looking in the standard
  sound directories.  We should not be issuing a WARNING log message if a
  sound cannot be found in the "custom" directory.

  Resolves: https://github.com/asterisk/asterisk/issues/1170

#### documentation: Update Gosub, Goto, and add new documentationtype.
  Author: Ben Ford
  Date:   2025-03-14

  Gosub and Goto were not displaying their syntax correctly on the docs
  site. This change adds a new way to specify an optional context, an
  optional extension, and a required priority that the xml stylesheet can
  parse without having to know which optional parameters come in which
  order. In Asterisk, it looks like this:

    parameter name="context" documentationtype="dialplan_context"
    parameter name="extension" documentationtype="dialplan_extension"
    parameter name="priority" documentationtype="dialplan_priority" required="true"

  The stylesheet will ignore the context and extension parameters, but for
  priority, it will automatically inject the following:

    [[context,]extension,]priority

  This is the correct oder for applications such as Gosub and Goto.


#### res_config_curl.c: Remove unnecessary warnings.
  Author: Sean Bright
  Date:   2025-03-17

  Resolves: #1164

#### README.md: Updates and Fixes
  Author: George Joseph
  Date:   2025-03-05

  * Outdated information has been removed.
  * New links added.
  * Placeholder added for link to change logs.

  Going forward, the release process will create HTML versions of the README
  and change log and will update the link in the README to the current
  change log for the branch...

  * In the development branches, the link will always point to the current
    release on GitHub.
  * In the "releases/*" branches and the tarballs, the link will point to the
    ChangeLogs/ChangeLog-<version>.html file in the source directory.
  * On the downloads website, the link will point to the
    ChangeLog-<version>.html file in the same directory.

  Resolves: #1131

#### res_rtp_asterisk.c: Don't truncate spec-compliant `ice-ufrag` or `ice-pwd`.
  Author: Sean Bright
  Date:   2025-03-07

  RFC 8839[1] indicates that the `ice-ufrag` and `ice-pwd` attributes
  can be up to 256 bytes long. While we don't generate values of that
  size, we should be able to accomodate them without truncating.

  1. https://www.rfc-editor.org/rfc/rfc8839#name-ice-ufrag-and-ice-pwd-attri


#### fix: Correct default flag for tcp_keepalive_enable option
  Author: Joshua Elson
  Date:   2025-03-06

  Resolves an issue where the tcp_keepalive_enable option was not properly enabled in the sample configuration due to an incorrect default flag setting.

  Fixes: #1149

#### docs: AMI documentation fixes.
  Author: Sean Bright
  Date:   2025-02-18

  Most of this patch is adding missing PJSIP-related event
  documentation, but the one functional change was adding a sorcery
  to-string handler for endpoint's `redirect_method` which was not
  showing up in the AMI event details or `pjsip show endpoint
  <endpoint>` output.

  The rest of the changes are summarized below:

  * app_agent_pool.c: Typo fix Epoche -> Epoch.
  * stasis_bridges.c: Add missing AttendedTransfer properties.
  * stasis_channels.c: Add missing AgentLogoff properties.
  * pjsip_manager.xml:
    - Add missing AorList properties.
    - Add missing AorDetail properties.
    - Add missing ContactList properties.
    - Add missing ContactStatusDetail properties.
    - Add missing EventDetail properties.
    - Add missing AuthList properties.
    - Add missing AuthDetail properties.
    - Add missing TransportDetail properties.
    - Add missing EndpointList properties.
    - Add missing IdentifyDetail properties.
  * res_pjsip_registrar.c: Add missing InboundRegistrationDetail documentation.
  * res_pjsip_pubsub.c:
    - Add missing ResourceListDetail documentation.
    - Add missing InboundSubscriptionDetail documentation.
    - Add missing OutboundSubscriptionDetail documentation.
  * res_pjsip_outbound_registration.c: Add missing OutboundRegistrationDetail documentation.


#### config.c: #include of non-existent file should not crash
  Author: Allan Nathanson
  Date:   2025-03-03

  Corrects a segmentation fault when a configuration file has a #include
  statement that referenced a file that does not exist.

  Resolves: https://github.com/asterisk/asterisk/issues/1139

#### manager.c: Check for restricted file in action_createconfig.
  Author: George Joseph
  Date:   2025-03-03

  The `CreateConfig` manager action now ensures that a config file can
  only be created in the AST_CONFIG_DIR unless `live_dangerously` is set.

  Resolves: #1122

#### swagger_model.py: Fix invalid escape sequence in get_list_parameter_type().
  Author: George Joseph
  Date:   2025-03-04

  Recent python versions complain when backslashes in strings create invalid
  escape sequences.  This causes issues for strings used as regex patterns like
  `'^List\[(.*)\]$'` where you want the regex parser to treat `[` and `]`
  as literals.  Double-backslashing is one way to fix it but simply converting
  the string to a raw string `re.match(r'^List\[(.*)\]$', text)` is easier
  and less error prone.


#### res_rtp_asterisk.c: Use correct timeout value for T.140 RED timer.
  Author: Sean Bright
  Date:   2025-02-24

  Found while reviewing #1128


#### docs: Fix typos in cdr/ Found via codespell
  Author: Luz Paz
  Date:   2025-02-12


#### docs: Fix various typos in channels/ Found via `codespell -q 3 -S "./CREDITS,*.po" -L abd,asent,atleast,cachable,childrens,contentn,crypted,dne,durationm,enew,exten,inout,leapyear,mye,nd,oclock,offsetp,ot,parm,parms,preceeding,pris,ptd,requestor,re-use,re-used,re-uses,ser,siz,slanguage,slin,thirdparty,varn,varns,ues`
  Author: Luz Paz
  Date:   2025-02-04


#### docs: Fix various typos in main/ Found via `codespell -q 3 -S "./CREDITS" -L abd,asent,atleast,childrens,contentn,crypted,dne,durationm,exten,inout,leapyear,nd,oclock,offsetp,ot,parm,parms,requestor,ser,slanguage,slin,thirdparty,varn,varns,ues`
  Author: Luz Paz
  Date:   2025-02-04


#### bridging: Fix multiple bridging issues causing SEGVs and FRACKs.
  Author: George Joseph
  Date:   2025-01-22

  Issues:

  * The bridging core allowed multiple bridges to be created with the same
    unique bridgeId at the same time.  Only the last bridge created with the
    duplicate name was actually saved to the core bridges container.

  * The bridging core was creating a stasis topic for the bridge and saving it
    in the bridge->topic field but not increasing its reference count.  In the
    case where two bridges were created with the same uniqueid (which is also
    the topic name), the second bridge would get the _existing_ topic the first
    bridge created.  When the first bridge was destroyed, it would take the
    topic with it so when the second bridge attempted to publish a message to
    it it either FRACKed or SEGVd.

  * The bridge destructor, which also destroys the bridge topic, is run from the
    bridge manager thread not the caller's thread.  This makes it possible for
    an ARI developer to create a new one with the same uniqueid believing the
    old one was destroyed when, in fact, the old one's destructor hadn't
    completed. This could cause the new bridge to get the old one's topic just
    before the topic was destroyed.  When the new bridge attempted to publish
    a message on that topic, asterisk could either FRACK or SEGV.

  * The ARI bridges resource also allowed multiple bridges to be created with
    the same uniqueid but it kept the duplicate bridges in its app_bridges
    container.  This created a situation where if you added two bridges with
    the same "bridge1" uniqueid, all operations on "bridge1" were performed on
    the first bridge created and the second was basically orphaned.  If you
    attempted to delete what you thought was the second bridge, you actually
    deleted the first one created.

  Changes:

  * A new API `ast_bridge_topic_exists(uniqueid)` was created to determine if
    a topic already exists for a bridge.

  * `bridge_base_init()` in bridge.c and `ast_ari_bridges_create()` in
    resource_bridges.c now call `ast_bridge_topic_exists(uniqueid)` to check
    if a bridge with the requested uniqueid already exists and will fail if it
    does.

  * `bridge_register()` in bridges.c now checks the core bridges container to
    make sure a bridge doesn't already exist with the requested uniqueid.
    Although most callers of `bridge_register()` will have already called
    `bridge_base_init()`, which will now fail on duplicate bridges, there
    is no guarantee of this so we must check again.

  * The core bridges container allocation was changed to reject duplicate
    uniqueids instead of silently replacing an existing one. This is a "belt
    and suspenders" check.

  * A global mutex was added to bridge.c to prevent concurrent calls to
    `bridge_base_init()` and `bridge_register()`.

  * Even though you can no longer create multiple bridges with the same uniqueid
    at the same time, it's still possible that the bridge topic might be
    destroyed while a second bridge with the same uniqueid was trying to use
    it. To address this, the bridging core now increments the reference count
    on bridge->topic when a bridge is created and decrements it when the
    bridge is destroyed.

  * `bridge_create_common()` in res_stasis.c now checks the stasis app_bridges
    container to make sure a bridge with the requested uniqueid doesn't already
    exist.  This may seem like overkill but there are so many entrypoints to
    bridge creation that we need to be safe and catch issues as soon in the
    process as possible.

  * The stasis app_bridges container allocation was changed to reject duplicate
    uniqueids instead of adding them. This is a "belt and suspenders" check.

  * The `bridge show all` CLI command now shows the bridge name as well as the
    bridge id.

  * Response code 409 "Conflict" was added as a possible response from the ARI
    bridge create resources to signal that a bridge with the requested uniqueid
    already exists.

  * Additional debugging was added to multiple bridging and stasis files.

  Resolves: #211

#### bridge_channel: don't set cause code on channel during bridge delete if already set
  Author: Mike Bradeen
  Date:   2025-02-18

  Due to a potential race condition via ARI when hanging up a channel hangup with cause
  while also deleting a bridge containing that channel, the bridge delete can over-write
  the hangup cause code resulting in Normal Call Clearing instead of the set value.

  With this change, bridge deletion will only set the hangup code if it hasn't been
  previously set.

  Resolves: #1124

#### res_config_pgsql: Fix regression that removed dbname config.
  Author: George Joseph
  Date:   2025-02-11

  A recent commit accidentally removed the code that sets dbname.
  This commit adds it back in.

  Resolves: #1119

#### res_stir_shaken: Allow missing or anonymous CID to continue to the dialplan.
  Author: George Joseph
  Date:   2025-02-05

  The verification check for missing or anonymous callerid was happening before
  the endpoint's profile was retrieved which meant that the failure_action
  parameter wasn't available.  Therefore, if verification was enabled and there
  was no callerid or it was "anonymous", the call was immediately terminated
  instead of giving the dialplan the ability to decide what to do with the call.

  * The callerid check now happens after the verification context is created and
    the endpoint's stir_shaken_profile is available.

  * The check now processes the callerid failure just as it does for other
    verification failures and respects the failure_action parameter.  If set
    to "continue" or "continue_return_reason", `STIR_SHAKEN(0,verify_result)`
    in the dialplan will return "invalid_or_no_callerid".

  * If the endpoint's failure_action is "reject_request", the call will be
    rejected with `433 "Anonymity Disallowed"`.

  * If the endpoint's failure_action is "continue_return_reason", the call will
    continue but a `Reason: STIR; cause=433; text="Anonymity Disallowed"`
    header will be added to the next provisional or final response.

  Resolves: #1112

#### resource_channels.c: Fix memory leak in ast_ari_channels_external_media.
  Author: George Joseph
  Date:   2025-02-04

  Between ast_ari_channels_external_media(), external_media_rtp_udp(),
  and external_media_audiosocket_tcp(), the `variables` structure being passed
  around wasn't being cleaned up properly when there was a failure.

  * In ast_ari_channels_external_media(), the `variables` structure is now
    defined with RAII_VAR to ensure it always gets cleaned up.

  * The ast_variables_destroy() call was removed from external_media_rtp_udp().

  * The ast_variables_destroy() call was removed from
    external_media_audiosocket_tcp(), its `endpoint` allocation was changed to
    to use ast_asprintf() as external_media_rtp_udp() does, and it now
    returns an error on failure.

  * ast_ari_channels_external_media() now checks the new return code from
    external_media_audiosocket_tcp() and sets the appropriate error response.

  Resolves: #1109

#### ari/pjsip: Make it possible to control transfers through ARI
  Author: Holger Hans Peter Freyther
  Date:   2024-06-15

  Introduce a ChannelTransfer event and the ability to notify progress to
  ARI. Implement emitting this event from the PJSIP channel instead of
  handling the transfer in Asterisk when configured.

  Introduce a dialplan function to the PJSIP channel to switch between the
  "core" and "ari-only" behavior.

  UserNote: Call transfers on the PJSIP channel can now be controlled by
  ARI. This can be enabled by using the PJSIP_TRANSFER_HANDLING(ari-only)
  dialplan function.


#### channel.c: Remove dead AST_GENERATOR_FD code.
  Author: Sean Bright
  Date:   2025-02-06

  Nothing ever sets the `AST_GENERATOR_FD`, so this block of code will
  never execute. It also is the only place where the `generate` callback
  is called with the channel lock held which made it difficult to reason
  about the thread safety of `ast_generator`s.

  In passing, also note that `AST_AGENT_FD` isn't used either.


#### func_strings.c: Prevent SEGV in HASH single-argument mode.
  Author: George Joseph
  Date:   2025-01-30

  When in single-argument mode (very rarely used), a malformation of a column
  name (also very rare) could cause a NULL to be returned when retrieving the
  channel variable for that column.  Passing that to strncat causes a SEGV.  We
  now check for the NULL and print a warning message.

  Resolves: #1101

#### docs: Add version information to AGI command XML elements.
  Author: George Joseph
  Date:   2025-01-24

  This process was a bit different than the others because everything
  is in the same file, there's an array that contains the command
  names and their handler functions, and the last command was created
  over 15 years ago.

  * Dump a `git blame` of res/res_agi.c from BEFORE the handle_* prototypes
    were changed.
  * Create a command <> handler function xref by parsing the the agi_command
    array.
  * For each entry, grep the function definition line "static int handle_*"
    from the git blame output and capture the commit.  This will be the
    commit the command was created in.
  * Do a `git tag --contains <commit> | sort -V | head -1` to get the
    tag the function was created in.
  * Add a single since/version element to the command XML.  Multiple versions
    aren't supported here because the branching and tagging scheme changed
    several times in the 2000's.


#### docs: Fix minor typo in MixMonitor AMI action
  Author: Jeremy Lainé
  Date:   2025-01-28

  The `Options` argument was erroneously documented as lowercase
  `options`.


#### utils: Disable old style definition warnings for libdb.
  Author: Naveen Albert
  Date:   2025-01-23

  Newer versions of gcc now warn about old style definitions, such
  as those in libdb, which causes compilation failure with DEVMODE
  enabled. Ignore these warnings for libdb.

  Resolves: #1085

#### rtp.conf.sample: Correct stunaddr example.
  Author: fabriziopicconi
  Date:   2024-09-25


#### docs: Add version information to ARI resources and methods.
  Author: George Joseph
  Date:   2025-01-27

  * Dump a git blame of each file in rest-api/api-docs.

  * Get the commit for each "resourcePath" and "httpMethod" entry.

  * Find the tags for each commit (same as other processes).

  * Insert a "since" array after each "resourcePath" and "httpMethod" entry.


#### docs: Indent <since> tags.
  Author: Sean Bright
  Date:   2025-01-23

  Also updates the 'since' of applications/functions that existed before
  XML documentation was introduced (1.6.2.0).


#### res_pjsip_authenticator_digest: Make correct error messages appear again.
  Author: George Joseph
  Date:   2025-01-28

  When an incoming request can't be matched to an endpoint, the "artificial"
  auth object is used to create a challenge to return in a 401 response and we
  emit a "No matching endpoint found" log message. If the client then responds
  with an Authorization header but the request still can't be matched to an
  endpoint, the verification will fail and, as before, we'll create a challenge
  to return in a 401 response and we emit a "No matching endpoint found" log
  message.  HOWEVER, because there WAS an Authorization header and it failed
  verification, we should have also been emitting a "Failed to authenticate"
  log message but weren't because there was a check that short-circuited that
  it if the artificial auth was used.  Since many admins use the "Failed to
  authenticate" message with log parsers like fail2ban, those attempts were not
  being recognized as suspicious.

  Changes:

  * digest_check_auth() now always emits the "Failed to authenticate" log
    message if verification of an Authorization header failed even if the
    artificial auth was used.

  * The verification logic was refactored to be clearer about the handling
    of the return codes from verify().

  * Comments were added clarify what return codes digest_check_auth() should
    return to the distributor and the implications of changing them.

  Resolves: #1095

#### alembic: Database updates required.
  Author: George Joseph
  Date:   2025-01-28

  This commit doesn't actually change anything.  It just adds the following
  upgrade notes that were omitted from the original commits.

  Resolves: #1097

  UpgradeNote: Two commits in this release...
  'Add SHA-256 and SHA-512-256 as authentication digest algorithms'
  'res_pjsip: Add new AOR option "qualify_2xx_only"'
  ...have modified alembic scripts for the following database tables: ps_aors,
  ps_contacts, ps_auths, ps_globals. If you don't use the scripts to update
  your database, reads from those tables will succeeed but inserts into the
  ps_contacts table by res_pjsip_registrar will fail.

#### res_pjsip: Fix startup/reload memory leak in config_auth.
  Author: George Joseph
  Date:   2025-01-23

  An issue in config_auth.c:ast_sip_auth_digest_algorithms_vector_init() was
  causing double allocations for the two supported_algorithms vectors to the
  tune of 915 bytes.  The leak only happens on startup and when a reload is done
  and doesn't get bigger with the number of auth objects defined.

  * Pre-initialized the two vectors in config_auth:auth_alloc().
  * Removed the allocations in ast_sip_auth_digest_algorithms_vector_init().
  * Added a note to the doc for ast_sip_auth_digest_algorithms_vector_init()
    noting that the vector passed in should be initialized and empty.
  * Simplified the create_artificial_auth() function in pjsip_distributor.
  * Set the vector initialization count to 0 in config_global:global_apply().

#### docs: Add version information to application and function XML elements
  Author: George Joseph
  Date:   2025-01-23

  * Do a git blame on the embedded XML application or function element.

  * From the commit hash, grab the summary line.

  * Do a git log --grep <summary> to find the cherry-pick commits in all
    branches that match.

  * Do a git patch-id to ensure the commits are all related and didn't get
    a false match on the summary.

  * Do a git tag --contains <commit> to find the tags that contain each
    commit.

  * Weed out all tags not ..0.

  * Sort and discard any .0.0 and following tags where the commit
    appeared in an earlier branch.

  * The result is a single tag for each branch where the application or function
    was defined.

  The applications and functions defined in the following files were done by
  hand because the XML was extracted from the C source file relatively recently.
  * channels/pjsip/dialplan_functions_doc.xml
  * main/logger_doc.xml
  * main/manager_doc.xml
  * res/res_geolocation/geoloc_doc.xml
  * res/res_stir_shaken/stir_shaken_doc.xml


#### docs: Add version information to manager event instance XML elements
  Author: George Joseph
  Date:   2025-01-20

  * Do a git blame on the embedded XML managerEvent elements.

  * From the commit hash, grab the summary line.

  * Do a git log --grep <summary> to find the cherry-pick commits in all
    branches that match.

  * Do a git patch-id to ensure the commits are all related and didn't get
    a false match on the summary.

  * Do a git tag --contains <commit> to find the tags that contain each
    commit.

  * Weed out all tags not ..0.

  * Sort and discard any .0.0 and following tags where the commit
    appeared in an earlier branch.

  * The result is a single tag for each branch where the application or function
    was defined.

  The events defined in res/res_pjsip/pjsip_manager.xml were done by hand
  because the XML was extracted from the C source file relatively recently.

  Two bugs were fixed along the way...

  * The get_documentation awk script was exiting after it processed the first
    DOCUMENTATION block it found in a file.  We have at least 1 source file
    with multiple DOCUMENTATION blocks so only the first one in them was being
    processed.  The awk script was changed to continue searching rather
    than exiting after the first block.

  * Fixing the awk script revealed an issue in logger.c where the third
    DOCUMENTATION block contained a XML fragment that consisted only of
    a managerEventInstance element that wasn't wrapped in a managerEvent
    element.  Since logger_doc.xml already existed, the remaining fragments
    in logger.c were moved to it and properly organized.


#### LICENSE: Update company name, email, and address.
  Author: Joshua C. Colp
  Date:   2025-01-21


#### res_prometheus.c: Set Content-Type header on /metrics response.
  Author: Sean Bright
  Date:   2025-01-21

  This should resolve the Prometheus error:

  > Error scraping target: non-compliant scrape target
    sending blank Content-Type and no
    fallback_scrape_protocol specified for target.

  Resolves: #1075

#### README.md, asterisk.c: Update Copyright Dates
  Author: George Joseph
  Date:   2025-01-20


#### docs: Add version information to configObject and configOption XML elements
  Author: George Joseph
  Date:   2025-01-16

  Most of the configObjects and configOptions that are implemented with
  ACO or Sorcery now have `<since>/<version>` elements added.  There are
  probably some that the script I used didn't catch.  The version tags were
  determined by the following...
   * Do a git blame on the API call that created the object or option.
   * From the commit hash, grab the summary line.
   * Do a `git log --grep <summary>` to find the cherry-pick commits in all
     branches that match.
   * Do a `git patch-id` to ensure the commits are all related and didn't get
     a false match on the summary.
   * Do a `git tag --contains <commit>` to find the tags that contain each
     commit.
   * Weed out all tags not <major>.<minor>.0.
   * Sort and discard any <major>.0.0 and following tags where the commit
     appeared in an earlier branch.
   * The result is a single tag for each branch where the API was last touched.

  configObjects and configOptions elements implemented with the base
  ast_config APIs were just not possible to find due to the non-deterministic
  way they are accessed.

  Also note that if the API call was on modified after it was added, the
  version will be the one it was last modified in.

  Final note:  The configObject and configOption elements were introduced in
  12.0.0 so options created before then may not have any XML documentation.


#### res_pjsip_authenticator_digest: Fix issue with missing auth and DONT_OPTIMIZE
  Author: George Joseph
  Date:   2025-01-17

  The return code fom digest_check_auth wasn't explicitly being initialized.
  The return code also wasn't explicitly set to CHALLENGE when challenges
  were sent.  When optimization was turned off (DONT_OPTIMIZE), the compiler
  was setting it to "0"(CHALLENGE) which worked fine.  However, with
  optimization turned on, it was setting it to "1" (SUCCESS) so if there was
  no incoming Authorization header, the function was returning SUCCESS to the
  distributor allowing the request to incorrectly succeed.

  The return code is now initialized correctly and is now explicitly set
  to CHALLENGE when we send challenges.


#### ast_tls_cert: Add option to skip passphrase for CA private key.
  Author: Naveen Albert
  Date:   2025-01-14

  Currently, the ast_tls_cert file is hardcoded to use the -des3 option
  for 3DES encryption, and the script needs to be manually modified
  to not require a passphrase. Add an option (-e) that disables
  encryption of the CA private key so no passphrase is required.

  Resolves: #1064

#### chan_iax2: Avoid unnecessarily backlogging non-voice frames.
  Author: Naveen Albert
  Date:   2025-01-09

  Currently, when receiving an unauthenticated call, we keep track
  of the negotiated format in the chosenformat, which allows us
  to later create the channel using the right format. However,
  this was not done for authenticated calls. This meant that in
  certain circumstances, if we had not yet received a voice frame
  from the peer, only certain other types of frames (e.g. text),
  there were no variables containing the appropriate frame.
  This led to problems in the jitterbuffer callback where we
  unnecessarily bailed out of retrieving a frame from the jitterbuffer.
  This was logic intentionally added in commit 73103bdcd5b342ce5dfa32039333ffadad551151
  in response to an earlier regression, and while this prevents
  crashes, it also backlogs legitimate frames unnecessarily.

  The abort logic was initially added because at this point in the
  code, we did not have the negotiated format available to us.
  However, it should always be available to us as a last resort
  in chosenformat, so we now pull it from there if needed. This
  allows us to process frames the jitterbuffer even if voicefmt
  and peerfmt aren't set and still avoid the crash. The failsafe
  logic is retained, but now it shouldn't be triggered anymore.

  Resolves: #1054

#### config.c: fix #tryinclude being converted to #include on rewrite
  Author: Allan Nathanson
  Date:   2024-09-16

  Correct an issue in ast_config_text_file_save2() when updating configuration
  files with "#tryinclude" statements. The API currently replaces "#tryinclude"
  with "#include". The API also creates empty template files if the referenced
  files do not exist. This change resolves these problems.

  Resolves: https://github.com/asterisk/asterisk/issues/920

#### sig_analog: Add Last Number Redial feature.
  Author: Naveen Albert
  Date:   2023-11-10

  This adds the Last Number Redial feature to
  simple switch.

  UserNote: Users can now redial the last number
  called if the lastnumredial setting is set to yes.

  Resolves: #437

#### docs: Various XML fixes
  Author: George Joseph
  Date:   2025-01-15

  * channels/pjsip/dialplan_functions_doc.xml: Added xmlns:xi to docs element.

  * main/bucket.c: Removed XML completely since the "bucket" and "file" objects
    are internal only with no config file.

  * main/named_acl.c: Fixed the configFile element name. It was "named_acl.conf"
    and should have been "acl.conf"

  * res/res_geolocation/geoloc_doc.xml: Added xmlns:xi to docs element.

  * res/res_http_media_cache.c: Fixed the configFile element name. It was
    "http_media_cache.conf" and should have been "res_http_media_cache.conf".


#### strings.c: Improve numeric detection in `ast_strings_match()`.
  Author: Sean Bright
  Date:   2025-01-15

  Essentially, we were treating 1234x1234 and 1234x5678 as 'equal'
  because we were able to convert the prefix of each of these strings to
  the same number.

  Resolves: #1028

#### docs: Enable since/version handling for XML, CLI and ARI documentation
  Author: George Joseph
  Date:   2025-01-09

  * Added the "since" element to the XML configObject and configOption elements
    in appdocsxml.dtd.

  * Added the "Since" section to the following CLI output:
    ```
    config show help <module> <object>
    config show help <module> <object> <option>
    core show application <app>
    core show function <func>
    manager show command <command>
    manager show event <event>
    agi show commands topic <topic>
    ```

  * Refactored the commands above to output their sections in the same order:
    Synopsis, Since, Description, Syntax, Arguments, SeeAlso

  * Refactored the commands above so they all use the same pattern for writing
    the output to the CLI.

  * Fixed several memory leaks caused by failure to free temporary output
    buffers.

  * Added a "since" array to the mustache template for the top-level resources
    (Channel, Endpoint, etc.) and to the paths/methods underneath them. These
    will be added to the generated markdown if present.
    Example:
    ```
      "resourcePath": "/api-docs/channels.{format}",
      "requiresModules": [
          "res_stasis_answer",
          "res_stasis_playback",
          "res_stasis_recording",
          "res_stasis_snoop"
      ],
      "since": [
          "18.0.0",
          "21.0.0"
      ],
      "apis": [
          {
              "path": "/channels",
              "description": "Active channels",
              "operations": [
                  {
                      "httpMethod": "GET",
                      "since": [
                          "18.6.0",
                          "21.8.0"
                      ],
                      "summary": "List all active channels in Asterisk.",
                      "nickname": "list",
                      "responseClass": "List[Channel]"
                  },

    ```

  NOTE:  No versioning information is actually added in this commit.
  Those will be added separately and instructions for adding and maintaining
  them will be published on the documentation site at a later date.


#### logger.h: Fix build when AST_DEVMODE is not defined.
  Author: Artem Umerov
  Date:   2025-01-13

  Resolves: #1058

#### dialplan_functions_doc.xml: Document PJSIP_MEDIA_OFFER's `media` argument.
  Author: Sean Bright
  Date:   2025-01-14

  Resolves: #1023

#### samples: Use "asterisk" instead of "postgres" for username
  Author: Abdelkader Boudih
  Date:   2025-01-07


#### manager: Add `<since>` tags for all AMI actions.
  Author: Sean Bright
  Date:   2025-01-02


#### logger.c fix: malformed JSON template
  Author: Steffen Arntz
  Date:   2025-01-08

  this typo was mentioned before, but never got fixed.
  https://community.asterisk.org/t/logger-cannot-log-long-json-lines-properly/87618/6


#### manager.c: Rename restrictedFile to is_restricted_file.
  Author: Sean Bright
  Date:   2025-01-09

  Also correct the spelling of 'privileges.'


#### res_config_pgsql: normalize database connection option with cel and cdr by supporting new options name
  Author: Abdelkader Boudih
  Date:   2025-01-08


#### res_pjproject: Fix typo (OpenmSSL->OpenSSL)
  Author: Stanislav Abramenkov
  Date:   2025-01-10

  Fix typo (OpenmSSL->OpenSSL) mentioned by bkford in #972


#### Add SHA-256 and SHA-512-256 as authentication digest algorithms
  Author: George Joseph
  Date:   2024-10-17

  * Refactored pjproject code to support the new algorithms and
  added a patch file to third-party/pjproject/patches

  * Added new parameters to the pjsip auth object:
    * password_digest = <algorithm>:<digest>
    * supported_algorithms_uac = List of algorithms to support
      when acting as a UAC.
    * supported_algorithms_uas = List of algorithms to support
      when acting as a UAS.
    See the auth object in pjsip.conf.sample for detailed info.

  * Updated both res_pjsip_authenticator_digest.c (for UAS) and
  res_pjsip_outbound_authentocator_digest.c (UAC) to suport the
  new algorithms.

  The new algorithms are only available with the bundled version
  of pjproject, or an external version > 2.14.1.  OpenSSL version
  1.1.1 or greater is required to support SHA-512-256.

  Resolves: #948

  UserNote: The SHA-256 and SHA-512-256 algorithms are now available
  for authentication as both a UAS and a UAC.


#### config.c: retain leading whitespace before comments
  Author: Allan Nathanson
  Date:   2024-10-30

  Configurations loaded with the ast_config_load2() API and later written
  out with ast_config_text_file_save2() will have any leading whitespace
  stripped away.  The APIs should make reasonable efforts to maintain the
  content and formatting of the configuration files.

  This change retains any leading whitespace from comment lines that start
  with a ";".

  Resolves: https://github.com/asterisk/asterisk/issues/970

#### config.c: Fix off-nominal reference leak.
  Author: Sean Bright
  Date:   2025-01-07

  This was identified and fixed by @Allan-N in #918 but it is an
  important fix in its own right.

  The fix here is slightly different than Allan's in that we just move
  the initialization of the problematic AO2 container to where it is
  first used.

  Fixes #1046


#### normalize contrib/ast-db-manage/queue_log.ini.sample
  Author: Abdelkader Boudih
  Date:   2025-01-05


#### Add C++ Standard detection to configure and fix a new C++20 compile issue
  Author: George Joseph
  Date:   2025-01-03

  * The autoconf-archive package contains macros useful for detecting C++
    standard and testing other C++ capabilities but that package was never
    included in the install_prereq script so many existing build environments
    won't have it.  Even if it is installed, older versions won't newer C++
    standards and will actually cause an error if you try to test for that
    version. To make it available for those environments, the
    ax_cxx_compile_stdcxx.m4 macro has copied from the latest release of
    autoconf-archive into the autoconf directory.

  * A convenience wrapper(ast_cxx_check_std) around ax_cxx_compile_stdcxx was
    also added so checking the standard version and setting the
    asterisk-specific PBX_ variables becomes a one-liner:
    `AST_CXX_CHECK_STD([std], [force_latest_std])`.
    Calling that with a version of `17` for instance, will set PBX_CXX17
    to 0 or 1 depending on whether the current c++ compiler supports stdc++17.
    HAVE_CXX17 will also be 'defined" or not depending on the result.

  * C++ compilers hardly ever default to the latest standard they support.  g++
    version 14 for instance supports up to C++23 but only uses C++17 by default.
    If you want to use C++23, you have to add `-std=gnu++=23` to the g++
    command line.  If you set the second argument of AST_CXX_CHECK_STD to "yes",
    the macro will automatically keep the highest `-std=gnu++` value that
    worked and pass that to the Makefiles.

  * The autoconf-archive package was added to install_prereq for future use.

  * Updated configure.ac to use AST_CXX_CHECK_STD() to check for C++
    versions 11, 14, 17, 20 and 23.

  * Updated configure.ac to accept the `--enable-latest-cxx-std` option which
    will set the second option to AST_CXX_CHECK_STD() to "yes".  The default
    is "no".

  * ast_copy_string() in strings.h declares the 'sz' variable as volatile and
    does an `sz--` on it later.  C++20 no longer allows the `++` and `--`
    increment and decrement operators to be used on variables declared as
    volatile however so that was changed to `sz -= 1`.


#### chan_dahdi: Fix wrong channel state when RINGING recieved.
  Author: Naveen Albert
  Date:   2024-12-16

  Previously, when AST_CONTROL_RINGING was received by
  a DAHDI device, it would set its channel state to
  AST_STATE_RINGING. However, an analysis of the codebase
  and other channel drivers reveals RINGING corresponds to
  physical power ringing, whereas AST_STATE_RING should be
  used for audible ringback on the channel. This also ensures
  the correct device state is returned by the channel state
  to device state conversion.

  Since there seems to be confusion in various places regarding
  AST_STATE_RING vs. AST_STATE_RINGING, some documentation has
  been added or corrected to clarify the actual purposes of these
  two channel states, and the associated device state mapping.

  An edge case that prompted this fix, but isn't explicitly
  addressed here, is that of an incoming call to an FXO port.
  The channel state will be "Ring", which maps to a device state
  of "In Use", not "Ringing" as would be more intuitive. However,
  this is semantic, since technically, Asterisk is treating this
  the same as any other incoming call, and so "Ring" is the
  semantic state (put another way, Asterisk isn't ringing anything,
  like in the cases where channels are in the "Ringing" state).

  Since FXO ports don't currently support Call Waiting, a suitable
  workaround for the above would be to ignore the device state and
  instead check the channel state (e.g. IMPORT(DAHDI/1-1,CHANNEL(state)))
  since it will be Ring if the FXO port is idle (but a call is ringing
  on it) and Up if the FXO port is actually in use. (In both cases,
  the device state would misleadingly be "In Use".)

  Resolves: #1029

#### Upgrade bundled pjproject to 2.15.1 Resolves: asterisk#1016
  Author: Stanislav Abramenkov
  Date:   2024-12-03

  UserNote: Bundled pjproject has been upgraded to 2.15.1. For more
  information visit pjproject Github page: https://github.com/pjsip/pjproject/releases/tag/2.15.1


#### gcc14: Fix issues caught by gcc 14
  Author: George Joseph
  Date:   2025-01-03

  * test_message.c: Fix segfaults caused by passing NULL as an sprintf fmt.


#### Header fixes for compiling C++ source files
  Author: George Joseph
  Date:   2024-12-31

  A few tweaks needed to be done to some existing header files to allow them to
  be compiled when included from C++ source files.

  logger.h had declarations for ast_register_verbose() and
  ast_unregister_verbose() which caused C++ issues but those functions were
  actually removed from logger.c many years ago so the declarations were just
  removed from logger.h.


#### Add ability to pass arguments to unit tests from the CLI
  Author: George Joseph
  Date:   2024-12-27

  Unit tests can now be passed custom arguments from the command
  line.  For example, the following command would run the "mytest" test
  in the "/main/mycat" category with the option "myoption=54"

  `CLI> test execute category /main/mycat name mytest options myoption=54`

  You can also pass options to an entire category...

  `CLI> test execute category /main/mycat options myoption=54`

  Basically, everything after the "options" keyword is passed verbatim to
  the test which must decide what to do with it.

  * A new API ast_test_get_cli_args() was created to give the tests access to
  the cli_args->argc and cli_args->argv elements.

  * Although not needed for the option processing, a new macro
  ast_test_validate_cleanup_custom() was added to test.h that allows you
  to specify a custom error message instead of just "Condition failed".

  * The test_skel.c was updated to demonstrate parsing options and the use
  of the ast_test_validate_cleanup_custom() macro.


#### res_pjsip: Add new AOR option "qualify_2xx_only"
  Author: Kent
  Date:   2024-12-03

  Added a new option "qualify_2xx_only" to the res_pjsip AOR qualify
  feature to mark a contact as available only if an OPTIONS request
  returns a 2XX response. If the option is not specified or is false,
  any response to the OPTIONS request marks the contact as available.

  UserNote: The pjsip.conf AOR section now has a "qualify_2xx_only"
  option that can be set so that only 2XX responses to OPTIONS requests
  used to qualify a contact will mark the contact as available.


#### res_odbc: release threads from potential starvation.
  Author: Jaco Kroon
  Date:   2024-12-10

  Whenever a slot is freed up due to a failed connection, wake up a waiter
  before failing.

  In the case of a dead connection there could be waiters, for example,
  let's say two threads tries to acquire objects at the same time, with
  one in the cached connections, one will acquire the dead connection, and
  the other will enter into the wait state.  The thread with the dead
  connection will clear up the dead connection, and then attempt a
  re-acquire (at this point there cannot be cached connections else the
  other thread would have received that and tried to clean up), as such,
  at this point we're guaranteed that either there are no waiting threads,
  or that the maxconnections - connection_cnt threads will attempt to
  re-acquire connections, and then either succeed, using those
  connections, or failing, and then signalling to release more waiters.

  Also fix the pointer log for ODBC handle %p dead which would always
  reflect NULL.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### app_queue: indicate the paused state of a dynamically added member in queue_log.
  Author: Sperl Viktor
  Date:   2024-12-05

  Fixes: #1021

#### Allow C++ source files (as extension .cc) in the main directory
  Author: George Joseph
  Date:   2024-12-09

  Although C++ files (as extension .cc) have been handled in the module
  directories for many years, the main directory was missing one line in its
  Makefile that prevented C++ files from being recognised there.


#### format_gsm.c: Added mime type
  Author: Alexey Khabulyak
  Date:   2024-12-03

  Sometimes it's impossible to get a file extension from URL
  (eg. http://example.com/gsm/your) so we have to rely on content-type header.
  Currenly, asterisk does not support content-type for gsm format(unlike wav).
  Added audio/gsm according to https://www.rfc-editor.org/rfc/rfc4856.html


#### func_uuid: Add a new dialplan function to generate UUIDs
  Author: Maksim Nesterov
  Date:   2024-12-01

  This function is useful for uniquely identifying calls, recordings, and other entities in distributed environments, as well as for generating an argument for the AudioSocket application.


#### app_queue: allow dynamically adding a queue member in paused state.
  Author: Sperl Viktor
  Date:   2024-11-27

  Fixes: #1007

  UserNote: use the p option of AddQueueMember() for paused member state.
  Optionally, use the r(reason) option to specify a custom reason for the pause.


#### chan_iax2: Add log message for rejected calls.
  Author: Naveen Albert
  Date:   2023-11-06

  Add a log message for a path that currently silently drops IAX2
  frames without indicating that anything is wrong.


#### chan_pjsip: Send VIDUPDATE RTP frame for all H.264 streams
  Author: Maximilian Fridrich
  Date:   2024-12-02

  Currently, when a chan_pjsip channel receives a VIDUPDATE indication,
  an RTP VIDUPDATE frame is only queued on a H.264 stream if WebRTC is
  enabled on that endpoint. This restriction does not really make sense.

  Now, a VIDUPDATE RTP frame is written even if WebRTC is not enabled (as
  is the case with VP8, VP9, and H.265 streams).

  Resolves: #1013

#### audiohook.c: resolving the issue with audiohook both reading when packet loss on one side of the call
  Author: Tinet-mucw
  Date:   2024-08-22

  When there is 0% packet loss on one side of the call and 15% packet loss on the other side, reading frame is often failed when reading direction_both audiohook. when read_factory available = 0, write_factory available = 320; i think write factory is usable read; because after reading one frame, there is still another frame that can be read together with the next read factory frame.

  Resolves: #851

#### res_curl.conf.sample: clean up sample configuration and add new SSL options
  Author: Mike Pultz
  Date:   2024-11-21

  This update properly documents all the current configuration options supported
  by the curl implementation, including the new ssl_* options.


#### res_rtp_asterisk.c: Fix bridged_payload matching with sample rate for DTMF
  Author: Alexey Vasilyev
  Date:   2024-11-25

  Fixes #1004


#### manager.c: Add Processed Call Count to CoreStatus output
  Author: Mike Pultz
  Date:   2024-11-21

  This update adds the processed call count to the CoreStatus AMI Action responsie. This output is
  similar to the values returned by "core show channels" or "core show calls" in the CLI.

  UserNote: The current processed call count is now returned as CoreProcessedCalls from the
  CoreStatus AMI Action.


#### func_curl.c: Add additional CURL options for SSL requests
  Author: Mike Pultz
  Date:   2024-11-09

  This patch adds additional CURL TLS options / options to support mTLS authenticated requests:

  * ssl_verifyhost - perform a host verification on the peer certificate (CURLOPT_SSL_VERIFYHOST)
  * ssl_cainfo - define a CA certificate file (CURLOPT_CAINFO)
  * ssl_capath - define a CA certificate directory (CURLOPT_CAPATH)
  * ssl_cert - define a client certificate for the request (CURLOPT_SSLCERT)
  * ssl_certtype - specify the client certificate type (CURLOPT_SSLCERTTYPE)
  * ssl_key - define a client private key for the request (CURLOPT_SSLKEY)
  * ssl_keytype - specify the client private key type (CURLOPT_SSLKEYTYPE)
  * ssl_keypasswd - set a password for the private key, if required (CURLOPT_KEYPASSWD)

  UserNote: The following new configuration options are now available
  in the res_curl.conf file, and the CURL() function: 'ssl_verifyhost'
  (CURLOPT_SSL_VERIFYHOST), 'ssl_cainfo' (CURLOPT_CAINFO), 'ssl_capath'
  (CURLOPT_CAPATH), 'ssl_cert' (CURLOPT_SSLCERT), 'ssl_certtype'
  (CURLOPT_SSLCERTTYPE), 'ssl_key' (CURLOPT_SSLKEY), 'ssl_keytype',
  (CURLOPT_SSLKEYTYPE) and 'ssl_keypasswd' (CURLOPT_KEYPASSWD). See the
  libcurl documentation for more details.


#### sig_analog: Fix regression with FGD and E911 signaling.
  Author: Naveen Albert
  Date:   2024-11-14

  Commit 466eb4a52b69e6dead7ebba13a83f14ef8a559c1 introduced a regression
  which completely broke Feature Group D and E911 signaling, by removing
  the call to analog_my_getsigstr, which affected multiple switch cases.
  Restore the original behavior for all protocols except Feature Group C
  CAMA (MF), which is all that patch was attempting to target.

  Resolves: #993

#### main/stasis_channels.c: Fix crash when setting a global variable with invalid UTF8 characters
  Author: James Terhune
  Date:   2024-11-18

  Add check for null value of chan before referencing it with ast_channel_name()

  Resolves: #999

#### res_stir_shaken: Allow sending Identity headers for unknown TNs
  Author: George Joseph
  Date:   2024-11-08

  Added a new option "unknown_tn_attest_level" to allow Identity
  headers to be sent when a callerid TN isn't explicitly configured
  in stir_shaken.conf.  Since there's no TN object, a private_key_file
  and public_cert_url must be configured in the attestation or profile
  objects.

  Since "unknown_tn_attest_level" uses the same enum as attest_level,
  some of the sorcery macros had to be refactored to allow sharing
  the enum and to/from string conversion functions.

  Also fixed a memory leak in crypto_utils:pem_file_cb().

  Resolves: #921

  UserNote: You can now set the "unknown_tn_attest_level" option
  in the attestation and/or profile objects in stir_shaken.conf to
  enable sending Identity headers for callerid TNs not explicitly
  configured.


#### manager.c: Restrict ListCategories to the configuration directory.
  Author: Ben Ford
  Date:   2024-12-17

  When using the ListCategories AMI action, it was possible to traverse
  upwards through the directories to files outside of the configured
  configuration directory. This action is now restricted to the configured
  directory and an error will now be returned if the specified file is
  outside of this limitation.

  Resolves: #GHSA-33x6-fj46-6rfh

  UserNote: The ListCategories AMI action now restricts files to the
  configured configuration directory.

#### res_pjsip: Change suppress_moh_on_sendonly to OPT_BOOL_T
  Author: George Joseph
  Date:   2024-11-15

  The suppress_moh_on_sendonly endpoint option should have been
  defined as OPT_BOOL_T in pjsip_configuration.c and AST_BOOL_VALUES
  in the alembic script instead of OPT_YESNO_T and YESNO_VALUES.

  Also updated contrib/ast-db-manage/README.md to indicate that
  AST_BOOL_VALUES should always be used and provided an example.

  Resolves: #995

#### res_pjsip: Add new endpoint option "suppress_moh_on_sendonly"
  Author: George Joseph
  Date:   2024-11-05

  Normally, when one party in a call sends Asterisk an SDP with
  a "sendonly" or "inactive" attribute it means "hold" and causes
  Asterisk to start playing MOH back to the other party. This can be
  problematic if it happens at certain times, such as in a 183
  Progress message, because the MOH will replace any early media you
  may be playing to the calling party. If you set this option
  to "yes" on an endpoint and the endpoint receives an SDP
  with "sendonly" or "inactive", Asterisk will NOT play MOH back to
  the other party.

  Resolves: #979

  UserNote: The new "suppress_moh_on_sendonly" endpoint option
  can be used to prevent playing MOH back to a caller if the remote
  end sends "sendonly" or "inactive" (hold) to Asterisk in an SDP.


#### res_pjsip.c: Fix Contact header rendering for IPv6 addresses.
  Author: Sean Bright
  Date:   2024-11-08

  Fix suggested by @nvsystems.

  Fixes #985


#### samples: remove and/or change some wiki mentions
  Author: chrsmj
  Date:   2024-11-01

  Cleaned some dead links. Replaced word wiki with
  either docs or link to https://docs.asterisk.org/

  Resolves: #974

#### func_pjsip_aor/contact: Fix documentation for contact ID
  Author: George Joseph
  Date:   2024-11-09

  Clarified the use of the contact ID returned from PJSIP_AOR.

  Resolves: #990

#### res_pjsip: Move tenantid to end of ast_sip_endpoint
  Author: George Joseph
  Date:   2024-11-06

  The tenantid field was originally added to the ast_sip_endpoint
  structure at the end of the AST_DECLARE_STRING_FIELDS block.  This
  caused everything after it in the structure to move down in memory
  and break ABI compatibility.  It's now at the end of the structure
  as an AST_STRING_FIELD_EXTENDED.  Given the number of string fields
  in the structure now, the initial string field allocation was
  also increased from 64 to 128 bytes.

  Resolves: #982

#### pjsip_transport_events: handle multiple addresses for a domain
  Author: Thomas Guebels
  Date:   2024-10-29

  The key used for transport monitors was the remote host name for the
  transport and not the remote address resolved for this domain.

  This was problematic for domains returning multiple addresses as several
  transport monitors were created with the same key.

  Whenever a subsystem wanted to register a callback it would always end
  up attached to the first transport monitor with a matching key.

  The key used for transport monitors is now the remote address and port
  the transport actually connected to.

  Fixes: #932

#### func_evalexten: Add EVAL_SUB function.
  Author: Naveen Albert
  Date:   2024-10-17

  This adds an EVAL_SUB function, which is similar to the existing
  EVAL_EXTEN function but significantly more powerful, as it allows
  executing arbitrary dialplan and capturing its return value as
  the function's output. While EVAL_EXTEN should be preferred if it
  is possible to use it, EVAL_SUB can be used in a wider variety
  of cases and allows arbitrary computation to be performed in
  a dialplan function call, leveraging the dialplan.

  Resolves: #951

#### res_srtp: Change Unsupported crypto suite msg from verbose to debug
  Author: George Joseph
  Date:   2024-11-01

  There's really no point in spamming logs with a verbose message
  for every unsupported crypto suite an older client may send
  in an SDP.  If none are supported, there will be an error or
  warning.


#### Add res_pjsip_config_sangoma external module.
  Author: Ben Ford
  Date:   2024-11-01

  Adds res_pjsip_config_sangoma as an external module that can be
  downloaded via menuselect. It lives under the Resource Modules section.


#### app_mixmonitor: Add 'D' option for dual-channel audio.
  Author: Ben Ford
  Date:   2024-10-28

  Adds the 'D' option to app_mixmonitor that interleaves the input and
  output frames of the channel being recorded in the monitor output frame.
  This allows for two streams in the recording: the transmitted audio and
  the received audio. The 't' and 'r' options are compatible with this.

  Fixes: #945

  UserNote: The MixMonitor application now has a new 'D' option which
  interleaves the recorded audio in the output frames. This allows for
  stereo recording output with one channel being the transmitted audio and
  the other being the received audio. The 't' and 't' options are
  compatible with this.


#### pjsip_transport_events: Avoid monitor destruction
  Author: Thomas Guebels
  Date:   2024-10-28

  When a transport is disconnected, several events can arrive following
  each other. The first event will be PJSIP_TP_STATE_DISCONNECT and it
  will trigger the destruction of the transport monitor object. The lookup
  for the transport monitor to destroy is done using the transport key,
  that contains the transport destination host:port.

  A reconnect attempt by pjsip will be triggered as soon something needs to
  send a packet using that transport. This can happen directly after a
  disconnect since ca

  Subsequent events can arrive later like PJSIP_TP_STATE_DESTROY and will
  also try to trigger the destruction of the transport monitor if not
  already done. Since the lookup for the transport monitor to destroy is
  done using the transport key, it can match newly created transports
  towards the same destination and destroy their monitor object.

  Because of this, it was sometimes not possible to monitor a transport
  after one or more disconnections.

  This fix adds an additional check on the transport pointer to ensure
  only a monitor for that specific transport is removed.

  Fixes: #923

#### app_dial: Fix progress timeout calculation with no answer timeout.
  Author: Naveen Albert
  Date:   2024-10-16

  If to_answer is -1, simply comparing to see if the progress timeout
  is smaller than the answer timeout to prefer it will fail. Add
  an additional check that chooses the progress timeout if there is
  no answer timeout (or as before, if the progress timeout is smaller).

  Resolves: #821

#### pjproject_bundled:  Tweaks to support out-of-tree development
  Author: George Joseph
  Date:   2024-10-17

  * pjproject is now configured with --disable-libsrtp so it will
    build correctly when doing "out-of-tree" development.  Asterisk
    doesn't use pjproject for handling media so pjproject doesn't
    need libsrtp itself.

  * The pjsua app (which we used to use for the testsuite) no longer
    builds in pjproject's master branch so we just skip it.  The
    testsuite no longer needs it anyway.

  See third-party/pjproject/README-hacking.md for more info on building
  pjproject "out-of-tree".


#### Revert "res_rtp_asterisk: Count a roll-over of the sequence number even on lost packets."
  Author: Sean Bright
  Date:   2024-10-07

  This reverts commit cb5e3445be6c55517c8d05aca601b648341f8ae9.

  The original change from 16 to 15 bit sequence numbers was predicated
  on the following from the now-defunct libSRTP FAQ on sourceforge.net:

  > *Q6. The use of implicit synchronization via ROC seems
  > dangerous. Can senders and receivers lose ROC synchronization?*
  >
  > **A.** It is possible to lose ROC synchronization between sender and
  > receiver(s), though it is not likely in practice, and practical
  > steps can be taken to avoid it. A burst loss of 2^16 packets or more
  > will always break synchronization. For example, a conversational
  > voice codec that sends 50 packets per second will have its ROC
  > increment about every 22 minutes. A network with a burst of packet
  > loss that long has problems other than ROC synchronization.
  >
  > There is a higher sensitivity to loss at the very outset of an SRTP
  > stream. If the sender's initial sequence number is close to the
  > maximum value of 2^16-1, and all packets are lost from the initial
  > packet until the sequence number cycles back to zero, the sender
  > will increment its ROC, but the receiver will not. The receiver
  > cannot determine that the initial packets were lost and that
  > sequence-number rollover has occurred. In this case, the receiver's
  > ROC would be zero whereas the sender's ROC would be one, while their
  > sequence numbers would be so close that the ROC-guessing algorithm
  > could not detect this fact.
  >
  > There is a simple solution to this problem: the SRTP sender should
  > randomly select an initial sequence number that is always less than
  > 2^15. This ensures correct SRTP operation so long as fewer than 2^15
  > initial packets are lost in succession, which is within the maximum
  > tolerance of SRTP packet-index determination (see Appendix A and
  > page 14, first paragraph of RFC 3711). An SRTP receiver should
  > carefully implement the index-guessing algorithm. A naive
  > implementation can unintentionally guess the value of
  > 0xffffffffffffLL whenever the SEQ in the packet is greater than 2^15
  > and the locally stored SEQ and ROC are zero. (This can happen when
  > the implementation fails to treat those zero values as a special
  > case.)
  >
  > When ROC synchronization is lost, the receiver will not be able to
  > properly process the packets. If anti-replay protection is turned
  > on, then the desynchronization will appear as a burst of replay
  > check failures. Otherwise, if authentication is being checked, then
  > it will appear as a burst of authentication failures. Otherwise, if
  > encryption is being used, the desynchronization may not be detected
  > by the SRTP layer, and the packets may be improperly decrypted.

  However, modern libSRTP (as of 1.0.1[1]) now mentions the following in
  their README.md[2]:

  > The sequence number in the rtp packet is used as the low 16 bits of
  > the sender's local packet index. Note that RTP will start its
  > sequence number in a random place, and the SRTP layer just jumps
  > forward to that number at its first invocation. An earlier version
  > of this library used initial sequence numbers that are less than
  > 32,768; this trick is no longer required as the
  > rdbx_estimate_index(...) function has been made smarter.

  So truncating our initial sequence number to 15 bit is no longer
  necessary.

  1. https://github.com/cisco/libsrtp/blob/0eb007f0dc611f27cbfe0bf9855ed85182496cec/CHANGES#L271-L289
  2. https://github.com/cisco/libsrtp/blob/2de20dd9e9c8afbaf02fcf5d4048ce1ec9ddc0ae/README.md#implementation-notes


#### core_unreal.c: Fix memory leak in ast_unreal_new_channels()
  Author: George Joseph
  Date:   2024-10-15

  When the channel tech is multistream capable, the reference to
  chan_topology was passed to the new channel.  When the channel tech
  isn't multistream capable, the reference to chan_topology was never
  released.  "Local" channels are multistream capable so it didn't
  affect them but the confbridge "CBAnn" and the bridge_media
  "Recorder" channels are not so they caused a leak every time one
  of them was created.

  Also added tracing to ast_stream_topology_alloc() and
  stream_topology_destroy() to assist with debugging.

  Resolves: #938

#### dnsmgr.c: dnsmgr_refresh() incorrectly flags change with DNS round-robin
  Author: Allan Nathanson
  Date:   2024-09-29

  The dnsmgr_refresh() function checks to see if the IP address associated
  with a name/service has changed. The gotcha is that the ast_get_ip_or_srv()
  function only returns the first IP address returned by the DNS query. If
  there are multiple IPs associated with the name and the returned order is
  not consistent (e.g. with DNS round-robin) then the other IP addresses are
  not included in the comparison and the entry is flagged as changed even
  though the IP is still valid.

  Updated the code to check all IP addresses and flag a change only if the
  original IP is no longer valid.

  Resolves: #924

#### geolocation.sample.conf: Fix comment marker at end of file
  Author: George Joseph
  Date:   2024-10-08

  Resolves: #937

#### func_base64.c: Ensure we set aside enough room for base64 encoded data.
  Author: Sean Bright
  Date:   2024-10-08

  Reported by SingularTricycle on IRC.

  Fixes #940


#### app_dial: Fix progress timeout.
  Author: Naveen Albert
  Date:   2024-10-03

  Under some circumstances, the progress timeout feature added in commit
  320c98eec87c473bfa814f76188a37603ea65ddd does not work as expected,
  such as if there is no media flowing. Adjust the waitfor call to
  explicitly use the progress timeout if it would be reached sooner than
  the answer timeout to ensure we handle the timers properly.

  Resolves: #821

#### chan_dahdi: Never send MWI while off-hook.
  Author: Naveen Albert
  Date:   2024-10-01

  In some circumstances, it is possible for the do_monitor thread to
  erroneously think that a line is on-hook and send an MWI FSK spill
  to it when the line is really off-hook and no MWI should be sent.
  Commit 0a8b3d34673277b70be6b0e8ac50191b1f3c72c6 previously fixed this
  issue in a more readily encountered scenario, but it has still been
  possible for MWI to be sent when it shouldn't be. To robustly fix
  this issue, query DAHDI for the hook status to ensure we don't send
  MWI on a line that is actually still off hook.

  Resolves: #928

#### manager.c: Add unit test for Originate app and appdata permissions
  Author: George Joseph
  Date:   2024-10-03

  This unit test checks that dialplan apps and app data specified
  as parameters for the Originate action are allowed with the
  permissions the user has.


#### alembic: Drop redundant voicemail_messages index.
  Author: Sean Bright
  Date:   2024-09-26

  The `voicemail_messages_dir` index is a left prefix of the table's
  primary key and therefore unnecessary.


#### res_agi.c: Ensure SIGCHLD handler functions are properly balanced.
  Author: Sean Bright
  Date:   2024-09-30

  Calls to `ast_replace_sigchld()` and `ast_unreplace_sigchld()` must be
  balanced to ensure that we can capture the exit status of child
  processes when we need to. This extends to functions that call
  `ast_replace_sigchld()` and `ast_unreplace_sigchld()` such as
  `ast_safe_fork()` and `ast_safe_fork_cleanup()`.

  The primary change here is ensuring that we do not call
  `ast_safe_fork_cleanup()` in `res_agi.c` if we have not previously
  called `ast_safe_fork()`.

  Additionally we reinforce some of the documentation and add an
  assertion to, ideally, catch this sooner were this to happen again.

  Fixes #922


#### main, res, tests: Fix compilation errors on FreeBSD.
  Author: Naveen Albert
  Date:   2024-09-29

  asterisk.c, manager.c: Increase buffer sizes to avoid truncation warnings.
  config.c: Include header file for WIFEXITED/WEXITSTATUS macros.
  res_timing_kqueue: Use more portable format specifier.
  test_crypto: Use non-linux limits.h header file.

  Resolves: #916

#### res_rtp_asterisk: Fix dtls timer issues causing FRACKs and SEGVs
  Author: George Joseph
  Date:   2024-09-16

  In dtls_srtp_handle_timeout(), when DTLSv1_get_timeout() returned
  success but with a timeout of 0, we were stopping the timer and
  decrementing the refcount on instance but not resetting the
  timeout_timer to -1.  When dtls_srtp_stop_timeout_timer()
  was later called, it was atempting to stop a stale timer and could
  decrement the refcount on instance again which would then cause
  the instance destructor to run early.  This would result in either
  a FRACK or a SEGV when ast_rtp_stop(0 was called.

  According to the OpenSSL docs, we shouldn't have been stopping the
  timer when DTLSv1_get_timeout() returned success and the new timeout
  was 0 anyway.  We should have been calling DTLSv1_handle_timeout()
  again immediately so we now reschedule the timer callback for
  1ms (almost immediately).

  Additionally, instead of scheduling the timer callback at a fixed
  interval returned by the initial call to DTLSv1_get_timeout()
  (usually 999 ms), we now reschedule the next callback based on
  the last call to DTLSv1_get_timeout().

  Resolves: #487

#### manager.c: Restrict ModuleLoad to the configured modules directory.
  Author: Ben Ford
  Date:   2024-09-25

  When using the ModuleLoad AMI action, it was possible to traverse
  upwards through the directories to files outside of the configured
  modules directory. We decided it would be best to restrict access to
  modules exclusively in the configured directory. You will now get an
  error when the specified module is outside of this limitation.

  Fixes: #897

  UserNote: The ModuleLoad AMI action now restricts modules to the
  configured modules directory.


#### res_agi.c: Prevent possible double free during `SPEECH RECOGNIZE`
  Author: jiangxc
  Date:   2024-07-17

  When using the speech recognition module, crashes can occur
  sporadically due to a "double free or corruption (out)" error. Now, in
  the section where the audio stream is being captured in a loop, each
  time after releasing fr, it is set to NULL to prevent repeated
  deallocation.

  Fixes #772


#### cdr_custom: Allow absolute filenames.
  Author: Sean Bright
  Date:   2024-09-26

  A follow up to #893 that brings the same functionality to
  cdr_custom. Also update the sample configuration files to note support
  for absolute paths.


#### astfd.c: Avoid calling fclose with NULL argument.
  Author: Naveen Albert
  Date:   2024-09-24

  Don't pass through a NULL argument to fclose, which is undefined
  behavior, and instead return -1 and set errno appropriately. This
  also avoids a compiler warning with glibc 2.38 and newer, as glibc
  commit 71d9e0fe766a3c22a730995b9d024960970670af
  added the nonnull attribute to this argument.

  Resolves: #900

#### channel: Preserve CHANNEL(userfield) on masquerade.
  Author: Peter Jannesen
  Date:   2024-09-20

  In certain circumstances a channel may undergo an operation
  referred to as a masquerade. If this occurs the CHANNEL(userfield)
  value was not preserved causing it to get lost. This change makes
  it so that this field is now preserved.

  Fixes: #882

#### cel_custom: Allow absolute filenames.
  Author: Peter Jannesen
  Date:   2024-09-20

  If a filename starts with a '/' in cel_custom [mappings] assume it is
  a absolute file path and not relative filename/path to
  AST_LOG_DIR/cel_custom/


#### app_voicemail: Fix ill-formatted pager emails with custom subject.
  Author: Naveen Albert
  Date:   2024-09-24

  Add missing end-of-headers newline to pager emails with custom
  subjects, since this was missing from this code path.

  Resolves: #902

#### res_pjsip_pubsub: Persist subscription 'generator_data' in sorcery
  Author: Sean Bright
  Date:   2024-09-23

  Fixes #895


#### Fix application references to Background
  Author: George Joseph
  Date:   2024-09-20

  The app is actually named "BackGround" but several references
  in XML documentation were spelled "Background" with the lower
  case "g".  This was causing documentation links to return
  "not found" messages.


#### manager.conf.sample: Fix mathcing typo
  Author: George Joseph
  Date:   2024-09-24


#### manager: Enhance event filtering for performance
  Author: George Joseph
  Date:   2024-07-31

  UserNote: You can now perform more granular filtering on events
  in manager.conf using expressions like
  `eventfilter(name(Newchannel),header(Channel),method(starts_with)) = PJSIP/`
  This is much more efficient than
  `eventfilter = Event: Newchannel.*Channel: PJSIP/`
  Full syntax guide is in configs/samples/manager.conf.sample.


#### manager.c: Split XML documentation to manager_doc.xml
  Author: George Joseph
  Date:   2024-08-01


#### db.c: Remove limit on family/key length
  Author: George Joseph
  Date:   2024-09-11

  Consumers like media_cache have been running into issues with
  the previous astdb "/family/key" limit of 253 bytes when needing
  to store things like long URIs.  An Amazon S3 URI is a good example
  of this.  Now, instead of using a static 256 byte buffer for
  "/family/key", we use ast_asprintf() to dynamically create it.

  Both test_db.c and test_media_cache.c were also updated to use
  keys/URIs over the old 253 character limit.

  Resolves: #881

  UserNote: The `ast_db_*()` APIs have had the 253 byte limit on
  "/family/key" removed and will now accept families and keys with a
  total length of up to SQLITE_MAX_LENGTH (currently 1e9!).  This
  affects the `DB*` dialplan applications, dialplan functions,
  manager actions and `databse` CLI commands.  Since the
  media_cache also uses the `ast_db_*()` APIs, you can now store
  resources with URIs longer than 253 bytes.


#### stir_shaken: Fix propagation of attest_level and a few other values
  Author: George Joseph
  Date:   2024-09-24

  attest_level, send_mky and check_tn_cert_public_url weren't
  propagating correctly from the attestation object to the profile
  and tn.

  * In the case of attest_level, the enum needed to be changed
  so the "0" value (the default) was "NOT_SET" instead of "A".  This
  now allows the merging of the attestation object, profile and tn
  to detect when a value isn't set and use the higher level value.

  * For send_mky and check_tn_cert_public_url, the tn default was
  forced to "NO" which always overrode the profile and attestation
  objects.  Their defaults are now "NOT_SET" so the propagation
  happens correctly.

  * Just to remove some redundant code in tn_config.c, a bunch of calls to
  generate_sorcery_enum_from_str() and generate_sorcery_enum_to_str() were
  replaced with a single call to generate_acfg_common_sorcery_handlers().

  Resolves: #904

#### res_stir_shaken: Remove stale include for jansson.h in verification.c
  Author: George Joseph
  Date:   2024-09-17

  verification.c had an include for jansson.h left over from previous
  versions of the module.  Since res_stir_shaken no longer has a
  dependency on jansson, the bundled version wasn't added to GCC's
  include path so if you didn't also have a jansson development package
  installed, the compile would fail.  Removing the stale include
  was the only thing needed.

  Resolves: #889

#### res_stir_shaken.c: Fix crash when stir_shaken.conf is invalid
  Author: George Joseph
  Date:   2024-09-13

  * If the call to ast_config_load() returns CONFIG_STATUS_FILEINVALID,
  check_for_old_config() now returns LOAD_DECLINE instead of continuing
  on with a bad pointer.

  * If CONFIG_STATUS_FILEMISSING is returned, check_for_old_config()
  assumes the config is being loaded from realtime and now returns
  LOAD_SUCCESS.  If it's actually not being loaded from realtime,
  sorcery will catch that later on.

  * Also refactored the error handling in load_module() a bit.

  Resolves: #884

#### res_stir_shaken: Check for disabled before param validation
  Author: George Joseph
  Date:   2024-09-11

  For both attestation and verification, we now check whether they've
  been disabled either globally or by the profile before validating
  things like callerid, orig_tn, dest_tn, etc.  This prevents useless
  error messages.

  Resolves: #879

#### app_chanspy.c: resolving the issue writing frame to whisper audiohook.
  Author: Tinet-mucw
  Date:   2024-09-10

  ChanSpy(${channel}, qEoSw): because flags set o, ast_audiohook_set_frame_feed_direction(audiohook, AST_AUDIOHOOK_DIRECTION_READ); this will effect whisper audiohook and spy audiohook, this makes writing frame to whisper audiohook impossible. So add function start_whispering to starting whisper audiohook.

  Resolves: #876

#### autoservice: Do not sleep if autoservice_stop is called within autoservice thread
  Author: Alexei Gradinari
  Date:   2024-09-04

  It's possible that ast_autoservice_stop is called within the autoservice thread.
  In this case the autoservice thread is stuck in an endless sleep.

  To avoid endless sleep ast_autoservice_stop must check that it's not called
  within the autoservice thread.

  Fixes: #763

#### res_resolver_unbound: Test for NULL ub_result in unbound_resolver_callback
  Author: George Joseph
  Date:   2024-08-12

  The ub_result pointer passed to unbound_resolver_callback by
  libunbound can be NULL if the query was for something malformed
  like `.1` or `[.1]`.  If it is, we now set a 'ns_r_formerr' result
  and return instead of crashing with a SEGV.  This causes pjproject
  to simply cancel the transaction with a "No answer record in the DNS
  response" error.  The existing "off nominal" unit test was also
  updated to check this condition.

  Although not necessary for this fix, we also made
  ast_dns_resolver_completed() tolerant of a NULL result.

  Resolves: GHSA-v428-g3cw-7hv9

#### app_voicemail: Use ast_asprintf to create mailbox SQL query
  Author: George Joseph
  Date:   2024-09-03

  ...instead of trying to calculate the length of the buffer needed
  manually.


#### res_pjsip_sdp_rtp: Use negotiated DTMF Payload types on bitrate mismatch
  Author: Mike Bradeen
  Date:   2024-08-21

  When Asterisk sends an offer to Bob that includes 48K and 8K codecs with
  matching 4733 offers, Bob may want to use the 48K audio codec but can not
  accept 48K digits and so negotiates for a mixed set.

  Asterisk will now check Bob's offer to make sure Bob has indicated this is
  acceptible and if not, will use Bob's preference.

  Fixes: #847

#### app_chanspy.c: resolving the issue with audiohook direction read
  Author: Tinet-mucw
  Date:   2024-08-30

  ChanSpy(${channel}, qEoS): When chanspy spy the direction read, reading frame is often failed when reading direction read audiohook. because chanspy only read audiohook direction read; write_factory_ms will greater than 100ms soon, then ast_slinfactory_flush will being called, then direction read will fail.

  Resolves: #861

#### security_agreements.c: Refactor the to_str functions and fix a few other bugs
  Author: George Joseph
  Date:   2024-08-17

  * A static array of security mechanism type names was created.

  * ast_sip_str_to_security_mechanism_type() was refactored to do
    a lookup in the new array instead of using fixed "if/else if"
    statments.

  * security_mechanism_to_str() and ast_sip_security_mechanisms_to_str()
    were refactored to use ast_str instead of a fixed length buffer
    to store the result.

  * ast_sip_security_mechanism_type_to_str was removed in favor of
    just referencing the new type name array.  Despite starting with
    "ast_sip_", it was a static function so removing it doesn't affect
    ABI.

  * Speaking of "ast_sip_", several other static functions that
    started with "ast_sip_" were renamed to avoid confusion about
    their public availability.

  * A few VECTOR free loops were replaced with AST_VECTOR_RESET().

  * Fixed a meomry leak in pjsip_configuration.c endpoint_destructor
    caused by not calling ast_sip_security_mechanisms_vector_destroy().

  * Fixed a memory leak in res_pjsip_outbound_registration.c
    add_security_headers() caused by not specifying OBJ_NODATA in
    an ao2_callback.

  * Fixed a few ao2_callback return code misuses.

  Resolves: #845

#### res_pjsip_sdp_rtp fix leaking astobj2 ast_format
  Author: Alexei Gradinari
  Date:   2024-08-23

  PR #700 added a preferred_format for the struct ast_rtp_codecs,
  but when set the preferred_format it leaks an astobj2 ast_format.
  In the next code
  ast_rtp_codecs_set_preferred_format(&codecs, ast_format_cap_get_format(joint, 0));
  both functions ast_rtp_codecs_set_preferred_format
  and ast_format_cap_get_format increases the ao2 reference count.

  Fixes: #856

#### stir_shaken.conf.sample: Fix bad references to private_key_path
  Author: George Joseph
  Date:   2024-08-22

  They should be private_key_file.

  Resolves: #854

#### res_pjsip_logger.c: Fix 'OPTIONS' tab completion.
  Author: Sean Bright
  Date:   2024-08-19

  Fixes #843


#### alembic: Make 'revises' header comment match reality.
  Author: Sean Bright
  Date:   2024-08-17


#### Update version for Asterisk 22
  Author: Mike Bradeen
  Date:   2024-08-14


#### chan_mobile: decrease CHANNEL_FRAME_SIZE to prevent delay
  Author: Cade Parker
  Date:   2024-08-07

  On modern Bluetooth devices or lower-powered asterisk servers, decreasing the channel frame size significantly improves latency and delay on outbound calls with only a mild sacrifice to the quality of the call (the frame size before was massive overkill to begin with)
#### res_pjsip_notify: add dialplan application
  Author: Mike Bradeen
  Date:   2024-07-09

  Add dialplan application PJSIPNOTIFY to send either pre-configured
  NOTIFY messages from pjsip_notify.conf or with headers defined in
  dialplan.

  Also adds the ability to send pre-configured NOTIFY commands to a
  channel via the CLI.

  Resolves: #799

  UserNote: A new dialplan application PJSIPNotify is now available
  which can send SIP NOTIFY requests from the dialplan.

  The pjsip send notify CLI command has also been enhanced to allow
  sending NOTIFY messages to a specific channel. Syntax:

  pjsip send notify <option> channel <channel>

#### manager.c: Fix FRACK when doing CoreShowChannelMap in DEVMODE
  Author: George Joseph
  Date:   2024-08-08

  If you run an AMI CoreShowChannelMap on a channel that isn't in a
  bridge and you're in DEVMODE, you can get a FRACK because the
  bridge id is empty.  We now simply return an empty list for that
  request.

#### channel: Add multi-tenant identifier.
  Author: Ben Ford
  Date:   2024-05-21

  This patch introduces a new identifier for channels: tenantid. It's
  a stringfield on the channel that can be used for general purposes. It
  will be inherited by other channels the same way that linkedid is.

  You can set tenantid in a few ways. The first is to set it in the
  dialplan with the Set and CHANNEL functions:

  exten => example,1,Set(CHANNEL(tenantid)=My tenant ID)

  It can also be accessed via CHANNEL:

  exten => example,2,NoOp(CHANNEL(tenantid))

  Another method is to use the new tenantid option for pjsip endpoints in
  pjsip.conf:

  [my_endpoint]
  type=endpoint
  tenantid=My tenant ID

  This is considered the best approach since you will be able to see the
  tenant ID as early as the Newchannel event.

  It can also be set using set_var in pjsip.conf on the endpoint like
  setting other channel variable:

  set_var=CHANNEL(tenantid)=My tenant ID

  Note that set_var will not show tenant ID on the Newchannel event,
  however.

  Tenant ID has also been added to CDR. It's read-only and can be accessed
  via CDR(tenantid). You can also get the tenant ID of the last channel
  communicated with via CDR(peertenantid).

  Tenant ID will also show up in CEL records if it has been set, and the
  version number has been bumped accordingly.

  Fixes: #740

  UserNote: tenantid has been added to channels. It can be read in
  dialplan via CHANNEL(tenantid), and it can be set using
  Set(CHANNEL(tenantid)=My tenant ID). In pjsip.conf, it is recommended to
  use the new tenantid option for pjsip endpoints (e.g., tenantid=My
  tenant ID) so that it will show up in Newchannel events. You can set it
  like any other channel variable using set_var in pjsip.conf as well, but
  note that this will NOT show up in Newchannel events. Tenant ID is also
  available in CDR and can be accessed with CDR(tenantid). The peer tenant
  ID can also be accessed with CDR(peertenantid). CEL includes tenant ID
  as well if it has been set.

  UpgradeNote: A new versioned struct (ast_channel_initializers) has been
  added that gets passed to __ast_channel_alloc_ap. The new function
  ast_channel_alloc_with_initializers should be used when creating
  channels that require the use of this struct. Currently the only value
  in the struct is for tenantid, but now more fields can be added to the
  struct as necessary rather than the __ast_channel_alloc_ap function. A
  new option (tenantid) has been added to endpoints in pjsip.conf as well.
  CEL has had its version bumped to include tenant ID.

#### configure:  Use . file rather than source file.
  Author: Jaco Kroon
  Date:   2024-08-05

  source is a bash concept, so when /bin/sh points to another shell the
  existing construct won't work.

  Reference: https://bugs.gentoo.org/927055
  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### feat: ARI "ChannelToneDetected" event
  Author: gibbz00
  Date:   2024-07-18

  A stasis event is now produced when using the TONE_DETECT dialplan
  function. This event is published over ARI using the ChannelToneDetected
  event. This change does not make it available over AMI.

  Fixes: #811

  UserNote: Setting the TONE_DETECT dialplan function on a channel
  in ARI will now cause a ChannelToneDetected ARI event to be raised
  when the specified tone is detected.

#### manager.c: Add entries to Originate blacklist
  Author: George Joseph
  Date:   2024-07-22

  Added Reload and DBdeltree to the list of dialplan application that
  can't be executed via the Originate manager action without also
  having write SYSTEM permissions.

  Added CURL, DB*, FILE, ODBC and REALTIME* to the list of dialplan
  functions that can't be executed via the Originate manager action
  without also having write SYSTEM permissions.

  If the Queue application is attempted to be run by the Originate
  manager action and an AGI parameter is specified in the app data,
  it'll be rejected unless the manager user has either the AGI or
  SYSTEM permissions.

  Resolves: #GHSA-c4cg-9275-6w44

#### res_stasis: fix intermittent delays on adding channel to bridge
  Author: Mike Bradeen
  Date:   2024-07-10

  Previously, on command execution, the control thread was awoken by
  sending a SIGURG. It was found that this still resulted in some
  instances where the thread was not immediately awoken.

  This change instead sends a null frame to awaken the control thread,
  which awakens the thread more consistently.

  Resolves: #801

#### res_pjsip_sdp_rtp.c: Fix DTMF Handling in Re-INVITE with dtmf_mode set to auto
  Author: Tinet-mucw
  Date:   2024-08-02

  When the endpoint dtmf_mode is set to auto, a SIP request is sent to the UAC, and the SIP SDP from the UAC does not include the telephone-event. Later, the UAC sends an INVITE, and the SIP SDP includes the telephone-event. In this case, DTMF should be sent by RFC2833 rather than using inband signaling.

  Resolves: asterisk#826

#### rtp_engine.c: Prevent segfault in ast_rtp_codecs_payloads_unset()
  Author: George Joseph
  Date:   2024-07-25

  There can be empty slots in payload_mapping_tx corresponding to
  dynamic payload types that haven't been seen before so we now
  check for NULL before attempting to use 'type' in the call to
  ast_format_cmp.

  Note: Currently only chan_sip calls ast_rtp_codecs_payloads_unset()

  Resolves: #822

#### stir_shaken: CRL fixes and a new CLI command
  Author: George Joseph
  Date:   2024-07-19

  * Fixed a bug in crypto_show_cli_store that was causing asterisk
  to crash if there were certificate revocation lists in the
  verification certificate store.  We're also now prefixing
  certificates with "Cert:" and CRLs with "CRL:" to distinguish them
  in the list.

  * Added 'untrusted_cert_file' and 'untrusted_cert_path' options
  to both verification and profile objects.  If you have CRLs that
  are signed by a different CA than the incoming X5U certificate
  (indirect CRL), you'll need to provide the certificate of the
  CRL signer here.  Thse will show up as 'Untrusted" when showing
  the verification or profile objects.

  * Fixed loading of crl_path.  The OpenSSL API we were using to
  load CRLs won't actually load them from a directory, only a file.
  We now scan the directory ourselves and load the files one-by-one.

  * Fixed the verification flags being set on the certificate store.
    - Removed the CRL_CHECK_ALL flag as this was causing all certificates
      to be checked for CRL extensions and failing to verify the cert if
      there was none.  This basically caused all certs to fail when a CRL
      was provided via crl_file or crl_path.
    - Added the EXTENDED_CRL_SUPPORT flag as it is required to handle
      indirect CRLs.

  * Added a new CLI command...
  `stir_shaken verify certificate_file <certificate_file> [ <profile> ]`
  which will assist troubleshooting certificate problems by allowing
  the user to manually verify a certificate file against either the
  global verification certificate store or the store for a specific
  profile.

  * Updated the XML documentation and the sample config file.

  Resolves: #809

#### res_pjsip_config_wizard.c: Refactor load process
  Author: George Joseph
  Date:   2024-07-23

  The way we have been initializing the config wizard prevented it
  from registering its objects if res_pjsip happened to load
  before it.

  * We now use the object_type_registered sorcery observer to kick
  things off instead of the wizard_mapped observer.

  * The load_module function now checks if res_pjsip has been loaded
  already and if it was it fires the proper observers so the objects
  load correctly.

  Resolves: #816

  UserNote: The res_pjsip_config_wizard.so module can now be reloaded.

#### voicemail.conf.sample: Fix ':' comment typo
  Author: George Joseph
  Date:   2024-07-24

  ...and removed an errant trailing space.

  Resolves: #819

#### bridge_softmix: Fix queueing VIDUPDATE control frames
  Author: George Joseph
  Date:   2024-07-17

  softmix_bridge_write_control() now calls ast_bridge_queue_everyone_else()
  with the bridge_channel so the VIDUPDATE control frame isn't echoed back.

  softmix_bridge_write_control() was setting bridge_channel to NULL
  when calling ast_bridge_queue_everyone_else() for VIDUPDATE control
  frames.  This was causing the frame to be echoed back to the
  channel it came from.  In certain cases, like when two channels or
  bridges are being recorded, this can cause a ping-pong effect that
  floods the system with VIDUPDATE control frames.

  Resolves: #780

#### res_pjsip_path.c: Fix path when dialing using PJSIP_DIAL_CONTACTS()
  Author: Igor Goncharovsky
  Date:   2024-05-12

  When using the PJSIP_DIAL_CONTACTS() function for use in the Dial()
  command, the contacts are returned in text form, so the input to
  the path_outgoing_request() function is a contact value of NULL.
  The issue was reported in ASTERISK-28211, but was not actually fixed
  in ASTERISK-30100. This fix brings back the code that was previously
  removed and adds code to search for a contact to extract the path
  value from it.

#### res_pjsip_sdp_rtp: Add support for default/mismatched 8K RFC 4733/2833 digits
  Author: Mike Bradeen
  Date:   2024-06-21

  After change made in 624f509 to add support for non 8K RFC 4733/2833 digits,
  Asterisk would only accept RFC 4733/2833 offers that matched the sample rate of
  the negotiated codec(s).

  This change allows Asterisk to accept 8K RFC 4733/2833 offers if the UAC
  offfers 8K RFC 4733/2833 but negotiates for a non 8K bitrate codec.

  A number of corresponding tests in tests/channels/pjsip/dtmf_sdp also needed to
  be re-written to allow for these scenarios.

  Fixes: #776

#### ast-db-manage: Remove duplicate enum creation
  Author: George Joseph
  Date:   2024-07-08

  Remove duplicate creation of ast_bool_values from
  2b7c507d7d12_add_queue_log_option_log_restricted_.py.  This was
  causing alembic upgrades to fail since the enum was already created
  in fe6592859b85_fix_mwi_subscribe_replaces_.py back in 2018.

  Resolves: #797

#### security_agreement.c: Always add the Require and Proxy-Require headers
  Author: George Joseph
  Date:   2024-07-03

  The `Require: mediasec` and `Proxy-Require: mediasec` headers need
  to be sent whenever we send `Security-Client` or `Security-Verify`
  headers but the logic to do that was only in add_security_headers()
  in res_pjsip_outbound_register.  So while we were sending them on
  REGISTER requests, we weren't sending them on INVITE requests.

  This commit moves the logic to send the two headers out of
  res_pjsip_outbound_register:add_security_headers() and into
  security_agreement:ast_sip_add_security_headers().  This way
  they're always sent when we send `Security-Client` or
  `Security-Verify`.

  Resolves: #789

#### logger.h: Include SCOPE_CALL_WITH_INT_RESULT() in non-dev-mode builds.
  Author: Sean Bright
  Date:   2024-06-29

  Fixes #785

#### stasis_channels: Use uniqueid and name to delete old snapshots
  Author: George Joseph
  Date:   2024-05-08

  Whenver a new channel snapshot is created or when a channel is
  destroyed, we need to delete any existing channel snapshot from
  the snapshot cache.  Historically, we used the channel->snapshot
  pointer to delete any existing snapshots but this has two issues.

  First, if something (possibly ast_channel_internal_swap_snapshots)
  sets channel->snapshot to NULL while there's still a snapshot in
  the cache, we wouldn't be able to delete it and it would be orphaned
  when the channel is destroyed.  Since we use the cache to list
  channels from the CLI, AMI and ARI, it would appear as though the
  channel was still there when it wasn't.

  Second, since there are actually two caches, one indexed by the
  channel's uniqueid, and another indexed by the channel's name,
  deleting from the caches by pointer requires a sequential search of
  all of the hash table buckets in BOTH caches to find the matching
  snapshots.  Not very efficient.

  So, we now delete from the caches using the channel's uniqueid
  and name.  This solves both issues.

  This doesn't address how channel->snapshot might have been set
  to NULL in the first place because although we have concrete
  evidence that it's happening, we haven't been able to reproduce it.

  Resolves: #783

#### app_voicemail_odbc: Allow audio to be kept on disk
  Author: George Joseph
  Date:   2024-04-09

  This commit adds a new voicemail.conf option 'odbc_audio_on_disk'
  which when set causes the ODBC variant of app_voicemail to leave
  the message and greeting audio files on disk and only store the
  message metadata in the database.  This option came from a concern
  that the database could grow to large and cause remote access
  and/or replication to become slow.  In a clustering situation
  with this option, all asterisk instances would share the same
  database for the metadata and either use a shared filesystem
  or other filesystem replication service much more suitable
  for synchronizing files.

  The changes to app_voicemail to implement this feature were actually
  quite small but due to the complexity of the module, the actual
  source code changes were greater.  They fall into the following
  categories:

  * Tracing.  The module is so complex that it was impossible to
  figure out the path taken for various scenarios without the addition
  of many SCOPE_ENTER, SCOPE_EXIT and ast_trace statements, even in
  code that's not related to the functional change.  Making this worse
  was the fact that many "if" statements in this module didn't use
  braces.  Since the tracing macros add multiple statements, many "if"
  statements had to be converted to use braces.

  * Excessive use of PATH_MAX.  Previous maintainers of this module
  used PATH_MAX to allocate character arrays for filesystem paths
  and SQL statements as though they cost nothing.  In fact, PATH_MAX
  is defined as 4096 bytes!  Some functions had (and still have)
  multiples of these.  One function has 7.  Given that the vast
  majority of installations use the default spool directory path
  `/var/spool/asterisk/voicemail`, the actual path length is usually
  less than 80 bytes.  That's over 4000 bytes wasted.  It was the
  same for SQL statement buffers.  A 4K buffer for statement that
  only needed 60 bytes.  All of these PATH_MAX allocations in the
  ODBC related code were changed to dynamically allocated buffers.
  The rest will have to be addressed separately.

  * Bug fixes.  During the development of this feature, several
  pre-existing ODBC related bugs were discovered and fixed.  They
  had to do with leaving orphaned files on disk, not preserving
  original message ids when moving messages between folders,
  not honoring the "formats" config parameter in certain circumstances,
  etc.

  UserNote: This commit adds a new voicemail.conf option
  'odbc_audio_on_disk' which when set causes the ODBC variant of
  app_voicemail_odbc to leave the message and greeting audio files
  on disk and only store the message metadata in the database.
  Much more information can be found in the voicemail.conf.sample
  file.

#### bridge_basic.c: Make sure that ast_bridge_channel is not destroyed while iterating over bridge->channels. From the gdb information, we can see that while iterating over bridge->channels, the ast_bridge_channel reference count is 0, indicating it has already been destroyed.Additionally, when ast_bridge_channel is removed from bridge->channels, the bridge is first locked. Therefore, locking the bridge before iterating over bridge->channels can resolve the race condition.
  Author: Tinet-mucw
  Date:   2024-06-13

  Resolves: https://github.com/asterisk/asterisk/issues/768

#### app_queue:  Add option to not log Restricted Caller ID to queue_log
  Author: Alexei Gradinari
  Date:   2024-06-12

  Add a queue option log-restricted-caller-id to strip the Caller ID when storing the ENTERQUEUE event
  in the queue log if the Caller ID is restricted.

  Resolves: #765

  UpgradeNote: Add a new column to the queues table:
  queue_log_option_log_restricted ENUM('0','1','off','on','false','true','no','yes')
  to control whether the Restricted Caller ID will be stored in the queue log.

  UserNote: Add a Queue option log-restricted-caller-id to control whether the Restricted Caller ID
  will be stored in the queue log.
  If log-restricted-caller-id=no then the Caller ID will be stripped if the Caller ID is restricted.

#### pbx.c: expand fields width of "core show hints"
  Author: Alexei Gradinari
  Date:   2024-06-13

  The current width for "extension" is 20 and "device state id" is 20, which is too small.
  The "extension" field contains "ext"@"context", so 20 characters is not enough.
  The "device state id" field, for example for Queue pause state contains Queue:"queue_name"_pause_PSJIP/"endpoint", so the 20 characters is not enough.

  Increase the width of "extension" field to 30 characters and the width of the "device state id" field to 60 characters.

  Resolves: #770

  UserNote: The fields width of "core show hints" were increased.
  The width of "extension" field to 30 characters and
  the width of the "device state id" field to 60 characters.

#### pjsip: Add PJSIP_PARSE_URI_FROM dialplan function.
  Author: Sean Bright
  Date:   2024-06-02

  Various SIP headers permit a URI to be prefaced with a `display-name`
  production that can include characters (like commas and parentheses)
  that are problematic for Asterisk's dialplan parser and, specifically
  in the case of this patch, the PJSIP_PARSE_URI function.

  This patch introduces a new function - `PJSIP_PARSE_URI_FROM` - that
  behaves identically to `PJSIP_PARSE_URI` except that the first
  argument is now a variable name and not a literal URI.

  Fixes #756

#### manager.c: Properly terminate `CoreShowChannelMap` event.
  Author: Sean Bright
  Date:   2024-06-10

  Fixes #761

#### cli: Show configured cache dir
  Author: Bastian Triller
  Date:   2024-06-07

  Since Asterisk 19 it is possible to cache recorded files into another
  directory [1] [2].
  Show configured location of cache dir in CLI's core show settings.

  [1] ASTERISK-29143
  [2] b08427134fd51bb549f198e9f60685f2680c68d7

#### xml.c: Update deprecated libxml2 API usage.
  Author: Sean Bright
  Date:   2024-05-23

  Two functions are deprecated as of libxml2 2.12:

    * xmlSubstituteEntitiesDefault
    * xmlParseMemory

  So we update those with supported API.

  Additionally, `res_calendar_caldav` has been updated to use libxml2's
  xmlreader API instead of the SAX2 API which has always felt a little
  hacky (see deleted comment block in `res_calendar_caldav.c`).

  The xmlreader API has been around since libxml2 2.5.0 which was
  released in 2003.

  Fixes #725

#### cdr_pgsql: Fix crash when the module fails to load multiple times.
  Author: chrsmj
  Date:   2024-05-16

  Missing or corrupt cdr_pgsql.conf configuration file can cause the
  second attempt to load the PostgreSQL CDR module to crash Asterisk via
  the Command Line Interface because a null CLI command is registered on
  the first failed attempt to load the module.

  Resolves: #736

#### asterisk.c: Don't log an error if .asterisk_history does not exist.
  Author: Sean Bright
  Date:   2024-05-27

  Fixes #751

#### chan_ooh323: Fix R/0 typo in docs
  Author: Walter Doekes
  Date:   2024-05-27


#### bundled_pjproject: Disable UPnP support.
  Author: Sean Bright
  Date:   2024-05-24

  Fixes #747

#### file.h: Rename function argument to avoid C++ keyword clash.
  Author: Sean Bright
  Date:   2024-05-24

  Fixes #744

#### rtp_engine: add support for multirate RFC2833 digits
  Author: Mike Bradeen
  Date:   2024-04-08

  Add RFC2833 DTMF support for 16K, 24K, and 32K bitrate codecs.

  Asterisk currently treats RFC2833 Digits as a single rtp payload type
  with a fixed bitrate of 8K.  This change would expand that to 8, 16,
  24 and 32K.

  This requires checking the offered rtp types for any of these bitrates
  and then adding an offer for each (if configured for RFC2833.)  DTMF
  generation must also be changed in order to look at the current outbound
  codec in order to generate appropriately timed rtp.

  For cases where no outgoing audio has yet been sent prior to digit
  generation, Asterisk now has a concept of a 'preferred' codec based on
  offer order.

  On inbound calls Asterisk will mimic the payload types of the RFC2833
  digits.

  On outbound calls Asterisk will choose the next free payload types starting
  with 101.

  UserNote: No change in configuration is required in order to enable this
  feature. Endpoints configured to use RFC2833 will automatically have this
  enabled. If the endpoint does not support this, it should not include it in
  the SDP offer/response.

  Resolves: #699

#### configs: Fix a misleading IPv6 ACL example in Named ACLs
  Author: Ivan Poddubny
  Date:   2024-05-05

  "deny=::" is equivalent to "::/128".
  In order to mean "deny everything by default" it must be "::/0".

#### asterisk.c: Fix sending incorrect messages to systemd notify
  Author: Ivan Poddubny
  Date:   2024-05-05

  Send "RELOADING=1" instead of "RELOAD=1" to follow the format
  expected by systemd (see sd_notify(3) man page).

  Do not send STOPPING=1 in remote console mode:
  attempting to execute "asterisk -rx" by the main process leads to
  a warning if NotifyAccess=main (the default) or to a forced termination
  if NotifyAccess=all.

#### res/stasis/control.c: include signal.h
  Author: Fabrice Fontaine
  Date:   2024-05-01

  Include signal.h to avoid the following build failure with uclibc-ng
  raised since
  https://github.com/asterisk/asterisk/commit/2694792e13c7f3ab1911c4a69fba0df32c544177:

  stasis/control.c: In function 'exec_command_on_condition':
  stasis/control.c:313:3: warning: implicit declaration of function 'pthread_kill'; did you mean 'pthread_yield'? [-Wimplicit-function-declaration]
    313 |   pthread_kill(control->control_thread, SIGURG);
        |   ^~~~~~~~~~~~
        |   pthread_yield
  stasis/control.c:313:41: error: 'SIGURG' undeclared (first use in this function)
    313 |   pthread_kill(control->control_thread, SIGURG);
        |                                         ^~~~~~

  cherry-pick-to: 18
  cherry-pick-to: 20
  cherry-pick-to: 21

  Fixes: #729

#### res_pjsip_logger: Preserve logging state on reloads.
  Author: Naveen Albert
  Date:   2023-08-09

  Currently, reloading res_pjsip will cause logging
  to be disabled. This is because logging can also
  be controlled via the debug option in pjsip.conf
  and this defaults to "no".

  To improve this, logging is no longer disabled on
  reloads if logging had not been previously
  enabled using the debug option from the config.
  This ensures that logging enabled from the CLI
  will persist through a reload.

  ASTERISK-29912 #close

  Resolves: #246

  UserNote: Issuing "pjsip reload" will no longer disable
  logging if it was previously enabled from the CLI.

#### logger: Add unique verbose prefixes for levels 5-10.
  Author: Naveen Albert
  Date:   2024-04-27

  Add unique verbose prefixes for levels higher than 4, so
  that these can be visually differentiated from each other.

  Resolves: #721

#### say.c: Fix cents off-by-one due to floating point rounding.
  Author: Naveen Albert
  Date:   2024-01-10

  Some of the money announcements can be off by one cent,
  due to the use of floating point in the money calculations,
  which is bad for obvious reasons.

  This replaces floating point with simple string parsing
  to ensure the cents value is converted accurately.

  Resolves: #525

#### loader.c: Allow dependent modules to be unloaded recursively.
  Author: Naveen Albert
  Date:   2023-12-02

  Because of the (often recursive) nature of module dependencies in
  Asterisk, hot swapping a module on the fly is cumbersome if a module
  is depended on by other modules. Currently, dependencies must be
  popped manually by unloading dependents, unloading the module of
  interest, and then loading modules again in reverse order.

  To make this easier, the ability to do this recursively in certain
  circumstances has been added, as an optional extension to the
  "module refresh" command. If requested, Asterisk will check if a module
  that has a positive usecount could be unloaded safely if anything
  recursively dependent on it were unloaded. If so, it will go ahead
  and unload all these modules and load them back again. This makes
  hot swapping modules that provide dependencies much easier.

  Resolves: #474

  UserNote: In certain circumstances, modules with dependency relations
  can have their dependents automatically recursively unloaded and loaded
  again using the "module refresh" CLI command or the ModuleLoad AMI command.

#### res_pjsip_sdp_rtp.c: Initial RTP inactivity check must consider the rtp_timeout setting.
  Author: Henrik Liljedahl
  Date:   2024-04-11

  First rtp activity check was performed after 500ms regardless of the rtp_timeout setting. Having a call in ringing state for more than rtp_timeout and the first rtp package is received more than 500ms after sdp negotiation and before the rtp_timeout, erronously caused the call to be hungup. Changed to perform the first rtp inactivity check after the timeout setting preventing calls to be disconnected before the rtp_timeout has elapsed since sdp negotiation.

  Fixes #710

#### tcptls/iostream:  Add support for setting SNI on client TLS connections
  Author: George Joseph
  Date:   2024-04-23

  If the hostname field of the ast_tcptls_session_args structure is
  set (which it is for websocket client connections), that hostname
  will now automatically be used in an SNI TLS extension in the client
  hello.

  Resolves: #713

  UserNote: Secure websocket client connections now send SNI in
  the TLS client hello.

#### stir_shaken:  Fix memory leak, typo in config, tn canonicalization
  Author: George Joseph
  Date:   2024-04-25

  * Fixed possible memory leak in tn_config:tn_get_etn() where we
  weren't releasing etn if tn or eprofile were null.
  * We now canonicalize TNs before using them for lookups or adding
  them to Identity headers.
  * Fixed a typo in stir_shaken.conf.sample.

  Resolves: #716

#### make_buildopts_h: Always include DETECT_DEADLOCKS
  Author: George Joseph
  Date:   2024-04-27

  Since DETECT_DEADLOCKS is now split from DEBUG_THREADS, it must
  always be included in buildopts.h instead of only when
  ADD_CFLAGS_TO_BUILDOPTS_H is defined.  A SEGV will result otherwise.

  Resolves: #719

#### sorcery.c: Fixed crash error when executing "module reload"
  Author: Spiridonov Dmitry
  Date:   2024-04-14

  Fixed crash error when cli "module reload". The error appears when
  compiling with res_prometheus and using the sorcery memory cache for
  registrations

#### callerid.c: Parse previously ignored Caller ID parameters.
  Author: Naveen Albert
  Date:   2024-04-01

  Commit f2f397c1a8cc48913434ebb297f0ff50d96993db previously
  made it possible to send Caller ID parameters to FXS stations
  which, prior to that, could not be sent.

  This change is complementary in that we now handle receiving
  all these parameters on FXO lines and provide these up to
  the dialplan, via chan_dahdi. In particular:

  * If a redirecting reason is provided, the channel's redirecting
    reason is set. No redirecting number is set, since there is
    no parameter for this in the Caller ID protocol, but the reason
    can be checked to determine if and why a call was forwarded.
  * If the Call Qualifier parameter is received, the Call Qualifier
    variable is set.
  * Some comments have been added to explain why some of the code
    is the way it is, to assist other people looking at it.

  With this change, Asterisk's Caller ID implementation is now
  reasonably complete for both FXS and FXO operation.

  Resolves: #681

#### logger.h:  Add SCOPE_CALL and SCOPE_CALL_WITH_RESULT
  Author: George Joseph
  Date:   2024-04-09

  If you're tracing a large function that may call another function
  multiple times in different circumstances, it can be difficult to
  see from the trace output exactly which location that function
  was called from.  There's no good way to automatically determine
  the calling location.  SCOPE_CALL and SCOPE_CALL_WITH_RESULT
  simply print out a trace line before and after the call.

  The difference between SCOPE_CALL and SCOPE_CALL_WITH_RESULT is
  that SCOPE_CALL ignores the function's return value (if any) where
  SCOPE_CALL_WITH_RESULT allows you to specify the type of the
  function's return value so it can be assigned to a variable.
  SCOPE_CALL_WITH_INT_RESULT is just a wrapper for SCOPE_CALL_WITH_RESULT
  and the "int" return type.

#### app_queue.c: Properly handle invalid strategies from realtime.
  Author: Sean Bright
  Date:   2024-04-13

  The existing code sets the queue strategy to `ringall` but it is then
  immediately overwritten with an invalid one.

  Fixes #707

#### file.c, channel.c: Don't emit warnings if progress received.
  Author: Naveen Albert
  Date:   2024-04-09

  Silently ignore AST_CONTROL_PROGRESS where appropriate,
  as most control frames already are.

  Resolves: #696

#### alembic: Correct NULLability of PJSIP id columns.
  Author: Sean Bright
  Date:   2024-04-06

  Fixes #695

#### rtp_engine and stun: call ast_register_atexit instead of ast_register_cleanup
  Author: George Joseph
  Date:   2024-04-02

  rtp_engine.c and stun.c were calling ast_register_cleanup which
  is skipped if any loadable module can't be cleanly unloaded
  when asterisk shuts down.  Since this will always be the case,
  their cleanup functions never get run.  In a practical sense
  this makes no difference since asterisk is shutting down but if
  you're in development mode and trying to use the leak sanitizer,
  the leaks from both of those modules clutter up the output.

#### manager.c: Add missing parameters to Login documentation
  Author: George Joseph
  Date:   2024-04-03

  * Added the AuthType and Key parameters for MD5 authentication.

  * Added the Events parameter.

  Resolves: #689

#### func_callerid: Emit warning if invalid redirecting reason set.
  Author: Naveen Albert
  Date:   2024-04-01

  Emit a warning if REDIRECTING(reason) is set to an invalid
  reason, consistent with what happens when
  REDIRECTING(orig-reason) is set to an invalid reason.

  Resolves: #683

#### chan_dahdi: Add DAHDIShowStatus AMI action.
  Author: Naveen Albert
  Date:   2024-03-29

  * Add an AMI action to correspond to the "dahdi show status"
    command, allowing span information to be retrieved via AMI.
  * Show span number and sig type in "dahdi show channels".

  Resolves: #673

#### res_stir_shaken:  Fix compilation for CentOS7 (openssl 1.0.2)
  Author: George Joseph
  Date:   2024-04-01

  * OpenSSL 1.0.2 doesn't support X509_get0_pubkey so we now use
    X509_get_pubkey.  The difference is that X509_get_pubkey requires
    the caller to free the EVP_PKEY themselves so we now let
    RAII_VAR do that.
  * OpenSSL 1.0.2 doesn't support upreffing an X509_STORE so we now
    wrap it in an ao2 object.
  * OpenSSL 1.0.2 doesn't support X509_STORE_get0_objects to get all
    the certs from an X509_STORE and there's no easy way to polyfill
    it so the CLI commands that list profiles will show a "not
    supported" message instead of listing the certs in a store.

  Resolves: #676

#### Fix incorrect application and function documentation references
  Author: George Joseph
  Date:   2024-04-01

  There were a few references in the embedded documentation XML
  where the case didn't match or where the referenced app or function
  simply didn't exist any more.  These were causing 404 responses
  in docs.asterisk.org.

#### cli.c: `core show channels concise` is not really deprecated.
  Author: Sean Bright
  Date:   2024-04-01

  Fixes #675

#### res_pjsip_endpoint_identifier_ip: Endpoint identifier request URI
  Author: Sperl Viktor
  Date:   2024-03-28

  Add ability to match against PJSIP request URI.

  UserNote: this new feature let users match endpoints based on the
  indound SIP requests' URI. To do so, add 'request_uri' to the
  endpoint's 'identify_by' option. The 'match_request_uri' option of
  the identify can be an exact match for the entire request uri, or a
  regular expression (between slashes). It's quite similar to the
  header identifer.

  Fixes: #599

#### Implement Configurable TCP Keepalive Settings in PJSIP Transports
  Author: Joshua Elson
  Date:   2024-03-18

  This commit introduces configurable TCP keepalive settings for both TCP and TLS transports. The changes allow for finer control over TCP connection keepalives, enhancing stability and reliability in environments prone to connection timeouts or where intermediate devices may prematurely close idle connections. This has proven necessary and has already been tested in production in several specialized environments where access to the underlying transport is unreliable in ways invisible to the operating system directly, so these keepalive and timeout mechanisms are necessary.

  Fixes #657

#### chan_dahdi: Don't retry opening nonexistent channels on restart.
  Author: Naveen Albert
  Date:   2024-03-26

  Commit 729cb1d390b136ccc696430aa5c68d60ea4028be added logic to retry
  opening DAHDI channels on "dahdi restart" if they failed initially,
  up to 1,000 times in a loop, to address cases where the channel was
  still in use. However, this retry loop does not use the actual error,
  which means chan_dahdi will also retry opening nonexistent channels
  1,000 times per channel, causing a flood of unnecessary warning logs
  for an operation that will never succeed, with tens or hundreds of
  thousands of open attempts being made.

  The original patch would have been more targeted if it only retried
  on the specific relevant error (likely EBUSY, although it's hard to
  say since the original issue is no longer available).

  To avoid the problem above while avoiding the possibility of breakage,
  this skips the retry logic if the error is ENXIO (No such device or
  address), since this will never succeed.

  Resolves: #669

#### res_pjsip_refer.c: Allow GET_TRANSFERRER_DATA
  Author: Martin Tomec
  Date:   2024-02-06

  There was functionality in chan_sip to get REFER headers, with GET_TRANSFERRER_DATA variable. This commit implements the same functionality in pjsip, to ease transfer from chan_sip to pjsip.

  Fixes: #579

  UserNote: the GET_TRANSFERRER_DATA dialplan variable can now be used also in pjsip.
#### res_ari.c: Add additional output to ARI requests when debug is enabled
  Author: Martin Nystroem
  Date:   2024-03-22

  When ARI debug is enabled the logs will now output http method and the uri.

  Fixes: #666

#### alembic: Fix compatibility with SQLAlchemy 2.0+.
  Author: Sean Bright
  Date:   2024-03-20

  SQLAlchemy 2.0 changed the way that commits/rollbacks are handled
  causing the final `UPDATE` to our `alembic_version_<whatever>` tables
  to be rolled back instead of committed.

  We now use one connection to determine which
  `alembic_version_<whatever>` table to use and another to run the
  actual migrations. This prevents the erroneous rollback.

  This change is compatible with both SQLAlchemy 1.4 and 2.0.

#### manager.c: Add new parameter 'PreDialGoSub' to Originate AMI action
  Author: jonatascalebe
  Date:   2024-03-14

  manager.c: Add new parameter 'PreDialGoSub' to Originate AMI action

  The action originate does not has the ability to run an subroutine at initial channel, like the Aplication Originate. This update give this ability for de action originate too.

  For example, we can run a routine via Gosub on the channel to request an automatic answer, so the caller does not need to accept the call when using the originate command via manager, making the operation more efficient.

  UserNote: When using the Originate AMI Action, we now can pass the PreDialGoSub parameter, instructing the asterisk to perform an subrouting at channel before call start. With this parameter an call initiated by AMI can request the channel to start the call automaticaly, adding a SIP header to using GoSUB, instructing to autoanswer the channel, and proceeding the outbuound extension executing. Exemple of an context to perform the previus indication:
  [addautoanswer]
  exten => _s,1,Set(PJSIP_HEADER(add,Call-Info)=answer-after=0)
  exten => _s,n,Set(PJSIP_HEADER(add,Alert-Info)=answer-after=0)
  exten => _s,n,Return()

#### menuselect: Minor cosmetic fixes.
  Author: Naveen Albert
  Date:   2024-03-21

  Improve some of the formatting from
  dd3f17c699e320d6d30c94298d8db49573ba28da
  (#521).

#### pbx_variables.c: Prevent SEGV due to stack overflow.
  Author: Naveen Albert
  Date:   2023-12-04

  It is possible for dialplan to result in an infinite
  recursion of variable substitution, which eventually
  leads to stack overflow. If we detect this, abort
  substitution and log an error for the user to fix
  the broken dialplan.

  Resolves: #480

  UpgradeNote: The maximum amount of dialplan recursion
  using variable substitution (such as by using EVAL_EXTEN)
  is capped at 15.

#### res_prometheus: Fix duplicate output of metric and help text
  Author: Holger Hans Peter Freyther
  Date:   2024-02-24

  The prometheus exposition format requires each line to be unique[1].
  This is handled by struct prometheus_metric having a list of children
  that is managed when registering a metric. In case the scrape callback
  is used, it is the responsibility of the implementation to handle this
  correctly.

  Originally the bridge callback didn't handle NULL snapshots, the crash
  fix lead to NULL metrics, and fixing that lead to duplicates.

  The original code assumed that snapshots are not NULL and then relied on
  "if (i > 0)" to establish the parent/children relationship between
  metrics of the same class. This is not workerable as the first bridge
  might be invisible/lacks a snapshot.

  Fix this by keeping a separate array of the first metric by class.
  Instead of relying on the index of the bridge, check whether the array
  has an entry. Use that array for the output.

  Add a test case that verifies that the help text is not duplicated.

  Resolves: #642

  [1] https://prometheus.io/docs/instrumenting/exposition_formats/#grouping-and-sorting

#### manager.c: Add CLI command to kick AMI sessions.
  Author: Naveen Albert
  Date:   2023-12-06

  This adds a CLI command that can be used to manually
  kick specific AMI sessions.

  Resolves: #485

  UserNote: The "manager kick session" CLI command now
  allows kicking a specified AMI session.

#### chan_dahdi: Allow specifying waitfordialtone per call.
  Author: Naveen Albert
  Date:   2023-12-02

  The existing "waitfordialtone" setting in chan_dahdi.conf
  applies permanently to a specific channel, regardless of
  how it is being used. This rather restrictively prevents
  a system from simultaneously being able to pick free lines
  for outgoing calls while also allowing barge-in to a trunk
  by some other arrangement.

  This allows specifying "waitfordialtone" using the CHANNEL
  function for only the next call that will be placed, allowing
  significantly more flexibility in the use of trunk interfaces.

  Resolves: #472

  UserNote: "waitfordialtone" may now be specified for DAHDI
  trunk channels on a per-call basis using the CHANNEL function.

#### res_parking: Fail gracefully if parking lot is full.
  Author: Naveen Albert
  Date:   2024-03-03

  Currently, if a parking lot is full, bridge setup returns -1,
  causing dialplan execution to terminate without TryExec.
  However, such failures should be handled more gracefully,
  the same way they are on other paths, as indicated by the
  module's author, here:

  http://lists.digium.com/pipermail/asterisk-dev/2018-December/077144.html

  Now, callers will hear the parking failure announcement, and dialplan
  will continue, which is consistent with existing failure modes.

  Resolves: #624

#### res_config_mysql.c: Support hostnames up to 255 bytes.
  Author: Sean Bright
  Date:   2024-03-18

  Fixes #654

#### res_pjsip: Fix alembic downgrade for boolean columns.
  Author: Sean Bright
  Date:   2024-03-18

  When downgrading, ensure that we don't touch columns that didn't
  actually change during upgrade.

#### Upgrade bundled pjproject to 2.14.1
  Author: Stanislav Abramenkov
  Date:   2024-03-12

  Fixes: asterisk#648

  UserNote: Bundled pjproject has been upgraded to 2.14.1. For more
  information visit pjproject Github page: https://github.com/pjsip/pjproject/releases/tag/2.14.1

#### alembic: Quote new MySQL keyword 'qualify.'
  Author: Sean Bright
  Date:   2024-03-15

  Fixes #651

#### res_pjsip_session: Reset pending_media_state->read_callbacks
  Author: Maximilian Fridrich
  Date:   2024-02-15

  In handle_negotiated_sdp the pending_media_state->read_callbacks must be
  reset before they are added in the SDP handlers in
  handle_negotiated_sdp_session_media. Otherwise, old callbacks for
  removed streams and file descriptors could be added to the channel and
  Asterisk would poll on non-existing file descriptors.

  Resolves: #611

#### res_pjsip_stir_shaken.c:  Add checks for missing parameters
  Author: George Joseph
  Date:   2024-03-11

  * Added checks for missing session, session->channel and rdata
    in stir_shaken_incoming_request.

  * Added checks for missing session, session->channel and tdata
    in stir_shaken_outgoing_request.

  Resolves: #645

#### app_dial: Add dial time for progress/ringing.
  Author: Naveen Albert
  Date:   2024-02-08

  Add a timeout option to control the amount of time
  to wait if no early media is received before giving
  up. This allows aborting early if the destination
  is not being responsive.

  Resolves: #588

  UserNote: The timeout argument to Dial now allows
  specifying the maximum amount of time to dial if
  early media is not received.

#### app_voicemail: Properly reinitialize config after unit tests.
  Author: Naveen Albert
  Date:   2024-02-29

  Most app_voicemail unit tests were not properly cleaning up
  after themselves after running. This led to test mailboxes
  lingering around in the system. It also meant that if any
  unit tests in app_voicemail that create mailboxes were executed
  and the module was not unloaded/loaded again prior to running
  the test_voicemail_vm_info unit test, Asterisk would segfault
  due to an attempt to copy a NULL string.

  The load_config test did actually have logic to reinitialize
  the config after the test. However, this did not work in practice
  since load_config() would not reload the config since voicemail.conf
  had not changed during the test; thus, additional logic has been
  added to ensure that voicemail.conf is truly reloaded, after any
  unit tests which modify the users list.

  This prevents the SEGV due to invalid mailboxes lingering around,
  and also ensures that the system state is restored to what it was
  prior to the tests running.

  Resolves: #629

#### app_queue.c : fix "queue add member" usage string
  Author: Shaaah
  Date:   2024-01-23

  Fixing bracket placement in the "queue add member" cli usage string.

#### app_voicemail: Allow preventing mark messages as urgent.
  Author: Naveen Albert
  Date:   2024-02-24

  This adds an option to allow preventing callers from leaving
  messages marked as 'urgent'.

  Resolves: #619

  UserNote: The leaveurgent mailbox option can now be used to
  control whether callers may leave messages marked as 'Urgent'.

#### res_pjsip: Use consistent type for boolean columns.
  Author: Sean Bright
  Date:   2024-02-27

  This migrates the relevant schema objects from the `('yes', 'no')`
  definition to the `('0', '1', 'off', 'on', 'false', 'true', 'yes', 'no')`
  one.

  Fixes #617

#### attestation_config.c: Use ast_free instead of ast_std_free
  Author: George Joseph
  Date:   2024-03-05

  In as_check_common_config, we were calling ast_std_free on
  raw_key but raw_key was allocated with ast_malloc so it
  should be freed with ast_free.

  Resolves: #636

#### Makefile: Add stir_shaken/cache to directories created on install
  Author: George Joseph
  Date:   2024-03-04

  The default location for the stir_shaken cache is
  /var/lib/asterisk/keys/stir_shaken/cache but we were only creating
  /var/lib/asterisk/keys/stir_shaken on istall.  We now create
  the cache sub-directory.

  Resolves: #634

#### Stir/Shaken Refactor
  Author: George Joseph
  Date:   2023-10-26

  Why do we need a refactor?

  The original stir/shaken implementation was started over 3 years ago
  when little was understood about practical implementation.  The
  result was an implementation that wouldn't actually interoperate
  with any other stir-shaken implementations.

  There were also a number of stir-shaken features and RFC
  requirements that were never implemented such as TNAuthList
  certificate validation, sending Reason headers in SIP responses
  when verification failed but we wished to continue the call, and
  the ability to send Media Key(mky) grants in the Identity header
  when the call involved DTLS.

  Finally, there were some performance concerns around outgoing
  calls and selection of the correct certificate and private key.
  The configuration was keyed by an arbitrary name which meant that
  for every outgoing call, we had to scan the entire list of
  configured TNs to find the correct cert to use.  With only a few
  TNs configured, this wasn't an issue but if you have a thousand,
  it could be.

  What's changed?

  * Configuration objects have been refactored to be clearer about
    their uses and to fix issues.
      * The "general" object was renamed to "verification" since it
        contains parameters specific to the incoming verification
        process.  It also never handled ca_path and crl_path
        correctly.
      * A new "attestation" object was added that controls the
        outgoing attestation process.  It sets default certificates,
        keys, etc.
      * The "certificate" object was renamed to "tn" and had it's key
        change to telephone number since outgoing call attestation
        needs to look up certificates by telephone number.
      * The "profile" object had more parameters added to it that can
        override default parameters specified in the "attestation"
        and "verification" objects.
      * The "store" object was removed altogther as it was never
        implemented.

  * We now use libjwt to create outgoing Identity headers and to
    parse and validate signatures on incoming Identiy headers.  Our
    previous custom implementation was much of the source of the
    interoperability issues.

  * General code cleanup and refactor.
      * Moved things to better places.
      * Separated some of the complex functions to smaller ones.
      * Using context objects rather than passing tons of parameters
        in function calls.
      * Removed some complexity and unneeded encapsuation from the
        config objects.

  Resolves: #351
  Resolves: #46

  UserNote: Asterisk's stir-shaken feature has been refactored to
  correct interoperability, RFC compliance, and performance issues.
  See https://docs.asterisk.org/Deployment/STIR-SHAKEN for more
  information.

  UpgradeNote: The stir-shaken refactor is a breaking change but since
  it's not working now we don't think it matters. The
  stir_shaken.conf file has changed significantly which means that
  existing ones WILL need to be changed.  The stir_shaken.conf.sample
  file in configs/samples/ has quite a bit more information.  This is
  also an ABI breaking change since some of the existing objects
  needed to be changed or removed, and new ones added.  Additionally,
  if res_stir_shaken is enabled in menuselect, you'll need to either
  have the development package for libjwt v1.15.3 installed or use
  the --with-libjwt-bundled option with ./configure.

#### translate.c: implement new direct comp table mode
  Author: Sebastian Jennen
  Date:   2024-02-25

  The new mode lists for each codec translation the actual real cost in cpu microseconds per second translated audio.
  This allows to compare the real cpu usage of translations and helps in evaluation of codec implementation changes regarding performance (regression testing).

  - add new table mode
  - hide the 999999 comp values, as these only indicate an issue with transcoding
  - hide the 0 values, as these also do not contain any information (only indicate a multistep transcoding)

  Resolves: #601

#### README.md: Removed outdated link
  Author: Shyju Kanaprath
  Date:   2024-02-23

  Removed outdated link http://www.quicknet.net from README.md

  cherry-pick-to: 18
  cherry-pick-to: 20
  cherry-pick-to: 21
#### strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.
  Author: Sean Bright
  Date:   2024-02-17

  If a dynamic string is created with an initial length of 0,
  `ast_str_buffer(…)` will return an invalid pointer.

  This was a secondary discovery when fixing #65.

#### res_rtp_asterisk.c: Correct coefficient in MOS calculation.
  Author: romryz
  Date:   2024-02-06

  Media Experience Score relies on incorrect pseudo_mos variable
  calculation. According to forming an opinion section of the
  documentation, calculation relies on ITU-T G.107 standard:

      https://docs.asterisk.org/Deployment/Media-Experience-Score/#forming-an-opinion

  ITU-T G.107 Annex B suggests to calculate MOS with a coefficient
  "seven times ten to the power of negative six", 7 * 10^(-6). which
  would mean 6 digits after the decimal point. Current implementation
  has 7 digits after the decimal point, which downrates the calls.

  Fixes: #597

#### dsp.c: Fix and improve potentially inaccurate log message.
  Author: Naveen Albert
  Date:   2024-02-09

  If ast_dsp_process is called with a codec besides slin, ulaw,
  or alaw, a warning is logged that in-band DTMF is not supported,
  but this message is not always appropriate or correct, because
  ast_dsp_process is much more generic than just DTMF detection.

  This logs a more generic message in those cases, and also improves
  codec-mismatch logging throughout dsp.c by ensuring incompatible
  codecs are printed out.

  Resolves: #595

#### pjsip show channelstats: Prevent possible segfault when faxing
  Author: George Joseph
  Date:   2024-02-09

  Under rare circumstances, it's possible for the original audio
  session in the active_media_state default_session to be corrupted
  instead of removed when switching to the t38/image media session
  during fax negotiation.  This can cause a segfault when a "pjsip
  show channelstats" attempts to print that audio media session's
  rtp statistics.  In these cases, the active_media_state
  topology is correctly showing only a single t38/image stream
  so we now check that there's an audio stream in the topology
  before attempting to use the audio media session to get the rtp
  statistics.

  Resolves: #592

#### Reduce startup/shutdown verbose logging
  Author: George Joseph
  Date:   2024-01-31

  When started with a verbose level of 3, asterisk can emit over 1500
  verbose message that serve no real purpose other than to fill up
  logs. When asterisk shuts down, it emits another 1100 that are of
  even less use. Since the testsuite runs asterisk with a verbose
  level of 3, and asterisk starts and stops for every one of the 700+
  tests, the number of log messages is staggering.  Besides taking up
  resources, it also makes it hard to debug failing tests.

  This commit changes the log level for those verbose messages to 5
  instead of 3 which reduces the number of log messages to only a
  handful. Of course, NOTICE, WARNING and ERROR message are
  unaffected.

  There's also one other minor change...
  ast_context_remove_extension_callerid2() logs a DEBUG message
  instead of an ERROR if the extension you're deleting doesn't exist.
  The pjsip_config_wizard calls that function to clean up the config
  and has been triggering that annoying error message for years.

  Resolves: #582

#### configure: Rerun bootstrap on modern platform.
  Author: Naveen Albert
  Date:   2024-02-08

  The last time configure was run, it was run on a system that
  did not enable -std=gnu11 by default, which meant that the
  restrict qualifier would not be recognized on certain platforms.
  This regenerates the configure files from running bootstrap.sh,
  so that these should be recognized on all supported platforms.

  Resolves: #586

#### Upgrade bundled pjproject to 2.14.
  Author: Ben Ford
  Date:   2024-02-05

  Fixes: #406

  UserNote: Bundled pjproject has been upgraded to 2.14. For more
  information on what all is included in this change, check out the
  pjproject Github page: https://github.com/pjsip/pjproject/releases

#### app_speech_utils.c: Allow partial speech results.
  Author: cmaj
  Date:   2024-02-02

  Adds 'p' option to SpeechBackground() application.
  With this option, when the app timeout is reached,
  whatever the backend speech engine collected will
  be returned as if it were the final, full result.
  (This works for engines that make partial results.)

  Resolves: #572

  UserNote: The SpeechBackground dialplan application now supports a 'p'
  option that will return partial results from speech engines that
  provide them when a timeout occurs.

#### res_pjsip_outbound_registration.c: Add User-Agent header override
  Author: Flole998
  Date:   2023-12-13

  This introduces a setting for outbound registrations to override the
  global User-Agent header setting.

  Resolves: #515

  UserNote: PJSIP outbound registrations now support a per-registration
  User-Agent header

#### utils: Make behavior of ast_strsep* match strsep.
  Author: Joshua C. Colp
  Date:   2024-01-31

  Given the scenario of passing an empty string to the
  ast_strsep functions the functions would return NULL
  instead of an empty string. This is counter to how
  strsep itself works.

  This change alters the behavior of the functions to
  match that of strsep.

  Fixes: #565

#### app_chanspy: Add 'D' option for dual-channel audio
  Author: Mike Bradeen
  Date:   2024-01-31

  Adds the 'D' option to app chanspy that causes the input and output
  frames of the spied channel to be interleaved in the spy output frame.
  This allows the input and output of the spied channel to be decoded
  separately by the receiver.

  If the 'o' option is also set, the 'D' option is ignored as the
  audio being spied is inherently one direction.

  Fixes: #569

  UserNote: The ChanSpy application now accepts the 'D' option which
  will interleave the spied audio within the outgoing frames. The
  purpose of this is to allow the audio to be read as a Dual channel
  stream with separate incoming and outgoing audio. Setting both the
  'o' option and the 'D' option and results in the 'D' option being
  ignored.

#### app_if: Fix next priority calculation.
  Author: Naveen Albert
  Date:   2024-01-28

  Commit fa3922a4d28860d415614347d9f06c233d2beb07 fixed
  a branching issue but "overshoots" when calculating
  the next priority. This fixes that; accompanying
  test suite tests have also been extended.

  Resolves: #560

#### res_pjsip_t38.c: Permit IPv6 SDP connection addresses.
  Author: Sean Bright
  Date:   2024-01-29

  The existing code prevented IPv6 addresses from being properly parsed.

  Fixes #558

#### BuildSystem: Bump autotools versions on OpenBSD.
  Author: Brad Smith
  Date:   2024-01-27

  Bump up to the more commonly used and modern versions of
  autoconf and automake.

#### main/utils: Simplify the FreeBSD ast_get_tid() handling
  Author: Brad Smith
  Date:   2024-01-27

  FreeBSD has had kernel threads for 20+ years.

#### res_pjsip_session.c: Correctly format SDP connection addresses.
  Author: Sean Bright
  Date:   2024-01-27

  Resolves a regression identified by @justinludwig involving the
  rendering of IPv6 addresses in outgoing SDP.

  Also updates `media_address` on PJSIP endpoints so that if we are able
  to parse the configured value as an IP we store it in a format that we
  can directly use later. Based on my reading of the code it appeared
  that one could configure `media_address` as:

  ```
  [foo]
  type = endpoint
  ...
  media_address = [2001:db8::]
  ```

  And that value would be blindly copied into the outgoing SDP without
  regard to its format.

  Fixes #541

#### rtp_engine.c: Correct sample rate typo for L16/44100.
  Author: Sean Bright
  Date:   2024-01-28

  Fixes #555

#### manager.c: Fix erroneous reloads in UpdateConfig.
  Author: Naveen Albert
  Date:   2024-01-25

  Currently, a reload will always occur if the
  Reload header is provided for the UpdateConfig
  action. However, we should not be doing a reload
  if the header value has a falsy value, per the
  documentation, so this makes the reload behavior
  consistent with the existing documentation.

  Resolves: #551

#### res_calendar_icalendar: Print iCalendar error on parsing failure.
  Author: Naveen Albert
  Date:   2023-12-14

  If libical fails to parse a calendar, print the error message it provdes.

  Resolves: #492

#### app_confbridge: Don't emit warnings on valid configurations.
  Author: Sean Bright
  Date:   2024-01-21

  The numeric bridge profile options `internal_sample_rate` and
  `maximum_sample_rate` are documented to accept the special values
  `auto` and `none`, respectively. While these values currently work,
  they also emit warnings when used which could be confusing for users.

  In passing, also ensure that we only accept the documented range of
  sample rate values between 8000 and 192000.

  Fixes #546

#### app_voicemail_odbc: remove macrocontext from voicemail_messages table
  Author: Mike Bradeen
  Date:   2024-01-10

  When app_macro was deprecated, the macrocontext column was removed from
  the INSERT statement but the binds were not renumbered. This broke the
  insert.

  This change removes the macrocontext column via alembic and re-numbers
  the existing columns in the INSERT.

  Fixes: #527

  UserNote: The fix requires removing the macrocontext column from the
  voicemail_messages table in the voicemail database via alembic upgrade.

  UpgradeNote: The fix requires that the voicemail database be upgraded via
  alembic. Upgrading to the latest voicemail database via alembic will
  remove the macrocontext column from the voicemail_messages table.

#### chan_dahdi: Allow MWI to be manually toggled on channels.
  Author: Naveen Albert
  Date:   2023-11-10

  This adds a CLI command to manually toggle the MWI status
  of a channel, useful for troubleshooting or resetting
  MWI devices, similar to the capabilities offered with
  SIP messaging to manually control MWI status.

  UserNote: The 'dahdi set mwi' now allows MWI on channels
  to be manually toggled if needed for troubleshooting.

  Resolves: #440

#### logger: Fix linking regression.
  Author: Naveen Albert
  Date:   2024-01-16

  Commit 008731b0a4b96c4e6c340fff738cc12364985b64
  caused a regression by resulting in logger.xml
  being compiled and linked into the asterisk
  binary in lieu of logger.c on certain platforms
  if Asterisk was compiled in dev mode.

  To fix this, we ensure the file has a unique
  name without the extension. Most existing .xml
  files have been named differently from any
  .c files in the same directory or did not
  pose this issue.

  channels/pjsip/dialplan_functions.xml does not
  pose this issue but is also being renamed
  to adhere to this policy.

  Resolves: #539

#### chan_rtp.c: MulticastRTP missing refcount without codec option
  Author: PeterHolik
  Date:   2024-01-15

  Fixes: #529

#### chan_rtp.c: Change MulticastRTP nameing to avoid memory leak
  Author: PeterHolik
  Date:   2024-01-16

  Fixes: asterisk#536

#### func_frame_trace: Add CLI command to dump frame queue.
  Author: Naveen Albert
  Date:   2024-01-12

  This adds a simple CLI command that can be used for
  analyzing all frames currently queued to a channel.

  A couple log messages are also adjusted to be more
  useful in tracing bridging problems.

  Resolves: #533

#### menuselect: Use more specific error message.
  Author: Naveen Albert
  Date:   2024-01-04

  Instead of using the same error message for
  missing dependencies and conflicts, be specific
  about what actually went wrong.

  Resolves: #520

#### res_pjsip_nat: Fix potential use of uninitialized transport details
  Author: Maximilian Fridrich
  Date:   2024-01-08

  The ast_sip_request_transport_details must be zero initialized,
  otherwise this could lead to a SEGV.

  Resolves: #509

#### app_if: Fix faulty EndIf branching.
  Author: Naveen Albert
  Date:   2023-12-23

  This fixes faulty branching logic for the
  EndIf application. Instead of computing
  the next priority, which should be done
  for false conditionals or ExitIf, we should
  simply advance to the next priority.

  Resolves: #341

#### manager.c: Fix regression due to using wrong free function.
  Author: Naveen Albert
  Date:   2023-12-26

  Commit 424be345639d75c6cb7d0bd2da5f0f407dbd0bd5 introduced
  a regression by calling ast_free on memory allocated by
  realpath. This causes Asterisk to abort when executing this
  function. Since the memory is allocated by glibc, it should
  be freed using ast_std_free.

  Resolves: #513

#### res_rtp_asterisk: Fix regression issues with DTLS client check
  Author: George Joseph
  Date:   2023-12-15

  * Since ICE candidates are used for the check and pjproject is
    required to use ICE, res_rtp_asterisk was failing to compile
    when pjproject wasn't available.  The check is now wrapped
    with an #ifdef HAVE_PJPROJECT.

  * The rtp->ice_active_remote_candidates container was being
    used to check the address on incoming packets but that
    container doesn't contain peer reflexive candidates discovered
    during negotiation. This was causing the check to fail
    where it shouldn't.  We now check against pjproject's
    real_ice->rcand array which will contain those candidates.

  * Also fixed a bug in ast_sockaddr_from_pj_sockaddr() where
    we weren't zeroing out sin->sin_zero before returning.  This
    was causing ast_sockaddr_cmp() to always return false when
    one of the inputs was converted from a pj_sockaddr, even
    if both inputs had the same address and port.

  Resolves: #500
  Resolves: #503
  Resolves: #505

#### res_pjsip_header_funcs: Duplicate new header value, don't copy.
  Author: Gitea
  Date:   2023-07-10

  When updating an existing header the 'update' code incorrectly
  just copied the new value into the existing buffer. If the
  new value exceeded the available buffer size memory outside
  of the buffer would be written into, potentially causing
  a crash.

  This change makes it so that the 'update' now duplicates
  the new header value instead of copying it into the existing
  buffer.

#### res_pjsip: disable raw bad packet logging
  Author: Mike Bradeen
  Date:   2023-07-25

  Add patch to split the log level for invalid packets received on the
  signaling port.  The warning regarding the packet will move to level 2
  so that it can still be displayed, while the raw packet will be at level
  4.

#### res_rtp_asterisk.c: Check DTLS packets against ICE candidate list
  Author: George Joseph
  Date:   2023-11-09

  When ICE is in use, we can prevent a possible DOS attack by allowing
  DTLS protocol messages (client hello, etc) only from sources that
  are in the active remote candidates list.

  Resolves: GHSA-hxj9-xwr8-w8pq

#### manager.c: Prevent path traversal with GetConfig.
  Author: Ben Ford
  Date:   2023-11-13

  When using AMI GetConfig, it was possible to access files outside of the
  Asterisk configuration directory by using filenames with ".." and "./"
  even while live_dangerously was not enabled. This change resolves the
  full path and ensures we are still in the configuration directory before
  attempting to access the file.

#### config_options.c: Fix truncation of option descriptions.
  Author: Naveen Albert
  Date:   2023-11-09

  This increases the format width of option descriptions
  to avoid needless truncation for longer descriptions.

  Resolves: #428

#### manager.c: Improve clarity of "manager show connected".
  Author: Naveen Albert
  Date:   2023-12-05

  Improve the "manager show connected" CLI command
  to clarify that the last two columns are permissions
  related, not counts, and use sufficient widths
  to consistently display these values.

  ASTERISK-30143 #close
  Resolves: #482

#### make_xml_documentation: Really collect LOCAL_MOD_SUBDIRS documentation.
  Author: Sean Bright
  Date:   2023-12-01

  Although `make_xml_documentation`'s `print_dependencies` command was
  corrected by the previous fix (#461) for #142, the `create_xml` was
  not properly handling `LOCAL_MOD_SUBDIRS` XML documentation.

#### general: Fix broken links.
  Author: Naveen Albert
  Date:   2023-11-09

  This fixes a number of broken links throughout the
  tree, mostly caused by wiki.asterisk.org being replaced
  with docs.asterisk.org, which should eliminate the
  need for sporadic fixes as in f28047db36a70e81fe373a3d19132c43adf3f74b.

  Resolves: #430

#### MergeApproved.yml:  Remove unneeded concurrency
  Author: George Joseph
  Date:   2023-12-06

  The concurrency parameter on the MergeAndCherryPick job has
  been rmeoved.  It was a hold-over from earlier days.

#### app_dial: Add option "j" to preserve initial stream topology of caller
  Author: Maximilian Fridrich
  Date:   2023-11-30

  Resolves: #462

  UserNote: The option "j" is now available for the Dial application which
  uses the initial stream topology of the caller to create the outgoing
  channels.

#### pbx_config.c: Don't crash when unloading module.
  Author: Sean Bright
  Date:   2023-12-02

  `pbx_config` subscribes to manager events to capture the `FullyBooted`
  event but fails to unsubscribe if the module is loaded after that
  event fires. If the module is unloaded, a crash occurs the next time a
  manager event is raised.

  We now unsubscribe when the module is unloaded if we haven't already
  unsubscribed.

  Fixes #470

#### ast_coredumper: Increase reliability
  Author: George Joseph
  Date:   2023-11-11

  Instead of searching for the asterisk binary and the modules in the
  filesystem, we now get their locations, along with libdir, from
  the coredump itself...

  For the binary, we can use `gdb -c <coredump> ... "info proc exe"`.
  gdb can print this even without having the executable and symbols.

  Once we have the binary, we can get the location of the modules with
  `gdb ... "print ast_config_AST_MODULE_DIR`

  If there was no result then either it's not an asterisk coredump
  or there were no symbols loaded.  Either way, it's not usable.

  For libdir, we now run "strings" on the note0 section of the
  coredump (which has the shared library -> memory address xref) and
  search for "libasteriskssl|libasteriskpj", then take the dirname.

  Since we're now getting everything from the coredump, it has to be
  correct as long as we're not crossing namespace boundaries like
  running asterisk in a docker container but trying to run
  ast_coredumper from the host using a shared file system (which you
  shouldn't be doing).

  There is still a case for using --asterisk-bin and/or --libdir: If
  you've updated asterisk since the coredump was taken, the binary,
  libraries and modules won't match the coredump which will render it
  useless.  If you can restore or rebuild the original files that
  match the coredump and place them in a temporary directory, you can
  use --asterisk-bin, --libdir, and a new --moddir option to point to
  them and they'll be correctly captured in a tarball created
  with --tarball-coredumps.  If you also use --tarball-config, you can
  use a new --etcdir option to point to what normally would be the
  /etc/asterisk directory.

  Also addressed many "shellcheck" findings.

  Resolves: #445

#### logger.c: Move LOG_GROUP documentation to dedicated XML file.
  Author: Sean Bright
  Date:   2023-12-01

  The `get_documentation` awk script will only extract the first
  DOCUMENTATION block that it finds in a given file. This is by design
  (9bc2127) to prevent AMI event documentation from being pulled in to
  the core.xml documentation file.

  Because of this, the `LOG_GROUP` documentation added in 89709e2 was
  not being properly extracted and was missing fom the resulting XML
  documentation file. This commit moves the `LOG_GROUP` documentation to
  a separate `logger.xml` file.

#### res_odbc.c: Allow concurrent access to request odbc connections
  Author: Matthew Fredrickson
  Date:   2023-11-30

  There are valid scenarios where res_odbc's connection pool might have some dead
  or stuck connections while others are healthy (imagine network
  elements/firewalls/routers silently timing out connections to a single DB and a
  single IP address, or a heterogeneous connection pool connected to potentially
  multiple IPs/instances of a replicated DB using a DNS front end for load
  balancing and one replica fails).

  In order to time out those unhealthy connections without blocking access to
  other parts of Asterisk that may attempt access to the connection pool, it would
  be beneficial to not lock/block access around the entire pool in
  _ast_odbc_request_obj2 while doing potentially blocking operations on connection
  pool objects such as the connection_dead() test, odbc_obj_connect(), or by
  dereferencing a struct odbc_obj for the last time and triggering a
  odbc_obj_disconnect().

  This would facilitate much quicker and concurrent timeout of dead connections
  via the connection_dead() test, which could block potentially for a long period
  of time depending on odbc.ini or other odbc connector specific timeout settings.

  This also would make rapid failover (in the clustered DB scenario) much quicker.

  This patch changes the locking in _ast_odbc_request_obj2() to not lock around
  odbc_obj_connect(), _disconnect(), and connection_dead(), while continuing to
  lock around truly shared, non-immutable state like the connection_cnt member and
  the connections list on struct odbc_class.

  Fixes: #465

#### res_pjsip_header_funcs.c: Check URI parameter length before copying.
  Author: Sean Bright
  Date:   2023-12-04

  Fixes #477

#### config.c: Log #exec include failures.
  Author: Sean Bright
  Date:   2023-11-22

  If the script referenced by `#exec` does not exist, writes anything to
  stderr, or exits abnormally or with a non-zero exit status, we log
  that to Asterisk's error logging channel.

  Additionally, write out a warning if the script produces no output.

  Fixes #259

#### make_xml_documentation: Properly handle absolute LOCAL_MOD_SUBDIRS.
  Author: Sean Bright
  Date:   2023-11-27

  If LOCAL_MOD_SUBDIRS contains absolute paths, do not prefix them with
  the path to Asterisk's source tree.

  Fixes #142

#### app_voicemail.c: Completely resequence mailbox folders.
  Author: Sean Bright
  Date:   2023-11-27

  Resequencing is a process that occurs when we open a voicemail folder
  and discover that there are gaps between messages (e.g. `msg0000.txt`
  is missing but `msg0001.txt` exists). Resequencing involves shifting
  the existing messages down so we end up with a sequential list of
  messages.

  Currently, this process stops after reaching a threshold based on the
  message limit (`maxmsg`) configured on the current folder. However, if
  `maxmsg` is lowered when a voicemail folder contains more than
  `maxmsg + 10` messages, resequencing will not run completely leaving
  the mailbox in an inconsistent state.

  We now resequence up to the maximum number of messages permitted by
  `app_voicemail` (currently hard-coded at 9999 messages).

  Fixes #86

#### sig_analog: Fix channel leak when mwimonitor is enabled.
  Author: Naveen Albert
  Date:   2023-11-24

  When mwimonitor=yes is enabled for an FXO port,
  the do_monitor thread will launch mwi_thread if it thinks
  there could be MWI on an FXO channel, due to the noise
  threshold being satisfied. This, in turns, calls
  analog_ss_thread_start in sig_analog. However, unlike
  all other instances where __analog_ss_thread is called
  in sig_analog, this call path does not properly set
  pvt->ss_astchan to the Asterisk channel, which means
  that the Asterisk channel is NULL when __analog_ss_thread
  starts executing. As a result, the thread exits and the
  channel is never properly cleaned up by calling ast_hangup.

  This caused issues with do_monitor on incoming calls,
  as it would think the channel was still owned even while
  receiving events, leading to an infinite barrage of
  warning messages; additionally, the channel would persist
  improperly.

  To fix this, the assignment is added to the call path
  where it is missing (which is only used for mwi_thread).
  A warning message is also added since previously there
  was no indication that __analog_ss_thread was exiting
  abnormally. This resolves both the channel leak and the
  condition that led to the warning messages.

  Resolves: #458

#### res_rtp_asterisk.c: Update for OpenSSL 3+.
  Author: Sean Bright
  Date:   2023-11-20

  In 5ac5c2b0 we defined `OPENSSL_SUPPRESS_DEPRECATED` to silence
  deprecation warnings. This commit switches over to using
  non-deprecated API.

#### alembic: Update list of TLS methods available on ps_transports.
  Author: Sean Bright
  Date:   2023-11-14

  Related to #221 and #222.

  Also adds `*.ini` to the `.gitignore` file in ast-db-manage for
  convenience.

#### func_channel: Expose previously unsettable options.
  Author: Naveen Albert
  Date:   2023-11-11

  Certain channel options are not set anywhere or
  exposed in any way to users, making them unusable.
  This exposes some of these options which make sense
  for users to manipulate at runtime.

  Resolves: #442

#### app.c: Allow ampersands in playback lists to be escaped.
  Author: Sean Bright
  Date:   2023-11-07

  Any function or application that accepts a `&`-separated list of
  filenames can now include a literal `&` in a filename by wrapping the
  entire filename in single quotes, e.g.:

  ```
  exten = _X.,n,Playback('https://example.com/sound.cgi?a=b&c=d'&hello-world)
  ```

  Fixes #172

  UpgradeNote: Ampersands in URLs passed to the `Playback()`,
  `Background()`, `SpeechBackground()`, `Read()`, `Authenticate()`, or
  `Queue()` applications as filename arguments can now be escaped by
  single quoting the filename. Additionally, this is also possible when
  using the `CONFBRIDGE` dialplan function, or configuring various
  features in `confbridge.conf` and `queues.conf`.

#### uri.c: Simplify ast_uri_make_host_with_port()
  Author: Sean Bright
  Date:   2023-11-09


#### func_curl.c: Remove CURLOPT() plaintext documentation.
  Author: Sean Bright
  Date:   2023-11-13

  I assume this was missed when initially converting to XML
  documentation and we've been kicking the can down the road since.

#### res_http_websocket.c: Set hostname on client for certificate validation.
  Author: Sean Bright
  Date:   2023-11-09

  Additionally add a `assert()` to in the TLS client setup code to
  ensure that hostname is set when it is supposed to be.

  Fixes #433

#### live_ast: Add astcachedir to generated asterisk.conf.
  Author: Sean Bright
  Date:   2023-11-09

  `astcachedir` (added in b0842713) was not added to `live_ast` so
  continued to point to the system `/var/cache` directory instead of the
  one in the live environment.

#### SECURITY.md: Update with correct documentation URL
  Author: George Joseph
  Date:   2023-11-09


#### func_lock: Add missing see-also refs to documentation.
  Author: Naveen Albert
  Date:   2023-11-09

  Resolves: #423

#### app_followme.c: Grab reference on nativeformats before using it
  Author: Matthew Fredrickson
  Date:   2023-10-25

  Fixes a crash due to a lack of proper reference on the nativeformats
  object before passing it into ast_request().  Also found potentially
  similar use case bugs in app_chanisavail.c, bridge.c, and bridge_basic.c

  Fixes: #388

#### configs: Improve documentation for bandwidth in iax.conf.
  Author: Naveen Albert
  Date:   2023-11-09

  This improves the documentation for the bandwidth setting
  in iax.conf by making it clearer what the ramifications
  of this setting are. It also changes the sample default
  from low to high, since only high is compatible with good
  codecs that people will want to use in the vast majority
  of cases, and this is a common gotcha that trips up new users.

  Resolves: #425

#### logger: Add channel-based filtering.
  Author: Naveen Albert
  Date:   2023-08-09

  This adds the ability to filter console
  logging by channel or groups of channels.
  This can be useful on busy systems where
  an administrator would like to analyze certain
  calls in detail. A dialplan function is also
  included for the purpose of assigning a channel
  to a group (e.g. by tenant, or some other metric).

  ASTERISK-30483 #close

  Resolves: #242

  UserNote: The console log can now be filtered by
  channels or groups of channels, using the
  logger filter CLI commands.

#### chan_iax2.c: Don't send unsanitized data to the logger.
  Author: Sean Bright
  Date:   2023-11-08

  This resolves an issue where non-printable characters could be sent to
  the console/log files.

#### codec_ilbc: Disable system ilbc if version >= 3.0.0
  Author: George Joseph
  Date:   2023-11-07

  Fedora 37 started shipping ilbc 3.0.4 which we don't yet support.
  configure.ac now checks the system for "libilbc < 3" instead of
  just "libilbc".  If true, the system version of ilbc will be used.
  If not, the version included at codecs/ilbc will be used.

  Resolves: #84

#### resource_channels.c: Explicit codec request when creating UnicastRTP.
  Author: Sean Bright
  Date:   2023-11-06

  Fixes #394

#### doc: Update IP Quality of Service links.
  Author: Sean Bright
  Date:   2023-11-07

  Fixes #328

#### chan_pjsip: Add PJSIPHangup dialplan app and manager action
  Author: George Joseph
  Date:   2023-10-31

  See UserNote below.

  Exposed the existing Hangup AMI action in manager.c so we can use
  all of it's channel search and AMI protocol handling without
  duplicating that code in dialplan_functions.c.

  Added a lookup function to res_pjsip.c that takes in the
  string represenation of the pjsip_status_code enum and returns
  the actual status code.  I.E.  ast_sip_str2rc("DECLINE") returns
  603.  This allows the caller to specify PJSIPHangup(decline) in
  the dialplan, just like Hangup(call_rejected).

  Also extracted the XML documentation to its own file since it was
  almost as large as the code itself.

  UserNote: A new dialplan app PJSIPHangup and AMI action allows you
  to hang up an unanswered incoming PJSIP call with a specific SIP
  response code in the 400 -> 699 range.

#### chan_iax2.c: Ensure all IEs are displayed when dumping frame contents.
  Author: Sean Bright
  Date:   2023-11-06

  When IAX2 debugging was enabled (`iax2 set debug on`), if the last IE
  in a frame was one that may not have any data - such as the CALLTOKEN
  IE in an NEW request - it was not getting displayed.

#### chan_dahdi: Warn if nonexistent cadence is requested.
  Author: Naveen Albert
  Date:   2023-11-02

  If attempting to ring a channel using a nonexistent cadence,
  emit a warning, before falling back to the default cadence.

  Resolves: #409

#### stasis: Update the snapshot after setting the redirect
  Author: Holger Hans Peter Freyther
  Date:   2023-10-21

  The previous commit added the caller_rdnis attribute. Make it
  avialble during a possible ChanngelHangupRequest.

#### ari: Provide the caller ID RDNIS for the channels
  Author: Holger Hans Peter Freyther
  Date:   2023-10-14

  Provide the caller ID RDNIS when available. This will allow an
  application to follow the redirect.

#### main/utils: Implement ast_get_tid() for OpenBSD
  Author: Brad Smith
  Date:   2023-11-01

  Implement the ast_get_tid() function for OpenBSD. OpenBSD supports
  getting the TID via getthrid().

#### res_rtp_asterisk.c: Fix runtime issue with LibreSSL
  Author: Brad Smith
  Date:   2023-11-02

  The module will fail to load. Use proper function DTLS_method() with LibreSSL.

#### app_directory: Add ADSI support to Directory.
  Author: Naveen Albert
  Date:   2023-09-27

  This adds optional ADSI support to the Directory
  application, which allows callers with ADSI CPE
  to navigate the Directory system significantly
  faster than is possible using the audio prompts.
  Callers can see the directory name (and optionally
  extension) on their screenphone and confirm or
  reject a match immediately rather than waiting
  for it to be spelled out, enhancing usability.

  Resolves: #356

#### core_local: Fix local channel parsing with slashes.
  Author: Naveen Albert
  Date:   2023-08-09

  Currently, trying to call a Local channel with a slash
  in the extension will fail due to the parsing of characters
  after such a slash as being dial modifiers. Additionally,
  core_local is inconsistent and incomplete with
  its parsing of Local dial strings in that sometimes it
  uses the first slash and at other times it uses the last.

  For instance, something like DAHDI/5 or PJSIP/device
  is a perfectly usable extension in the dialplan, but Local
  channels in particular prevent these from being called.

  This creates inconsistent behavior for users, since using
  a slash in an extension is perfectly acceptable, and using
  a Goto to accomplish this works fine, but if specified
  through a Local channel, the parsing prevents this.

  This fixes this by explicitly parsing options from the
  last slash in the extension, rather than the first one,
  which doesn't cause an issue for extensions with slashes.

  ASTERISK-30013 #close

  Resolves: #248

#### Remove files that are no longer updated
  Author: Mark Murawski
  Date:   2023-10-30

  Fixes: #360

#### app_voicemail: Add AMI event for mailbox PIN changes.
  Author: Naveen Albert
  Date:   2023-10-30

  This adds an AMI event that is emitted whenever a
  mailbox password is successfully changed, allowing
  AMI consumers to process these.

  UserNote: The VoicemailPasswordChange event is
  now emitted whenever a mailbox password is updated,
  containing the mailbox information and the new
  password.

  Resolves: #398

#### app_queue.c: Emit unpause reason with PauseQueueMember event.
  Author: Sean Bright
  Date:   2023-10-30

  Fixes #395

#### bridge_simple: Suppress unchanged topology change requests
  Author: George Joseph
  Date:   2023-10-30

  In simple_bridge_join, we were sending topology change requests
  even when the new and old topologies were the same.  In some
  circumstances, this can cause unnecessary re-invites and even
  a re-invite flood.  We now suppress those.

  Resolves: #384

#### res_pjsip: Include cipher limit in config error message.
  Author: Naveen Albert
  Date:   2023-10-30

  If too many ciphers are specified in the PJSIP config,
  include the maximum number of ciphers that may be
  specified in the user-facing error message.

  Resolves: #396

#### res_speech: allow speech to translate input channel
  Author: Mike Bradeen
  Date:   2023-09-07

  * Allow res_speech to translate the input channel if the
    format is translatable to a format suppored by the
    speech provider.

  Resolves: #129

  UserNote: res_speech now supports translation of an input channel
  to a format supported by the speech provider, provided a translation
  path is available between the source format and provider capabilites.

#### res_rtp_asterisk.c: Fix memory leak in ephemeral certificate creation.
  Author: Sean Bright
  Date:   2023-10-25

  Fixes #386

#### res_pjsip_dtmf_info.c: Add 'INFO' to Allow header.
  Author: Sean Bright
  Date:   2023-10-17

  Fixes #376

#### Update issue guidelines link for bug reports.
  Author: Joshua C. Colp
  Date:   2023-10-27


#### api.wiki.mustache: Fix indentation in generated markdown
  Author: George Joseph
  Date:   2023-10-25

  The '*' list indicator for default values and allowable values for
  path, query and POST parameters need to be indented 4 spaces
  instead of 2.

  Should resolve issue 38 in the documentation repo.

#### pjsip_configuration.c: Disable DTLS renegotiation if WebRTC is enabled.
  Author: Sean Bright
  Date:   2023-10-23

  Per RFC8827:

      Implementations MUST NOT implement DTLS renegotiation and MUST
      reject it with a "no_renegotiation" alert if offered.

  So we disable it when webrtc=yes is set.

  Fixes #378

  UpgradeNote: The dtls_rekey will be disabled if webrtc support is
  requested on an endpoint. A warning will also be emitted.

#### configs: Fix typo in pjsip.conf.sample.
  Author: Samuel Olaechea
  Date:   2023-10-12


#### res_pjsip_exten_state,res_pjsip_mwi: Allow unload on shutdown
  Author: George Joseph
  Date:   2023-10-19

  Commit f66f77f last year prevents the res_pjsip_exten_state and
  res_pjsip_mwi modules from unloading due to possible pjproject
  asserts if the modules are reloaded. A side effect of the
  implementation is that the taskprocessors these modules use aren't
  being released. When asterisk is doing a graceful shutdown, it
  waits AST_TASKPROCESSOR_SHUTDOWN_MAX_WAIT seconds for all
  taskprocessors to stop but since those 2 modules don't release
  theirs, the shutdown hangs for that amount of time.

  This change allows the modules to be unloaded and their resources to
  be released when ast_shutdown_final is true.

  Resolves: #379

#### res_pjsip: Expanding PJSIP endpoint ID and relevant resource length to 255 characters
  Author: sungtae kim
  Date:   2023-09-23

  This commit introduces an extension to the endpoint and relevant
  resource sizes for PJSIP, transitioning from its current 40-character
  constraint to a more versatile 255-character capacity. This enhancement
  significantly overcomes limitations related to domain qualification and
  practical usage, ultimately delivering improved functionality. In
  addition, it includes adjustments to accommodate the expanded realm size
  within the ARI, specifically enhancing the maximum realm length.

  Resolves: #345

  UserNote: With this update, the PJSIP realm lengths have been extended
  to support up to 255 characters.

  UpgradeNote: As part of this update, the maximum allowable length
  for PJSIP endpoints and relevant resources has been increased from
  40 to 255 characters. To take advantage of this enhancement, it is
  recommended to run the necessary procedures (e.g., Alembic) to
  update your schemas.

#### res_stasis: signal when new command is queued
  Author: Mike Bradeen
  Date:   2023-10-02

  res_statsis's app loop sleeps for up to .2s waiting on input
  to a channel before re-checking the command queue. This can
  cause delays between channel setup and bridge.

  This change is to send a SIGURG on the sleeping thread when
  a new command is enqueued. This exits the sleeping thread out
  of the ast_waitfor() call triggering the new command being
  processed on the channel immediately.

  Resolves: #362

  UserNote: Call setup times should be significantly improved
  when using ARI.

#### ari/stasis: Indicate progress before playback on a bridge
  Author: Holger Hans Peter Freyther
  Date:   2023-10-02

  Make it possible to start a playback and the calling party
  to receive audio on a bridge before the call is connected.

  Model the implementation after play_on_channel and deliver a
  AST_CONTROL_PROGRESS before starting the playback.

  For a PJSIP channel this will result in sending a SIP 183
  Session Progress.

#### func_curl.c: Ensure channel is locked when manipulating datastores.
  Author: Sean Bright
  Date:   2023-10-09


#### logger.h: Add ability to change the prefix on SCOPE_TRACE output
  Author: George Joseph
  Date:   2023-10-05

  You can now define the _TRACE_PREFIX_ macro to change the
  default trace line prefix of "file:line function" to
  something else.  Full documentation in logger.h.

#### res_pjsip: update qualify_timeout documentation with DNS note
  Author: Mike Bradeen
  Date:   2023-09-26

  The documentation on qualify_timeout does not explicitly state that the timeout
  includes any time required to perform any needed DNS queries on the endpoint.

  If the OPTIONS response is delayed due to the DNS query, it can still render an
  endpoint as Unreachable if the net time is enough for qualify_timeout to expire.

  Resolves: #352

#### res_speech_aeap: add aeap error handling
  Author: Mike Bradeen
  Date:   2023-09-21

  res_speech_aeap previously did not register an error handler
  with aeap, so it was not notified of a disconnect. This resulted
  in SpeechBackground never exiting upon a websocket disconnect.

  Resolves: #303

#### Add libjwt to third-party
  Author: George Joseph
  Date:   2023-09-21

  The current STIR/SHAKEN implementation is not currently usable due
  to encryption issues. Rather than trying to futz with OpenSSL and
  the the current code, we can take advantage of the existing
  capabilities of libjwt but we first need to add it to the
  third-party infrastructure already in place for jansson and
  pjproject.

  A few tweaks were also made to the third-party infrastructure as
  a whole.  The jansson "dest" install directory was renamed "dist"
  to better match convention, and the third-party Makefile was updated
  to clean all product directories not just the ones currently in
  use.

  Resolves: #349

#### chan_dahdi: Clarify scope of callgroup/pickupgroup.
  Author: Naveen Albert
  Date:   2023-09-04

  Internally, chan_dahdi only applies callgroup and
  pickupgroup to FXO signalled channels, but this is
  not documented anywhere. This is now documented in
  the sample config, and a warning is emitted if a
  user tries configuring these settings for channel
  types that do not support these settings, since they
  will not have any effect.

  Resolves: #294

#### func_json: Fix crashes for some types
  Author: Bastian Triller
  Date:   2023-09-21

  This commit fixes crashes in JSON_DECODE() for types null, true, false
  and real numbers.

  In addition it ensures that a path is not deeper than 32 levels.

  Also allow root object to be an array.

  Add unit tests for above cases.

#### app_voicemail: Disable ADSI if unavailable.
  Author: Naveen Albert
  Date:   2023-09-27

  If ADSI is available on a channel, app_voicemail will repeatedly
  try to use ADSI, even if there is no CPE that supports it. This
  leads to many unnecessary delays during the session. If ADSI is
  available but ADSI setup fails, we now disable it to prevent
  further attempts to use ADSI during the session.

  Resolves: #354

#### codec_builtin: Use multiples of 20 for maximum_ms
  Author: Eduardo
  Date:   2023-07-28

  Some providers require a multiple of 20 for the maxptime or fail to complete calls,
  e.g. Vivo in Brazil. To increase compatibility, only multiples of 20 are now used.

  Resolves: #260

#### lock.c: Separate DETECT_DEADLOCKS from DEBUG_THREADS
  Author: George Joseph
  Date:   2023-09-13

  Previously, DETECT_DEADLOCKS depended on DEBUG_THREADS.
  Unfortunately, DEBUG_THREADS adds a lot of lock tracking overhead
  to all of the lock lifecycle calls whereas DETECT_DEADLOCKS just
  causes the lock calls to loop over trylock in 200us intervals until
  the lock is obtained and spits out log messages if it takes more
  than 5 seconds.  From a code perspective, the only reason they were
  tied together was for logging.  So... The ifdefs in lock.c were
  refactored to allow DETECT_DEADLOCKS to be enabled without
  also enabling DEBUG_THREADS.

  Resolves: #321

  UserNote: You no longer need to select DEBUG_THREADS to use
  DETECT_DEADLOCKS.  This removes a significant amount of overhead
  if you just want to detect possible deadlocks vs needing full
  lock tracing.

#### asterisk.c: Use the euid's home directory to read/write cli history
  Author: George Joseph
  Date:   2023-09-15

  The CLI .asterisk_history file is read from/written to the directory
  specified by the HOME environment variable. If the root user starts
  asterisk with the -U/-G options, or with runuser/rungroup set in
  asterisk.conf, the asterisk process is started as root but then it
  calls setuid/setgid to set the new user/group. This does NOT reset
  the HOME environment variable to the new user's home directory
  though so it's still left as "/root". In this case, the new user
  will almost certainly NOT have access to read from or write to the
  history file.

  * Added function process_histfile() which calls
    getpwuid(geteuid()) and uses pw->dir as the home directory
    instead of the HOME environment variable.
  * ast_el_read_default_histfile() and ast_el_write_default_histfile()
    have been modified to use the new process_histfile()
    function.

  Resolves: #337

#### res_pjsip_transport_websocket: Prevent transport from being destroyed before message finishes.
  Author: Tinet-mucw
  Date:   2023-09-13

  From the gdb information, ast_websocket_read reads a message successfully,
  then transport_read is called in the serializer. During execution of pjsip_transport_down,
  ws_session->stream->fd is closed; ast_websocket_read encounters an error and exits the while loop.
  After executing transport_shutdown, the transport's reference count becomes 0, causing a crash when sending SIP messages.
  This was due to pjsip_transport_dec_ref executing earlier than pjsip_rx_data_clone, leading to this issue.
  In websocket_cb executeing pjsip_transport_add_ref, this we now ensure the transport is not destroyed while in the loop.

  Resolves: asterisk#299

#### cel: add publish user event helper
  Author: Mike Bradeen
  Date:   2023-09-14

  Add a wrapper function around ast_cel_publish_event that
  packs event and extras into a blob before publishing

  Resolves:#330

#### chan_console: Fix deadlock caused by unclean thread exit.
  Author: Naveen Albert
  Date:   2023-09-09

  To terminate a console channel, stop_stream causes pthread_cancel
  to make stream_monitor exit. However, commit 5b8fea93d106332bc0faa4b7fa8a6ea71e546cac
  added locking to this function which results in deadlock due to
  the stream_monitor thread being killed while it's holding the pvt lock.

  To resolve this, a flag is now set and read to indicate abort, so
  the use of pthread_cancel and pthread_kill can be avoided altogether.

  Resolves: #308

#### file.c: Add ability to search custom dir for sounds
  Author: George Joseph
  Date:   2023-09-11

  To better co-exist with sounds files that may be managed by
  packages, custom sound files may now be placed in
  AST_DATA_DIR/sounds/custom instead of the standard
  AST_DATA_DIR/sounds/<lang> directory.  If the new
  "sounds_search_custom_dir" option in asterisk.conf is set
  to "true", asterisk will search the custom directory for sounds
  files before searching the standard directory.  For performance
  reasons, the "sounds_search_custom_dir" defaults to "false".

  Resolves: #315

  UserNote: A new option "sounds_search_custom_dir" has been added to
  asterisk.conf that allows asterisk to search
  AST_DATA_DIR/sounds/custom for sounds files before searching the
  standard AST_DATA_DIR/sounds/<lang> directory.

#### chan_iax2: Improve authentication debugging.
  Author: Naveen Albert
  Date:   2023-08-30

  Improves and adds some logging to make it easier
  for users to debug authentication issues.

  Resolves: #286

#### res_rtp_asterisk: fix wrong counter management in ioqueue objects
  Author: Vitezslav Novy
  Date:   2023-09-05

  In function  rtp_ioqueue_thread_remove counter in ioqueue object is not decreased
  which prevents unused ICE TURN threads from being removed.

  Resolves: #301

#### res_pjsip_pubsub: Add body_type to test_handler for unit tests
  Author: George Joseph
  Date:   2023-09-15

  The ast_sip_subscription_handler "test_handler" used for the unit
  tests didn't set "body_type" so the NULL value was causing
  a SEGV in build_subscription_tree().  It's now set to "".

  Resolves: #335

#### make_buildopts_h, et. al.  Allow adding all cflags to buildopts.h
  Author: George Joseph
  Date:   2023-09-13

  The previous behavior of make_buildopts_h was to not add the
  non-ABI-breaking MENUSELECT_CFLAGS like DETECT_DEADLOCKS,
  REF_DEBUG, etc. to the buildopts.h file because "it caused
  ccache to invalidate files and extended compile times". They're
  only defined by passing them on the gcc command line with '-D'
  options.   In practice, including them in the include file rarely
  causes any impact because the only time ccache cares is if you
  actually change an option so the hit occurrs only once after
  you change it.

  OK so why would we want to include them?  Many IDEs follow the
  include files to resolve defines and if the options aren't in an
  include file, it can cause the IDE to mark blocks of "ifdeffed"
  code as unused when they're really not.

  So...

  * Added a new menuselect compile option ADD_CFLAGS_TO_BUILDOPTS_H
    which tells make_buildopts_h to include the non-ABI-breaking
    flags in buildopts.h as well as the ABI-breaking ones. The default
    is disabled to preserve current behavior.  As before though,
    only the ABI-breaking flags appear in AST_BUILDOPTS and only
    those are used to calculate AST_BUILDOPT_SUM.
    A new AST_BUILDOPT_ALL define was created to capture all of the
    flags.

  * make_version_c was streamlined to use buildopts.h and also to
    create asterisk_build_opts_all[] and ast_get_build_opts_all(void)

  * "core show settings" now shows both AST_BUILDOPTS and
    AST_BUILDOPTS_ALL.

  UserNote: The "Build Options" entry in the "core show settings"
  CLI command has been renamed to "ABI related Build Options" and
  a new entry named "All Build Options" has been added that shows
  both breaking and non-breaking options.

#### func_periodic_hook: Add hangup step to avoid timeout
  Author: Mike Bradeen
  Date:   2023-09-12

  func_periodic_hook does not hangup after playback, relying on hangup
  which keeps the channel alive longer than necessary.

  Resolves: #325

#### res_stasis_recording.c: Save recording state when unmuted.
  Author: Sean Bright
  Date:   2023-09-12

  Fixes #322

#### res_speech_aeap: check for null format on response
  Author: Mike Bradeen
  Date:   2023-09-08

  * Fixed issue in res_speech_aeap when unable to provide an
    input format to check against.

#### func_periodic_hook: Don't truncate channel name
  Author: George Joseph
  Date:   2023-09-11

  func_periodic_hook was truncating long channel names which
  causes issues when you need to run other dialplan functions/apps
  on the channel.

  Resolves: #319

#### safe_asterisk: Change directory permissions to 755
  Author: George Joseph
  Date:   2023-09-11

  If the safe_asterisk script detects that the /var/lib/asterisk
  directory doesn't exist, it now creates it with 755 permissions
  instead of 770.  safe_asterisk needing to create that directory
  should be extremely rare though because it's normally created
  by 'make install' which already sets the permissions to 755.

  Resolves: #316

#### chan_rtp: Implement RTP glue for UnicastRTP channels
  Author: Maximilian Fridrich
  Date:   2023-09-05

  Resolves: #298

  UserNote: The dial string option 'g' was added to the UnicastRTP channel
  which enables RTP glue and therefore native RTP bridges with those
  channels.

#### variables: Add additional variable dialplan functions.
  Author: Joshua C. Colp
  Date:   2023-08-31

  Using the Set dialplan application does not actually
  delete channel or global variables. Instead the
  variables are set to an empty value.

  This change adds two dialplan functions,
  GLOBAL_DELETE and DELETE which can be used to
  delete global and channel variables instead
  of just setting them to empty.

  There is also no ability within the dialplan to
  determine if a global or channel variable has
  actually been set or not.

  This change also adds two dialplan functions,
  GLOBAL_EXISTS and VARIABLE_EXISTS which can be
  used to determine if a global or channel variable
  has been set or not.

  Resolves: #289

  UserNote: Four new dialplan functions have been added.
  GLOBAL_DELETE and DELETE have been added which allows
  the deletion of global and channel variables.
  GLOBAL_EXISTS and VARIABLE_EXISTS have been added
  which checks whether a global or channel variable has
  been set.

#### ari-stubs: Fix more local anchor references
  Author: George Joseph
  Date:   2023-09-05

  Also allow CreateDocs job to be run manually with default branches.

#### ari-stubs: Fix broken documentation anchors
  Author: George Joseph
  Date:   2023-09-05

  All of the links that reference page anchors with capital letters in
  the ids (#Something) have been changed to lower case to match the
  anchors that are generated by mkdocs.

#### res_pjsip_session: Send Session Interval too small response
  Author: Bastian Triller
  Date:   2023-08-28

  Handle session interval lower than endpoint's configured minimum timer
  when sending first answer. Timer setting is checked during this step and
  needs to handled appropriately.
  Before this change, no response was sent at all. After this change a
  response with 422 Session Interval too small is sent to UAC.

#### app_dial: Fix infinite loop when sending digits.
  Author: Naveen Albert
  Date:   2023-08-28

  If the called party hangs up while digits are being
  sent, -1 is returned to indicate so, but app_dial
  was not checking the return value, resulting in
  the hangup being lost and looping forever until
  the caller manually hangs up the channel. We now
  abort if digit sending fails.

  ASTERISK-29428 #close

  Resolves: #281

#### app_voicemail: Fix for loop declarations
  Author: Mike Bradeen
  Date:   2023-08-29

  Resolve for loop initial declarations added in cli changes.

  Resolves: #275

#### alembic: Fix quoting of the 100rel column
  Author: George Joseph
  Date:   2023-08-28

  Add quoting around the ps_endpoints 100rel column in the ALTER
  statements.  Although alembic doesn't complain when generating
  sql statements, postgresql does (rightly so).

  Resolves: #274

#### pbx.c: Fix gcc 12 compiler warning.
  Author: Naveen Albert
  Date:   2023-08-27

  Resolves: #277

#### app_audiosocket: Fixed timeout with -1 to avoid busy loop.
  Author: zhengsh
  Date:   2023-08-24

  Resolves: asterisk#234

#### download_externals:  Fix a few version related issues
  Author: George Joseph
  Date:   2023-08-18

  * Fixed issue with the script not parsing the new tag format for
    certified releases.  The format changed from certified/18.9-cert5
    to certified-18.9-cert5.

  * Fixed issue where the asterisk version wasn't being considered
    when looking for cached versions.

  Resolves: #263

#### main/refer.c: Fix double free in refer_data_destructor + potential leak
  Author: Maximilian Fridrich
  Date:   2023-08-21

  Resolves: #267

#### sig_analog: Add Called Subscriber Held capability.
  Author: Naveen Albert
  Date:   2023-08-09

  This adds support for Called Subscriber Held for FXS
  lines, which allows users to go on hook when receiving
  a call and resume the call later from another phone on
  the same line, without disconnecting the call. This is
  a convenience mechanism that most real PSTN telephone
  switches support.

  ASTERISK-30372 #close

  Resolves: #240

  UserNote: Called Subscriber Held is now supported for analog
  FXS channels, using the calledsubscriberheld option. This allows
  a station  user to go on hook when receiving an incoming call
  and resume from another phone on the same line by going on hook,
  without disconnecting the call.

#### install_prereq: Fix dependency install on aarch64.
  Author: Jason D. McCormick
  Date:   2023-04-28

  Fixes dependency solutions in install_prereq for Debian aarch64
  platforms. install_prereq was attempting to forcibly install 32-bit
  armhf packages due to the aptitude search for dependencies.

  Resolves: #37

#### res_pjsip.c: Set contact_user on incoming call local Contact header
  Author: MikeNaso
  Date:   2023-08-08

  If the contact_user is configured on the endpoint it will now be set on the local Contact header URI for incoming calls. The contact_user has already been set on the local Contact header URI for outgoing calls.

  Resolves: #226

#### extconfig: Allow explicit DB result set ordering to be disabled.
  Author: Sean Bright
  Date:   2023-07-12

  Added a new boolean configuration flag -
  `order_multi_row_results_by_initial_column` - to both res_pgsql.conf
  and res_config_odbc.conf that allows the administrator to disable the
  explicit `ORDER BY` that was previously being added to all generated
  SQL statements that returned multiple rows.

  Fixes: #179

#### res_pjsip_header_funcs: Make prefix argument optional.
  Author: Naveen Albert
  Date:   2023-08-09

  The documentation for PJSIP_HEADERS claims that
  prefix is optional, but in the code it is actually not.
  However, there is no inherent reason for this, as users
  may want to retrieve all header names, not just those
  beginning with a certain prefix.

  This makes the prefix optional for this function,
  simply fetching all header names if not specified.
  As a result, the documentation is now correct.

  Resolves: #230

  UserNote: The prefix argument to PJSIP_HEADERS is now
  optional. If not specified, all header names will be
  returned.

#### pjproject_bundled: Increase PJSIP_MAX_MODULE to 38
  Author: George Joseph
  Date:   2023-08-11

  The default is 32 with 8 being used by pjproject itself.  Recent
  commits have put us over the limit resulting in assertions in
  pjproject.  Since this value is used in invites, dialogs,
  transports and subscriptions as well as the global pjproject
  endpoint, we don't want to increase it too much.

  Resolves: #255

#### manager: Tolerate stasis messages with no channel snapshot.
  Author: Joshua C. Colp
  Date:   2023-08-09

  In some cases I have yet to determine some stasis messages may
  be created without a channel snapshot. This change adds some
  tolerance to this scenario, preventing a crash from occurring.

#### Prepare master for Asterisk 22
  Author: George Joseph
  Date:   2023-08-09


#### core/ari/pjsip: Add refer mechanism
  Author: Maximilian Fridrich
  Date:   2023-05-10

  This change adds support for refers that are not session based. It
  includes a refer implementation for the PJSIP technology which results
  in out-of-dialog REFERs being sent to a PJSIP endpoint. These can be
  triggered using the new ARI endpoint `/endpoints/refer`.

  Resolves: #71

  UserNote: There is a new ARI endpoint `/endpoints/refer` for referring
  an endpoint to some URI or endpoint.

#### chan_dahdi: Allow autoreoriginating after hangup.
  Author: Naveen Albert
  Date:   2023-08-04

  Currently, if an FXS channel is still off hook when
  all calls on the line have hung up, the user is provided
  reorder tone until going back on hook again.

  In addition to not reflecting what most commercial switches
  actually do, it's very common for switches to automatically
  reoriginate for the user so that dial tone is provided without
  the user having to depress and release the hookswitch manually.
  This can increase convenience for users.

  This behavior is now supported for kewlstart FXS channels.
  It's supported only for kewlstart (FXOKS) mainly because the
  behavior doesn't make any sense for ground start channels,
  and loop start signalling doesn't provide the necessary DAHDI
  event that makes this easy to implement. Likely almost everyone
  is using FXOKS over FXOLS anyways since FXOLS is pretty useless
  these days.

  ASTERISK-30357 #close

  Resolves: #224

  UserNote: The autoreoriginate setting now allows for kewlstart FXS
  channels to automatically reoriginate and provide dial tone to the
  user again after all calls on the line have cleared. This saves users
  from having to manually hang up and pick up the receiver again before
  making another call.

#### audiohook: Unlock channel in mute if no audiohooks present.
  Author: Joshua C. Colp
  Date:   2023-08-09

  In the case where mute was called on a channel that had no
  audiohooks the code was not unlocking the channel, resulting
  in a deadlock.

  Resolves: #233

#### sig_analog: Allow three-way flash to time out to silence.
  Author: Naveen Albert
  Date:   2023-07-10

  sig_analog allows users to flash and use the three-way dial
  tone as a primitive hold function, simply by never timing
  it out.

  Some systems allow this dial tone to time out to silence,
  so the user is not annoyed by a persistent dial tone.
  This option allows the dial tone to time out normally to
  silence.

  ASTERISK-30004 #close
  Resolves: #205

  UserNote: The threewaysilenthold option now allows the three-way
  dial tone to time out to silence, rather than continuing forever.

#### res_prometheus: Do not generate broken metrics
  Author: Holger Hans Peter Freyther
  Date:   2023-04-07

  In 8d6fdf9c3adede201f0ef026dab201b3a37b26b6 invisible bridges were
  skipped but that lead to producing metrics with no name and no help.

  Keep track of the number of metrics configured and then only emit these.
  Add a basic testcase that verifies that there is no '(NULL)' in the
  output.

  ASTERISK-30474

#### res_pjsip: Enable TLS v1.3 if present.
  Author: Sean Bright
  Date:   2023-08-02

  Fixes #221

  UserNote: res_pjsip now allows TLS v1.3 to be enabled if supported by
  the underlying PJSIP library. The bundled version of PJSIP supports
  TLS v1.3.

#### func_cut: Add example to documentation.
  Author: phoneben
  Date:   2023-07-19

  This adds an example to the XML documentation clarifying usage
  of the CUT function to address a common misusage.

#### extensions.conf.sample: Remove reference to missing context.
  Author: Sean Bright
  Date:   2023-07-16

  c3ff4648 removed the [iaxtel700] context but neglected to remove
  references to it.

  This commit addresses that and also removes iaxtel and freeworlddialup
  references from other config files.

#### func_export: Use correct function argument as variable name.
  Author: Sean Bright
  Date:   2023-07-12

  Fixes #208

#### app_queue: Add support for applying caller priority change immediately.
  Author: Joshua C. Colp
  Date:   2023-07-07

  The app_queue module provides both an AMI action and a CLI command
  to change the priority of a caller in a queue. Up to now this change
  of priority has only been reflected to new callers into the queue.

  This change adds an "immediate" option to both the AMI action and
  CLI command which immediately applies the priority change respective
  to the other callers already in the queue. This can allow, for example,
  a caller to be placed at the head of the queue immediately if their
  priority is sufficient.

  Resolves: #202

  UserNote: The 'queue priority caller' CLI command and
  'QueueChangePriorityCaller' AMI action now have an 'immediate'
  argument which allows the caller priority change to be reflected
  immediately, causing the position of a caller to move within the
  queue depending on the priorities of the other callers.

#### app.h: Move declaration of ast_getdata_result before its first use
  Author: George Joseph
  Date:   2023-07-10

  The ast_app_getdata() and ast_app_getdata_terminator() declarations
  in app.h were changed recently to return enum ast_getdata_result
  (which is how they were defined in app.c).  The existing
  declaration of ast_getdata_result in app.h was about 1000 lines
  after those functions however so under certain circumstances,
  a "use before declaration" error was thrown by the compiler.
  The declaration of the enum was therefore moved to before those
  functions.

  Resolves: #200

#### chan_iax2.c: Avoid crash with IAX2 switch support.
  Author: Sean Bright
  Date:   2023-07-07

  A change made in 82cebaa0 did not properly handle the case when a
  channel was not provided, triggering a crash. ast_check_hangup(...)
  does not protect against NULL pointers.

  Fixes #180

#### res_geolocation: Ensure required 'location_info' is present.
  Author: Sean Bright
  Date:   2023-07-07

  Fixes #189

#### Adds manager actions to allow move/remove/forward individual messages in a particular mailbox folder. The forward command can be used to copy a message within a mailbox or to another mailbox. Also adds a VoicemailBoxSummarry, required to retrieve message ID's.
  Author: Mike Bradeen
  Date:   2023-06-29

  Resolves: #181

  UserNote: The following manager actions have been added

  VoicemailBoxSummary - Generate message list for a given mailbox

  VoicemailRemove - Remove a message from a mailbox folder

  VoicemailMove - Move a message from one folder to another within a mailbox

  VoicemailForward - Copy a message from one folder in one mailbox
  to another folder in another or the same mailbox.

#### app_voicemail: add CLI commands for message manipulation
  Author: Mike Bradeen
  Date:   2023-06-20

  Adds CLI commands to allow move/remove/forward individual messages
  from a particular mailbox folder. The forward command can be used
  to copy a message within a mailbox or to another mailbox. Also adds
  a show mailbox, required to retrieve message ID's.

  Resolves: #170

  UserNote: The following CLI commands have been added to app_voicemail

  voicemail show mailbox <mailbox> <context>
  Show contents of mailbox <mailbox>@<context>

  voicemail remove <mailbox> <context> <from_folder> <messageid>
  Remove message <messageid> from <from_folder> in mailbox <mailbox>@<context>

  voicemail move <mailbox> <context> <from_folder> <messageid> <to_folder>
  Move message <messageid> in mailbox <mailbox>&<context> from <from_folder> to <to_folder>

  voicemail forward <from_mailbox> <from_context> <from_folder> <messageid> <to_mailbox> <to_context> <to_folder>
  Forward message <messageid> in mailbox <mailbox>@<context> <from_folder> to
  mailbox <mailbox>@<context> <to_folder>

#### res_rtp_asterisk: Move ast_rtp_rtcp_report_alloc using `rtp->themssrc_valid` into the scope of the rtp_instance lock.
  Author: zhengsh
  Date:   2023-06-30

  From the gdb information, it was found that when calling __ast_free, the size of the
  allocated space pointed to by the pointer matches the size created when rtp->themssrc_valid
  is equal to 0. However, in reality, when reading the value of rtp->themssrc_valid in gdb,
  it is found to be 1.

  Within ast_rtcp_write(), the call to ast_rtp_rtcp_report_alloc() uses rtp->themssrc_valid,
  which is outside the protection of the rtp_instance lock. However,
  ast_rtcp_generate_report(), which is called by ast_rtcp_generate_compound_prefix(), uses
  rtp->themssrc_valid within the protection of the rtp_instance lock.

  This can lead to the possibility that the value of rtp->themssrc_valid used in the call to
  ast_rtp_rtcp_report_alloc() may be different from the value of rtp->themssrc_valid used
  within ast_rtcp_generate_report().

  Resolves: asterisk#63

#### users.conf: Deprecate users.conf configuration.
  Author: Naveen Albert
  Date:   2023-06-30

  This deprecates the users.conf config file, which
  is no longer as widely supported but still integrated
  with a number of different modules.

  Because there is no real mechanism for marking a
  configuration file as "deprecated", and users.conf
  is not just used in a single place, this now emits
  a warning to the user when the PBX loads to notify
  about the deprecation.

  This configuration mechanism has been widely criticized
  and discouraged since its inception, and is no longer
  relevant to the configuration that most users are doing
  today. Removing it will allow for some simplification
  and cleanup in the codebase.

  Resolves: #183

  UpgradeNote: The users.conf config is now deprecated
  and will be removed in a future version of Asterisk.

#### sig_analog: Allow immediate fake ring to be suppressed.
  Author: Naveen Albert
  Date:   2023-06-08

  When immediate=yes on an FXS channel, sig_analog will
  start fake audible ringback that continues until the
  channel is answered. Even if it answers immediately,
  the ringback is still audible for a brief moment.
  This can be disruptive and unwanted behavior.

  This adds an option to disable this behavior, though
  the default behavior remains unchanged.

  ASTERISK-30003 #close
  Resolves: #118

  UserNote: The immediatering option can now be set to no to suppress
  the fake audible ringback provided when immediate=yes on FXS channels.

#### apply_patches: Use globbing instead of file/sort.
  Author: Sean Bright
  Date:   2023-07-06

  This accomplishes the same thing as a `find ... | sort` but with the
  added benefit of clarity and avoiding a call to a subshell.

  Additionally drop the -s option from call to patch as it is not POSIX.

#### apply_patches: Sort patch list before applying
  Author: George Joseph
  Date:   2023-07-06

  The apply_patches script wasn't sorting the list of patches in
  the "patches" directory before applying them. This left the list
  in an indeterminate order. In most cases, the list is actually
  sorted but rarely, they can be out of order and cause dependent
  patches to fail to apply.

  We now sort the list but the "sort" program wasn't in the
  configure scripts so we needed to add that and regenerate
  the scripts as well.

  Resolves: #193

#### pjsip: Upgrade bundled version to pjproject 2.13.1
  Author: Stanislav Abramenkov
  Date:   2023-07-05


#### app_voicemail: fix imap compilation errors
  Author: Mike Bradeen
  Date:   2023-06-26

  Fixes two compilation errors in app_voicemail_imap, one due to an unsed
  variable and one due to a new variable added in the incorrect location
  in _163.

  Resolves: #174

#### res_musiconhold: avoid moh state access on unlocked chan
  Author: Mike Bradeen
  Date:   2023-05-31

  Move channel unlock to after moh state access to avoid
  potential unlocked access to state.

  Resolves: #133

#### utils: add lock timestamps for DEBUG_THREADS
  Author: Mike Bradeen
  Date:   2023-05-23

  Adds last locked and unlocked timestamps as well as a
  counter for the number of times the lock has been
  attempted (vs locked/unlocked) to debug output printed
  using the DEBUG_THREADS option.

  Resolves: #110

#### rest-api: Updates for new documentation site
  Author: George Joseph
  Date:   2023-06-26

  The new documentation site uses traditional markdown instead
  of the Confluence flavored version.  This required changes in
  the mustache templates and the python that generates the files.

#### rest-api: Ran make ari stubs to fix resource_endpoints inconsistency
  Author: George Joseph
  Date:   2023-06-27


#### app_voicemail_imap: Fix message count when IMAP server is unavailable
  Author: Olaf Titz
  Date:   2023-06-15

  Some callers of __messagecount did not correctly handle error return,
  instead returning a -1 message count.
  This caused a notification with "Messages-Waiting: yes" and
  "Voice-Message: -1/0 (0/0)" if the IMAP server was unavailable.

  Fixes: #64

#### res_pjsip_rfc3326: Prefer Q.850 cause code over SIP.
  Author: Sean Bright
  Date:   2023-06-12

  Resolves: #116

#### Update config.yml
  Author: Joshua C. Colp
  Date:   2023-06-15


#### res_pjsip_session: Added new function calls to avoid ABI issues.
  Author: Ben Ford
  Date:   2023-06-05

  Added two new functions (ast_sip_session_get_dialog and
  ast_sip_session_get_pjsip_inv_state) that retrieve the dialog and the
  pjsip_inv_state respectively from the pjsip_inv_session on the
  ast_sip_session struct. This is due to pjproject adding a new field to
  the pjsip_inv_session struct that caused crashes when trying to access
  fields that were no longer where they were expected to be if a module
  was compiled against a different version of pjproject.

  Resolves: #145

#### app_queue: Add force_longest_waiting_caller option.
  Author: Nathan Bruning
  Date:   2023-01-24

  This adds an option 'force_longest_waiting_caller' which changes the
  global behavior of the queue engine to prevent queue callers from
  'jumping ahead' when an agent is in multiple queues.

  Resolves: #108

  Also closes old asterisk issues:
  - ASTERISK-17732
  - ASTERISK-17570


#### pjsip_transport_events.c: Use %zu printf specifier for size_t.
  Author: Sean Bright
  Date:   2023-06-05

  Partially resolves #143.

#### res_crypto.c: Gracefully handle potential key filename truncation.
  Author: Sean Bright
  Date:   2023-06-05

  Partially resolves #143.

#### configure: Remove obsolete and deprecated constructs.
  Author: Sean Bright
  Date:   2023-06-01

  These were uncovered when trying to run `bootstrap.sh` with Autoconf
  2.71:

  * AC_CONFIG_HEADER() is deprecated in favor of AC_CONFIG_HEADERS().
  * AC_HEADER_TIME is obsolete.
  * $as_echo is deprecated in favor of AS_ECHO() which requires an update
    to ax_pthread.m4.

  Note that the generated artifacts in this commit are from Autoconf 2.69.

  Resolves #139

#### res_fax_spandsp.c: Clean up a spaces/tabs issue
  Author: zhou_jiajian
  Date:   2023-05-26


#### ast-db-manage: Synchronize revisions between comments and code.
  Author: Sean Bright
  Date:   2023-06-06

  In a handful of migrations, the comment header that indicates the
  current and previous revisions has drifted from the identifiers
  revision and down_revision variables. This updates the comment headers
  to match the code.

#### test_statis_endpoints:  Fix channel_messages test again
  Author: George Joseph
  Date:   2023-06-12


#### res_crypto.c: Avoid using the non-portable ALLPERMS macro.
  Author: Sean Bright
  Date:   2023-06-05

  ALLPERMS is not POSIX and it's trivial enough to not jump through
  autoconf hoops to check for it.

  Fixes #149.

#### tcptls: when disabling a server port, we should set the accept_fd to -1.
  Author: Jaco Kroon
  Date:   2023-06-02

  If we don't set this to -1 if the structure can be potentially re-used
  later then it's possible that we'll issue a close() on an unrelated file
  descriptor, breaking asterisk in other interesting ways.

  I believe this to be an unlikely scenario, but it costs nothing to be
  safe.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### AMI: Add parking position parameter to Park action
  Author: Jiajian Zhou
  Date:   2023-05-19

  Add a parking space extension parameter (ParkingSpace) to the Park action.
  Park action will attempt to park the call to that extension.
  If the extension is already in use, then execution will continue at the next priority.

  UserNote: New ParkingSpace parameter has been added to AMI action Park.

#### test_stasis_endpoints.c: Make channel_messages more stable
  Author: George Joseph
  Date:   2023-06-09

  The channel_messages test was assuming that stasis would return
  messages in a specific order.  This is an incorrect assumption as
  message ordering was never guaranteed.  This was causing the test
  to fail occasionally.  We now test all the messages for the
  required message types instead of testing one by one.

  Resolves: #158

#### build: Fix a few gcc 13 issues
  Author: George Joseph
  Date:   2023-06-09

  * gcc 13 is now catching when a function is declared as returning
    an enum but defined as returning an int or vice versa.  Fixed
    a few in app.h, loader.c, stasis_message.c.

  * gcc 13 is also now (incorrectly) complaining of dangling pointers
    when assigning a pointer to a local char array to a char *. Had
    to change that to an ast_alloca.

  Resolves: #155

#### ast-db-manage: Fix alembic branching error caused by #122.
  Author: Sean Bright
  Date:   2023-06-05

  Fixes #147.

#### sounds: Update download URL to use HTTPS.
  Author: Sean Bright
  Date:   2023-06-01

  Related to #136

#### configure: Makefile downloader enable follow redirects.
  Author: Miguel Angel Nubla
  Date:   2023-06-01

  If curl is used for building, any download such as a sounds package
  will fail to follow HTTP redirects and will download wrong data.

  Resolves: #136

#### res_musiconhold: Add option to loop last file.
  Author: Naveen Albert
  Date:   2023-05-25

  Adds the loop_last option to res_musiconhold,
  which allows the last audio file in the directory
  to be looped perpetually once reached, rather than
  circling back to the beginning again.

  Resolves: #122
  ASTERISK-30462

  UserNote: The loop_last option in musiconhold.conf now
  allows the last file in the directory to be looped once reached.

#### chan_dahdi: Fix Caller ID presentation for FXO ports.
  Author: Naveen Albert
  Date:   2023-05-25

  Currently, the presentation for incoming channels is
  always available, because it is never actually set,
  meaning the channel presentation can be nonsensical.
  If the presentation from the incoming Caller ID spill
  is private or unavailable, we now update the channel
  presentation to reflect this.

  Resolves: #120
  ASTERISK-30333
  ASTERISK-21741

#### AMI: Add CoreShowChannelMap action.
  Author: Ben Ford
  Date:   2023-05-18

  Adds a new AMI action (CoreShowChannelMap) that takes in a channel name
  and provides a list of all channels that are connected to that channel,
  following local channel connections as well.

  Resolves: #104

  UserNote: New AMI action CoreShowChannelMap has been added.

#### sig_analog: Add fuller Caller ID support.
  Author: Naveen Albert
  Date:   2023-05-18

  A previous change, ASTERISK_29991, made it possible
  to send additional Caller ID parameters that were
  not previously supported.

  This change adds support for analog DAHDI channels
  to now be able to receive these parameters for
  on-hook Caller ID, in order to enhance the usability
  of CPE that support these parameters.

  Resolves: #94
  ASTERISK-30331

  UserNote: Additional Caller ID properties are now supported on
  incoming calls to FXS stations, namely the
  redirecting reason and call qualifier.

#### res_stasis.c: Add new type 'sdp_label' for bridge creation.
  Author: Joe Searle
  Date:   2023-05-25

  Add new type 'sdp_label' when creating a bridge using the ARI. This will
  add labels to the SDP for each stream, the label is set to the
  corresponding channel id.

  Resolves: #91

  UserNote: When creating a bridge using the ARI the 'type' argument now
  accepts a new value 'sdp_label' which will configure the bridge to add
  labels for each stream in the SDP with the corresponding channel id.

#### app_followme: fix issue with enable_callee_prompt=no (#88)
  Author: alex2grad
  Date:   2023-06-05

  * app_followme: fix issue with enable_callee_prompt=no

  If the FollowMe option 'enable_callee_prompt' is set to 'no' then Asterisk
  incorrectly sets a winner channel to the channel from which any control frame was read.

  This fix sets the winner channel only to the answered channel.

  Resolves: #87

  ASTERISK-30326

#### app_queue: Preserve reason for realtime queues
  Author: Niklas Larsson
  Date:   2023-05-05

  When Asterisk is restarted it does not preserve paused reason for
  members of realtime queues. This was fixed for non-realtime queues in
  ASTERISK_25732

  Resolves: #66

  UpgradeNote: Add a new column to the queue_member table:
  reason_paused VARCHAR(80) so the reason can be preserved.

  UserNote: Make paused reason in realtime queues persist an
  Asterisk restart. This was fixed for non-realtime
  queues in ASTERISK_25732.

#### indications: logging changes
  Author: Mike Bradeen
  Date:   2023-05-16

  Increase verbosity to indicate failure due to missing country
  and to specify default on CLI dump

  Resolves: #89

#### callerid: Allow specifying timezone for date/time.
  Author: Naveen Albert
  Date:   2023-05-18

  The Caller ID generation routine currently is hardcoded
  to always use the system time zone. This makes it possible
  to optionally specify any TZ-format time zone.

  Resolves: #98
  ASTERISK-30330

#### logrotate: Fix duplicate log entries.
  Author: Naveen Albert
  Date:   2023-05-18

  The Asterisk logrotate script contains explicit
  references to files with the .log extension,
  which are also included when *log is expanded.
  This causes issues with newer versions of logrotate.
  This fixes this by ensuring that a log file cannot
  be referenced multiple times after expansion occurs.

  Resolves: #96
  ASTERISK-30442
  Reported by: EN Barnett
  Tested by: EN Barnett

#### app_sla: Migrate SLA applications out of app_meetme.
  Author: Naveen Albert
  Date:   2023-05-02

  This removes the dependency of the SLAStation and SLATrunk
  applications on app_meetme, in anticipation of the imminent
  removal of the deprecated app_meetme module.

  The user interface for the SLA applications is exactly the
  same, and in theory, users should not notice a difference.
  However, the SLA applications now use ConfBridge under the
  hood, rather than MeetMe, and they are now contained within
  their own module.

  Resolves: #50
  ASTERISK-30309

  UpgradeNote: The SLAStation and SLATrunk applications have been moved
  from app_meetme to app_sla. If you are using these applications and have
  autoload=no, you will need to explicitly load this module in modules.conf.

#### chan_pjsip: Allow topology/session refreshes in early media state (#74)
  Author: Maximilian Fridrich
  Date:   2023-05-25

  With this change, session modifications in the early media state are
  possible if the SDP was sent reliably and confirmed by a PRACK. For
  details, see RFC 6337, escpecially section 3.2.

  Resolves: #73
#### chan_dahdi: Fix broken hidecallerid setting. (#101)
  Author: InterLinked1
  Date:   2023-05-25

  The hidecallerid setting in chan_dahdi.conf currently
  is broken for a couple reasons.

  First, the actual code in sig_analog to "allow" or "block"
  Caller ID depending on this setting improperly used
  ast_set_callerid instead of updating the presentation.
  This issue was mostly fixed in ASTERISK_29991, and that
  fix is carried forward to this code as well.

  Secondly, the hidecallerid setting is set on the DAHDI
  pvt but not carried forward to the analog pvt properly.
  This is because the chan_dahdi config loading code improperly
  set permhidecallerid to permhidecallerid from the config file,
  even though hidecallerid is what is actually set from the config
  file. (This is done correctly for call waiting, a few lines above.)
  This is fixed to read the proper value.

  Thirdly, in sig_analog, hidecallerid is set to permhidecallerid
  only on hangup. This can lead to potential security vulnerabilities
  as an allowed Caller ID from an initial call can "leak" into subsequent
  calls if no hangup occurs between them. This is fixed by setting
  hidecallerid to permcallerid when calls begin, rather than when they end.
  This also means we don't need to also set hidecallerid in chan_dahdi.c
  when copying from the config, as we would have to otherwise.

  Fourthly, sig_analog currently only allows dialing *67 or *82 if
  that would actually toggle the presentation. A comment is added
  clarifying that this behavior is okay.

  Finally, a couple log messages are updated to be more accurate.

  Resolves: #100
  ASTERISK-30349 #close
#### asterisk.c: Fix option warning for remote console. (#103)
  Author: InterLinked1
  Date:   2023-05-22

  Commit 09e989f972e2583df4e9bf585c246c37322d8d2f
  categorized the T option as not being compatible
  with remote consoles, but they do affect verbose
  messages with remote console. This fixes this.

  Resolves: #102
#### res_pjsip_pubsub: Add new pubsub module capabilities. (#82)
  Author: InterLinked1
  Date:   2023-05-18

  The existing res_pjsip_pubsub APIs are somewhat limited in
  what they can do. This adds a few API extensions that make
  it possible for PJSIP pubsub modules to implement richer
  features than is currently possible.

  * Allow pubsub modules to get a handle to pjsip_rx_data on subscription
  * Allow pubsub modules to run a callback when a subscription is renewed
  * Allow pubsub modules to run a callback for outgoing NOTIFYs, with
    a handle to the tdata, so that modules can append their own headers
    to the NOTIFYs

  This change does not add any features directly, but makes possible
  several new features that will be added in future changes.

  Resolves: #81
  ASTERISK-30485 #close

  Master-Only: True
#### configure: fix test code to match gethostbyname_r prototype. (#75)
  Author: Jaco Kroon
  Date:   2023-05-15

  This enables the test to work with CC=clang.

  Without this the test for 6 args would fail with:

  utils.c:99:12: error: static declaration of 'gethostbyname_r' follows non-static declaration
  static int gethostbyname_r (const char *name, struct hostent *ret, char *buf,
             ^
  /usr/include/netdb.h:177:12: note: previous declaration is here
  extern int gethostbyname_r (const char *__restrict __name,
             ^

  Fixing the expected return type to int sorts this out.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>
#### res_pjsip_pubsub.c: Use pjsip version for pending NOTIFY check. (#47)
  Author: Sean Bright
  Date:   2023-05-11

  The functionality we are interested in is present only in pjsip 2.13
  and newer.

  Resolves: #45
#### res_sorcery_memory_cache.c: Fix memory leak (#56)
  Author: zhengsh
  Date:   2023-05-12

  Replace the original call to ast_strdup with a call to ast_strdupa to fix the leak issue.

  Resolves: #55
  ASTERISK-30429
#### utils.h: Deprecate `ast_gethostbyname()`. (#79)
  Author: Sean Bright
  Date:   2023-05-11

  Deprecate `ast_gethostbyname()` in favor of `ast_sockaddr_resolve()` and
  `ast_sockaddr_resolve_first_af()`. `ast_gethostbyname()` has not been
  used by any in-tree code since 2021.

  This function will be removed entirely in Asterisk 23.

  Resolves: #78

  UpgradeNote: ast_gethostbyname() has been deprecated and will be removed
  in Asterisk 23. New code should use `ast_sockaddr_resolve()` and
  `ast_sockaddr_resolve_first_af()`.
#### xml.c: Process XML Inclusions recursively. (#69)
  Author: Sean Bright
  Date:   2023-05-11

  If processing an XInclude results in new <xi:include> elements, we
  need to run XInclude processing again. This continues until no
  replacement occurs or an error is encountered.

  There is a separate issue with dynamic strings (ast_str) that will be
  addressed separately.

  Resolves: #65
#### chan_pjsip: also return all codecs on empty re-INVITE for late offers (#59)
  Author: Henning Westerholt
  Date:   2023-05-04

  We should also return all codecs on an re-INVITE without SDP for a
  call that used late offer (e.g. no SDP in the initial INVITE, SDP
  in the ACK). Bugfix for feature introduced in ASTERISK-30193
  (https://issues.asterisk.org/jira/browse/ASTERISK-30193)

  Migration from previous gerrit change that was not merged.
#### cel: add local optimization begin event (#54)
  Author: Mike Bradeen
  Date:   2023-05-04

  The current AST_CEL_LOCAL_OPTIMIZE event is and has been
  triggered on a local optimization end to serve as a flag
  indicating the event occurred.  This change adds a second
  AST_CEL_LOCAL_OPTIMIZE_BEGIN event for further detail.

  Resolves: #52

  UpgradeNote: The existing AST_CEL_LOCAL_OPTIMIZE can continue
  to be used as-is and the AST_CEL_LOCAL_OPTIMIZE_BEGIN event
  can be ignored if desired.

  UserNote: The new AST_CEL_LOCAL_OPTIMIZE_BEGIN can be used
  by itself or in conert with the existing
  AST_CEL_LOCAL_OPTIMIZE to book-end local channel optimizaion.
#### core: Cleanup gerrit and JIRA references. (#58)
  Author: Sean Bright
  Date:   2023-05-03

  * Remove .gitreview and switch to pulling the main asterisk branch
    version from configure.ac instead.

  * Replace references to JIRA with GitHub.

  * Other minor cleanup found along the way.

  Resolves: #39
#### res_pjsip: mediasec: Add Security-Client headers after 401 (#49)
  Author: Maximilian Fridrich
  Date:   2023-05-02

  When using mediasec, requests sent after a 401 must still contain the
  Security-Client header according to
  draft-dawes-sipcore-mediasec-parameter.

  Resolves: #48
#### LICENSE: Update link to trademark policy. (#44)
  Author: Joshua C. Colp
  Date:   2023-05-02

  Resolves: #43
#### say.c: Fix French time playback. (#42)
  Author: InterLinked1
  Date:   2023-05-02

  ast_waitstream was not called after ast_streamfile,
  resulting in "o'clock" being skipped in French.

  Additionally, the minute announcements should be
  feminine.

  Reported-by: Danny Lloyd

  Resolves: #41
  ASTERISK-30488
#### chan_dahdi: Add dialmode option for FXS lines.
  Author: Naveen Albert
  Date:   2023-04-28

  Currently, both pulse and tone dialing are always enabled
  on all FXS lines, with no way of disabling one or the other.

  In some circumstances, it is desirable or necessary to
  disable one of these, and this behavior can be problematic.

  A new "dialmode" option is added which allows setting the
  methods to support on a per channel basis for FXS (FXO
  signalled lines). The four options are "both", "pulse",
  "dtmf"/"tone", and "none".

  Additionally, integration with the CHANNEL function is
  added so that this setting can be updated for a channel
  during a call.

  Resolves: #35
  ASTERISK-29992

  UserNote: A "dialmode" option has been added which allows
  specifying, on a per-channel basis, what methods of
  subscriber dialing (pulse and/or tone) are permitted.

  Additionally, this can be changed on a channel
  at any point during a call using the CHANNEL
  function.

#### Initial GitHub PRs
  Author: George Joseph
  Date:   2023-04-28


#### Initial GitHub Issue Templates
  Author: George Joseph
  Date:   2023-04-28


#### pbx_dundi: Fix PJSIP endpoint configuration check.
  Author: Joshua C. Colp
  Date:   2023-04-13

  ASTERISK-28233


#### res_pjsip_stir_shaken: Fix JSON field ordering and disallowed TN characters.
  Author: Naveen Albert
  Date:   2023-02-17

  The current STIR/SHAKEN signing process is inconsistent with the
  RFCs in a couple ways that can cause interoperability issues.

  RFC8225 specifies that the keys must be ordered lexicographically, but
  currently the fields are simply ordered according to the order
  in which they were added to the JSON object, which is not
  compliant with the RFC and can cause issues with some carriers.

  To fix this, we now leverage libjansson's ability to dump a JSON
  object sorted by key value, yielding the correct field ordering.

  Additionally, telephone numbers must have any leading + prefix removed
  and must not contain characters outside of 0-9, *, and # in order
  to comply with the RFCs. Numbers are now properly formatted as such.

  ASTERISK-30407 #close


#### pbx_dundi: Add PJSIP support.
  Author: Naveen Albert
  Date:   2022-12-09

  Adds PJSIP as a supported technology to DUNDi.

  To facilitate this, we now allow an endpoint to be specified
  for outgoing PJSIP calls. We also allow users to force a specific
  channel technology for outgoing SIP-protocol calls.

  ASTERISK-28109 #close
  ASTERISK-28233 #close


#### chan_pjsip: fix music on hold continues after INVITE with replaces
  Author: Henning Westerholt
  Date:   2023-03-21

  In a three party scenario with INVITE with replaces, we need to
  unhold the call, otherwise one party continues to get music on
  hold, and the call is not properly bridged between them.

  ASTERISK-30428


#### install_prereq: Add Linux Mint support.
  Author: The_Blode
  Date:   2023-03-17

  ASTERISK-30359 #close


#### voicemail.conf: Fix incorrect comment about #include.
  Author: Naveen Albert
  Date:   2023-03-28

  A comment at the top of voicemail.conf says that #include
  cannot be used in voicemail.conf because this breaks
  the ability for app_voicemail to auto-update passwords.
  This is factually incorrect, since Asterisk has no problem
  updating files that are #include'd in the main configuration
  file, and this does work in voicemail.conf as well.

  ASTERISK-30479 #close


#### app_queue: Fix minor xmldoc duplication and vagueness.
  Author: Naveen Albert
  Date:   2023-04-03

  The F option in the xmldocs for the Queue application
  was erroneously duplicated, causing it to display
  twice on the wiki. The two sections are now merged into one.

  Additionally, the description for the d option was quite
  vague. Some more details are added to provide context
  as to what this actually does.

  ASTERISK-30486 #close


#### test.c: Fix counting of tests and add 2 new tests
  Author: George Joseph
  Date:   2023-03-28

  The unit test XML output was counting all registered tests as "run"
  even when only a subset were actually requested to be run and
  the "failures" attribute was missing.

  * The "tests" attribute of the "testsuite" element in the
    output XML now reflects only the tests actually requested
    to be executed instead of all the tests registered.

  * The "failures" attribute was added to the "testsuite"
    element.

  Also added 2 new unit tests that just pass and fail to be
  used for CI testing.


#### res_pjsip_pubsub: subscription cleanup changes
  Author: Mike Bradeen
  Date:   2023-03-29

  There are two main parts of the change associated with this
  commit. These are driven by the change in call order of
  pubsub_on_rx_refresh and pubsub_on_evsub_state by pjproject
  when an in-dialog SUBSCRIBE is received.

  First, the previous behavior was for pjproject to call
  pubsub_on_rx_refresh before calling pubsub_on_evsub_state
  when an in-dialog SUBSCRIBE was received that changes the
  subscription state.

  If that change was a termination due to a re-SUBSCRIBE with
  an expires of 0, we used to use the call to pubsub_on_rx_refresh
  to set the substate of the evsub to TERMINATE_PENDING before
  pjproject could call pubsub_on_evsub_state.

  This substate let pubsub_on_evsub_state know that the
  subscription TERMINATED event could be ignored as there was
  still a subsequent NOTIFY that needed to be generated and
  another call to pubsub_on_evsub_state to come with it.

  That NOTIFY was sent via serialized_pubsub_on_refresh_timeout
  which would see the TERMINATE_PENDING state and transition it
  to TERMINATE_IN_PROGRESS before triggering another call to
  pubsub_on_evsub_state (which now would clean up the evsub.)

  The new pjproject behavior is to call pubsub_on_evsub_state
  before pubsub_on_rx_refresh. This means we no longer can set
  the state to TERMINATE_PENDING to tell pubsub_on_evsub_state
  that it can ignore the first TERMINATED event.

  To handle this, we now look directly at the event type,
  method type and the expires value to determine whether we
  want to ignore the event or use it to trigger the evsub
  cleanup.

  Second, pjproject now expects the NOTIFY to actually be sent
  during pubsub_on_rx_refresh and avoids the protocol violation
  inherent in sending a NOTIFY before the SUBSCRIBE is
  acknowledged by caching the sent NOTIFY then sending it
  after responding to the SUBSCRIBE.

  This requires we send the NOTIFY using the non-serialized
  pubsub_on_refresh_timeout directly and let pjproject handle
  the protocol violation.

  ASTERISK-30469


#### res_calendar: output busy state as part of show calendar.
  Author: Jaco Kroon
  Date:   2023-03-23

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### ael: Regenerate lexers and parsers.
  Author: Sean Bright
  Date:   2023-03-21

  Various changes to ensure that the lexers and parsers can be correctly
  generated when REBUILD_PARSERS is enabled.

  Some notes:

  * Because of the version of flex we are using to generate the lexers
    (2.5.35) some post-processing in the Makefile is still required.

  * The generated lexers do not contain the problematic C99 check that
    was being replaced by the call to sed in the respective Makefiles so
    it was removed.

  * Since these files are generated, they will include trailing
    whitespace in some places. This does not need to be corrected.


#### loader.c: Minor module key check simplification.
  Author: Sean Bright
  Date:   2023-03-23


#### bridge_builtin_features: add beep via touch variable
  Author: Mike Bradeen
  Date:   2023-03-01

  Add periodic beep option to one-touch recording by setting
  the touch variable TOUCH_MONITOR_BEEP or
  TOUCH_MIXMONITOR_BEEP to the desired interval in seconds.

  If the interval is less than 5 seconds, a minimum of 5
  seconds will be imposed.  If the interval is set to an
  invalid value, it will default to 15 seconds.

  A new test event PERIODIC_HOOK_ENABLED was added to the
  func_periodic_hook hook_on function to indicate when
  a hook is started.  This is so we can test that the touch
  variable starts the hook as expected.

  ASTERISK-30446


#### res_mixmonitor: MixMonitorMute by MixMonitor ID
  Author: Mike Bradeen
  Date:   2023-03-13

  While it is possible to create multiple mixmonitor instances
  on a channel, it was not previously possible to mute individual
  instances.

  This change includes the ability to specify the MixMonitorID
  when calling the manager action: MixMonitorMute.  This will
  allow an individual MixMonitor instance to be muted via id.
  This id can be stored as a channel variable using the 'i'
  MixMonitor option.

  As part of this change, if no MixMonitorID is specified in
  the manager action MixMonitorMute, Asterisk will set the mute
  flag on all MixMonitor spy-type audiohooks on the channel.
  This is done via the new audiohook function:
  ast_audiohook_set_mute_all.

  ASTERISK-30464


#### format_sln: add .slin as supported file extension
  Author: Mike Bradeen
  Date:   2023-03-14

  Adds '.slin' to existing supported file extensions:
  .sln and .raw

  ASTERISK-30465


#### cli: increase channel column width
  Author: Mike Bradeen
  Date:   2023-03-06

  For 'core show channels', the Channel name field is increased
  to 64 characters and the Location name field is increased to
  32 characters.

  For 'core show channels verbose', the Channel name field is
  increased to 80 characters, the Context is increased to 24
  characters and the Extension is increased to 24 characters.

  ASTERISK-30455


#### app_osplookup: Remove obsolete sample config.
  Author: Naveen Albert
  Date:   2023-02-24

  ASTERISK_30302 previously removed app_osplookup,
  but its sample config was not removed.
  This removes it since nothing else uses it.

  ASTERISK-30438 #close


#### func_json: Fix JSON parsing issues.
  Author: Naveen Albert
  Date:   2023-02-26

  Fix issue with returning empty instead of dumping
  the JSON string when recursing.

  Also adds a unit test to capture this fix.

  ASTERISK-30441 #close


#### app_dial: Fix DTMF not relayed to caller on unanswered calls.
  Author: Naveen Albert
  Date:   2023-03-04

  DTMF frames are not handled in app_dial when sent towards the
  caller. This means that if DTMF is sent to the calling party
  and the call has not yet been answered, the DTMF is not audible.
  This is now fixed by relaying DTMF frames if only a single
  destination is being dialed.

  ASTERISK-29516 #close


#### configure: fix detection of re-entrant resolver functions
  Author: Fabrice Fontaine
  Date:   2023-03-08

  uClibc does not provide res_nsearch:
  asterisk-16.0.0/main/dns.c:506: undefined reference to `res_nsearch'

  Patch coded by Yann E. MORIN:
  http://lists.busybox.net/pipermail/buildroot/2018-October/232630.html

  ASTERISK-21795 #close

  Signed-off-by: Bernd Kuhls <bernd.kuhls@t-online.de>
  [Retrieved from:
  https: //git.buildroot.net/buildroot/tree/package/asterisk/0005-configure-fix-detection-of-re-entrant-resolver-funct.patch]
  Signed-off-by: Fabrice Fontaine <fontaine.fabrice@gmail.com>

#### res_agi: RECORD FILE plays 2 beeps.
  Author: Sean Bright
  Date:   2023-03-08

  Sending the "RECORD FILE" command without the optional
  `offset_samples` argument can result in two beeps playing on the
  channel.

  This bug has been present since Asterisk 0.3.0 (2003-02-06).

  ASTERISK-30457 #close


#### app_senddtmf: Add SendFlash AMI action.
  Author: Naveen Albert
  Date:   2023-02-26

  Adds an AMI action to send a flash event
  on a channel.

  ASTERISK-30440 #close


#### http.c: Minor simplification to HTTP status output.
  Author: Boris P. Korzun
  Date:   2023-01-05

  Change the HTTP status page (located at /httpstatus by default) by:

  * Combining the address and port into a single line.
  * Changing "SSL" to "TLS"

  ASTERISK-30433 #close


#### make_version: Strip svn stuff and suppress ref HEAD errors
  Author: George Joseph
  Date:   2023-03-13

  * All of the code that used subversion has been removed.

  * When Asterisk is checked out from a tag or commit instead
    of one of the regular branches, git would emit messages like
    "fatal: ref HEAD is not a symbolic ref" which weren't fatal
    at all.  Those are now suppressed.


#### res_http_media_cache: Introduce options and customize
  Author: Holger Hans Peter Freyther
  Date:   2022-10-16

  Make the existing CURL parameters configurable and allow
  to specify the usable protocols, proxy and DNS timeout.

  ASTERISK-30340


#### contrib: rc.archlinux.asterisk uses invalid redirect.
  Author: Sean Bright
  Date:   2023-03-02

  `rc.archlinux.asterisk`, which explicitly requests bash in its
  shebang, uses the following command syntax:

    ${DAEMON} -rx "core stop now" > /dev/null 2&>1

  The intent of which is to execute:

    ${DAEMON} -rx "core stop now"

  While sending both stdout and stderr to `/dev/null`. Unfortunately,
  because the `&` is in the wrong place, bash is interpreting the `2` as
  just an additional argument to the `$DAEMON` command and not as a file
  descriptor and proceeds to use the bashism `&>` to send stderr and
  stdout to a file named `1`.

  So we clean it up and just use bash's shortcut syntax.

  Issue raised and a fix suggested (but not used) by peutch on GitHub¹.

  ASTERISK-30449 #close

  1. https://github.com/asterisk/asterisk/pull/31


#### main/iostream.c: fix build with libressl
  Author: Fabrice Fontaine
  Date:   2023-02-25

  Fix the following build failure with libressl by using SSL_is_server
  which is available since version 2.7.0 and
  https://github.com/libressl-portable/openbsd/commit/d7ec516916c5eaac29b02d7a8ac6570f63b458f7:

  iostream.c: In function 'ast_iostream_close':
  iostream.c:559:41: error: invalid use of incomplete typedef 'SSL' {aka 'struct ssl_st'}
    559 |                         if (!stream->ssl->server) {
        |                                         ^~

  ASTERISK-30107 #close

  Fixes: - http://autobuild.buildroot.org/results/ce4d62d00bb77ba5b303cacf6be7e350581a62f9

#### res_pjsip: Replace invalid UTF-8 sequences in callerid name
  Author: George Joseph
  Date:   2023-02-16

  * Added a new function ast_utf8_replace_invalid_chars() to
    utf8.c that copies a string replacing any invalid UTF-8
    sequences with the Unicode specified U+FFFD replacement
    character.  For example:  "abc\xffdef" becomes "abc\uFFFDdef".
    Any UTF-8 compliant implementation will show that character
    as a � character.

  * Updated res_pjsip:set_id_from_hdr() to use
    ast_utf8_replace_invalid_chars and print a warning if any
    invalid sequences were found during the copy.

  * Updated stasis_channels:ast_channel_publish_varset to use
    ast_utf8_replace_invalid_chars and print a warning if any
    invalid sequences were found during the copy.

  ASTERISK-27830


#### test.c: Avoid passing -1 to FD_* family of functions.
  Author: Sean Bright
  Date:   2023-02-27

  This avoids buffer overflow errors when running tests that capture
  output from child processes.

  This also corrects a copypasta in an off-nominal error message.


#### chan_iax2: Fix jitterbuffer regression prior to receiving audio.
  Author: Naveen Albert
  Date:   2022-12-14

  ASTERISK_29392 (a security fix) introduced a regression by
  not processing frames when we don't have an audio format.

  Currently, chan_iax2 only calls jb_get to read frames from
  the jitterbuffer when the voiceformat has been set on the pvt.
  However, this only happens when we receive a voice frame, which
  means that prior to receiving voice frames, other types of frames
  get stalled completely in the jitterbuffer.

  To fix this, we now fallback to using the format negotiated during
  call setup until we've actually received a voice frame with a format.
  This ensures we're always able to read from the jitterbuffer.

  ASTERISK-30354 #close
  ASTERISK-30162 #close


#### test_crypto.c: Fix getcwd(…) build error.
  Author: Sean Bright
  Date:   2023-02-27

  `getcwd(…)` is decorated with the `warn_unused_result` attribute and
  therefore needs its return value checked.


#### pjproject_bundled: fix cross-compilation with ssl libs
  Author: Nick French
  Date:   2023-02-11

  Asterisk makefiles auto-detect ssl library availability,
  then they assume that pjproject makefiles will also autodetect
  an ssl library at the same time, so they do not pass on the
  autodetection result to pjproject.

  This normally works, except the pjproject makefiles disables
  autodetection when cross-compiling.

  Fix by explicitly configuring pjproject to use ssl if we
  have been told to use it or it was autodetected

  ASTERISK-30424 #close


#### res_phoneprov.c: Multihomed SERVER cache prevention
  Author: cmaj
  Date:   2023-01-07

  Phones moving between subnets on multi-homed server have their
  initially connected interface IP cached in the SERVER variable,
  even when it is not specified in the configuration files. This
  prevents phones from obtaining the correct SERVER variable value
  when they move to another subnet.

  ASTERISK-30388 #close
  Reported-by: cmaj


#### app_read: Add an option to return terminator on empty digits.
  Author: Mike Bradeen
  Date:   2023-01-30

  Adds 'e' option to allow Read() to return the terminator as the
  dialed digits in the case where only the terminator is entered.

  ie; if "#" is entered, return "#" if the 'e' option is set and ""
  if it is not.

  ASTERISK-30411


#### app_directory: Add a 'skip call' option.
  Author: Mike Bradeen
  Date:   2023-01-27

  Adds 's' option to skip calling the extension and instead set the
  extension as DIRECTORY_EXTEN channel variable.

  ASTERISK-30405


#### app_senddtmf: Add option to answer target channel.
  Author: Mike Bradeen
  Date:   2023-02-06

  Adds a new option to SendDTMF() which will answer the specified
  channel if it is not already up. If no channel is specified, the
  current channel will be answered instead.

  ASTERISK-30422


#### res_pjsip: Prevent SEGV in pjsip_evsub_send_request
  Author: Mike Bradeen
  Date:   2023-02-21

  contributed pjproject - patch to check sub->pending_notify
  in evsub.c:on_tsx_state before calling
  pjsip_evsub_send_request()

  res_pjsip_pubsub - change post pjsip 2.13 behavior to use
  pubsub_on_refresh_timeout to avoid the ao2_cleanup call on
  the sub_tree. This is is because the final NOTIFY send is no
  longer the last place the sub_tree is referenced.

  ASTERISK-30419


#### app_queue: Minor docs and logging fixes for UnpauseQueueMember.
  Author: Sean Bright
  Date:   2023-02-02

  ASTERISK-30417 #close


#### app_queue: Reset all queue defaults before reload.
  Author: Sean Bright
  Date:   2023-01-31

  Several queue fields were not being set to their default value during
  a reload.

  Additionally added some sample configuration options that were missing
  from queues.conf.sample.


#### res_pjsip: Upgraded bundled pjsip to 2.13
  Author: Mike Bradeen
  Date:   2023-01-20

  Removed multiple patches.

  Code chages in res_pjsip_pubsub due to changes in evsub.

  Pjsip now calls on_evsub_state() before on_rx_refresh(),
  so the sub tree deletion that used to take place in
  on_evsub_state() now must take place in on_rx_refresh().

  Additionally, pjsip now requires that you send the NOTIFY
  from within on_rx_refresh(), otherwise it will assert
  when going to send the 200 OK. The idea is that it will
  look for this NOTIFY and cache it until after sending the
  response in order to deal with the self-imposed message
  mis-order. Asterisk previously dealt with this by pushing
  the NOTIFY in on_rx_refresh(), but pjsip now forces us
  to use it's method.

  Changes were required to configure in order to detect
  which way pjsip handles this as the two are not
  compatible for the reasons mentioned above.

  A corresponding change in testsuite is required in order
  to deal with the small interal timing changes caused by
  moving the NOTIFY send.

  ASTERISK-30325


#### doxygen: Fix doxygen errors.
  Author: Sean Bright
  Date:   2023-01-30


#### app_signal: Add signaling applications
  Author: Naveen Albert
  Date:   2022-01-06

  Adds the Signal and WaitForSignal
  applications, which can be used for inter-channel
  signaling in the dialplan.

  Signal supports sending a signal to other channels
  listening for a signal of the same name, with an
  optional data payload. The signal is received by
  all channels waiting for that named signal.

  ASTERISK-29810 #close


#### app_directory: add ability to specify configuration file
  Author: Mike Bradeen
  Date:   2023-01-25

  Adds option to app_directory to specify a filename from which to
  read configuration instead of voicemail.conf ie;

  same => n,Directory(,,c(directory.conf))

  This configuration should contain a list of extensions using the
  voicemail.conf format, ie;

  2020=2020,Dog Dog,,,,attach=no|saycid=no|envelope=no|delete=no

  ASTERISK-30404


#### func_json: Enhance parsing capabilities of JSON_DECODE
  Author: Naveen Albert
  Date:   2022-02-12

  Adds support for arrays to JSON_DECODE by allowing the
  user to print out entire arrays or index a particular
  key or print the number of keys in a JSON array.

  Additionally, adds support for recursively iterating a
  JSON tree in a single function call, making it easier
  to parse JSON results with multiple levels. A maximum
  depth is imposed to prevent potentially blowing
  the stack.

  Also fixes a bug with the unit tests causing an empty
  string to be printed instead of the actual test result.

  ASTERISK-29913 #close


#### res_pjsip_session: Add overlap_context option.
  Author: Naveen Albert
  Date:   2022-10-13

  Adds the overlap_context option, which can be used
  to explicitly specify a context to use for overlap
  dialing extension matches, rather than forcibly
  using the context configured for the endpoint.

  ASTERISK-30262 #close


#### res_stasis_snoop: Fix snoop crash
  Author: sungtae kim
  Date:   2023-01-04

  Added NULL pointer check and channel lock to prevent resource release
  while the chanspy is processing.

  ASTERISK-29604


#### res_monitor: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-18

  ASTERISK-30303


#### app_playback.c: Fix PLAYBACKSTATUS regression.
  Author: Sean Bright
  Date:   2023-01-05

  In Asterisk 11, if a channel was redirected away during Playback(),
  the PLAYBACKSTATUS variable would be set to SUCCESS. In Asterisk 12
  (specifically commit 7d9871b3940fa50e85039aef6a8fb9870a7615b9) that
  behavior was inadvertently changed and the same operation would result
  in the PLAYBACKSTATUS variable being set to FAILED. The Asterisk 11
  behavior has been restored.

  Partial fix for ASTERISK~25661.


#### res_rtp_asterisk: Don't use double math to generate timestamps
  Author: George Joseph
  Date:   2023-01-11

  Rounding issues with double math were causing rtp timestamp
  slips in outgoing packets.  We're now back to integer math
  and are getting no more slips.

  ASTERISK-30391


#### app_macro: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-12-12

  For most modules that interacted with app_macro, this change is limited
  to no longer looking for the current context from the macrocontext when
  set.  Additionally, the following modules are impacted:

  app_dial - no longer supports M^ connected/redirecting macro
  app_minivm - samples written using macro will no longer work.
  The sample needs a re-write

  app_queue - can no longer a macro on the called party's channel.
  Use gosub which is currently supported

  ccss - no callback macro, gosub only

  app_voicemail - no macro support

  channel  - remove macrocontext and priority, no connected line or
  redirection macro options
  options - stdexten is deprecated to gosub as the default and only
  pbx - removed macrolock
  pbx_dundi - no longer look for macro

  snmp - removed macro context, exten, and priority

  ASTERISK-30304


#### format_wav: replace ast_log(LOG_DEBUG, ...) by ast_debug(1, ...)
  Author: Alexei Gradinari
  Date:   2023-01-06

  Each playback of WAV files results in logging
  "Skipping unknown block 'LIST'".

  To prevent unnecessary flooding of this DEBUG log this patch replaces
  ast_log(LOG_DEBUG, ...) by ast_debug(1, ...).


#### res_pjsip_rfc3326: Add SIP causes support for RFC3326
  Author: Igor Goncharovsky
  Date:   2022-11-18

  Add ability to set HANGUPCAUSE when SIP causecode received in BYE (in addition to currently supported Q.850).

  ASTERISK-30319 #close


#### res_rtp_asterisk: Asterisk Media Experience Score (MES)
  Author: George Joseph
  Date:   2022-10-28

  -----------------

  This commit reinstates MES with some casting fixes to the
  functions in time.h that convert between doubles and timeval
  structures.  The casting issues were causing incorrect
  timestamps to be calculated which caused transcoding from/to
  G722 to produce bad or no audio.

  ASTERISK-30391

  -----------------

  This module has been updated to provide additional
  quality statistics in the form of an Asterisk
  Media Experience Score.  The score is avilable using
  the same mechanisms you'd use to retrieve jitter, loss,
  and rtt statistics.  For more information about the
  score and how to retrieve it, see
  https://wiki.asterisk.org/wiki/display/AST/Media+Experience+Score

  * Updated chan_pjsip to set quality channel variables when a
    call ends.
  * Updated channels/pjsip/dialplan_functions.c to add the ability
    to retrieve the MES along with the existing rtcp stats when
    using the CHANNEL dialplan function.
  * Added the ast_debug_rtp_is_allowed and ast_debug_rtcp_is_allowed
    checks for debugging purposes.
  * Added several function to time.h for manipulating time-in-samples
    and times represented as double seconds.
  * Updated rtp_engine.c to pass through the MES when stats are
    requested.  Also debug output that dumps the stats when an
    rtp instance is destroyed.
  * Updated res_rtp_asterisk.c to implement the calculation of the
    MES.  In the process, also had to update the calculation of
    jitter.  Many debugging statements were also changed to be
    more informative.
  * Added a unit test for internal testing.  The test should not be
    run during normal operation and is disabled by default.


#### Revert "res_rtp_asterisk: Asterisk Media Experience Score (MES)"
  Author: George Joseph
  Date:   2023-01-09

  This reverts commit e66c5da145b4545428fca768db7fb0921156af98.

  Reason for revert: Issue when transcoding to/from g722


#### http.c: Fix NULL pointer dereference bug
  Author: Boris P. Korzun
  Date:   2022-12-28

  If native HTTP is disabled but HTTPS is enabled and status page enabled
  too, Core/HTTP crashes while loading. 'global_http_server' references
  to NULL, but the status page tries to dereference it.

  The patch adds a check for HTTP is enabled.

  ASTERISK-30379 #close


#### loader: Allow declined modules to be unloaded.
  Author: Naveen Albert
  Date:   2022-12-08

  Currently, if a module declines to load, dlopen is called
  to register the module but dlclose never gets called.
  Furthermore, loader.c currently doesn't allow dlclose
  to ever get called on the module, since it declined to
  load and the unload function bails early in this case.

  This can be problematic if a module is updated, since the
  new module cannot be loaded into memory since we haven't
  closed all references to it. To fix this, we now allow
  modules to be unloaded, even if they never "loaded" in
  Asterisk itself, so that dlclose is called and the module
  can be properly cleaned up, allowing the updated module
  to be loaded from scratch next time.

  ASTERISK-30345 #close


#### app_broadcast: Add Broadcast application
  Author: Naveen Albert
  Date:   2022-08-15

  Adds a new application, Broadcast, which can be used for
  one-to-many transmission and many-to-one reception of
  channel audio in Asterisk. This is similar to ChanSpy,
  except it is designed for multiple channel targets instead
  of a single one. This can make certain kinds of audio
  manipulation more efficient and streamlined. New kinds
  of audio injection impossible with ChanSpy are also made
  possible.

  ASTERISK-30180 #close


#### func_frame_trace: Print text for text frames.
  Author: Naveen Albert
  Date:   2022-12-13

  Since text frames contain a text body, make FRAME_TRACE
  more useful for text frames by actually printing the text.

  ASTERISK-30353 #close


#### app_cdr: Remove deprecated application and option.
  Author: Naveen Albert
  Date:   2022-12-22

  This removes the deprecated NoCDR application, which
  was deprecated in Asterisk 12, having long been fully
  superseded by the CDR_PROP function.

  The deprecated e option to ResetCDR is also removed
  for the same reason.

  ASTERISK-30371 #close


#### res_http_media_cache: Do not crash when there is no extension
  Author: Holger Hans Peter Freyther
  Date:   2022-12-16

  Do not crash when a URL has no path component as in this case the
  ast_uri_path function will return NULL. Make the code cope with not
  having a path.

  The below would crash
  > media cache create http://google.com /tmp/foo.wav

  Thread 1 "asterisk" received signal SIGSEGV, Segmentation fault.
  0x0000ffff836616cc in strrchr () from /lib/aarch64-linux-gnu/libc.so.6
  (gdb) bt
   #0  0x0000ffff836616cc in strrchr () from /lib/aarch64-linux-gnu/libc.so.6
   #1  0x0000ffff43d43a78 in file_extension_from_string (str=<optimized out>, buffer=buffer@entry=0xffffca9973c0 "",
      capacity=capacity@entry=64) at res_http_media_cache.c:288
   #2  0x0000ffff43d43bac in file_extension_from_url_path (bucket_file=bucket_file@entry=0x3bf96568,
      buffer=buffer@entry=0xffffca9973c0 "", capacity=capacity@entry=64) at res_http_media_cache.c:378
   #3  0x0000ffff43d43c74 in bucket_file_set_extension (bucket_file=bucket_file@entry=0x3bf96568) at res_http_media_cache.c:392
   #4  0x0000ffff43d43d10 in bucket_file_run_curl (bucket_file=0x3bf96568) at res_http_media_cache.c:555
   #5  0x0000ffff43d43f74 in bucket_http_wizard_create (sorcery=<optimized out>, data=<optimized out>, object=<optimized out>)
      at res_http_media_cache.c:613
   #6  0x0000000000487638 in bucket_file_wizard_create (sorcery=<optimized out>, data=<optimized out>, object=<optimized out>)
      at bucket.c:191
   #7  0x0000000000554408 in sorcery_wizard_create (object_wizard=object_wizard@entry=0x3b9f0718,
      details=details@entry=0xffffca9974a8) at sorcery.c:2027
   #8  0x0000000000559698 in ast_sorcery_create (sorcery=<optimized out>, object=object@entry=0x3bf96568) at sorcery.c:2077
   #9  0x00000000004893a4 in ast_bucket_file_create (file=file@entry=0x3bf96568) at bucket.c:727
   #10 0x00000000004f877c in ast_media_cache_create_or_update (uri=0x3bfa1103 "https://google.com",
      file_path=0x3bfa1116 "/tmp/foo.wav", metadata=metadata@entry=0x0) at media_cache.c:335
   #11 0x00000000004f88ec in media_cache_handle_create_item (e=<optimized out>, cmd=<optimized out>, a=0xffffca9976b8)
      at media_cache.c:640

  ASTERISK-30375 #close


#### manager: Fix appending variables.
  Author: Naveen Albert
  Date:   2022-12-22

  The if statement here is always false after the for
  loop finishes, so variables are never appended.
  This removes that to properly append to the end
  of the variable list.

  ASTERISK-30351 #close
  Reported by: Sebastian Gutierrez


#### json.h: Add ast_json_object_real_get.
  Author: Naveen Albert
  Date:   2022-12-16

  json.h contains macros to get a string and an integer
  from a JSON object. However, the macro to do this for
  JSON reals is missing. This adds that.

  ASTERISK-30361 #close


#### res_pjsip_transport_websocket: Add remote port to transport
  Author: George Joseph
  Date:   2022-12-23

  When Asterisk receives a new websocket conenction, it creates a new
  pjsip transport for it and copies connection data into it.  The
  transport manager then uses the remote IP address and port on the
  transport to create a monitor for each connection.  However, the
  remote port wasn't being copied, only the IP address which meant
  that the transport manager was creating only 1 monitoring entry for
  all websocket connections from the same IP address. Therefore, if
  one of those connections failed, it deleted the transport taking
  all the the connections from that same IP address with it.

  * We now copy the remote port into the created transport and the
    transport manager behaves correctly.

  ASTERISK-30369


#### chan_sip: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-28

  ASTERISK-30297


#### res_rtp_asterisk: Asterisk Media Experience Score (MES)
  Author: George Joseph
  Date:   2022-10-28

  This module has been updated to provide additional
  quality statistics in the form of an Asterisk
  Media Experience Score.  The score is avilable using
  the same mechanisms you'd use to retrieve jitter, loss,
  and rtt statistics.  For more information about the
  score and how to retrieve it, see
  https://wiki.asterisk.org/wiki/display/AST/Media+Experience+Score

  * Updated chan_pjsip to set quality channel variables when a
    call ends.
  * Updated channels/pjsip/dialplan_functions.c to add the ability
    to retrieve the MES along with the existing rtcp stats when
    using the CHANNEL dialplan function.
  * Added the ast_debug_rtp_is_allowed and ast_debug_rtcp_is_allowed
    checks for debugging purposes.
  * Added several function to time.h for manipulating time-in-samples
    and times represented as double seconds.
  * Updated rtp_engine.c to pass through the MES when stats are
    requested.  Also debug output that dumps the stats when an
    rtp instance is destroyed.
  * Updated res_rtp_asterisk.c to implement the calculation of the
    MES.  In the process, also had to update the calculation of
    jitter.  Many debugging statements were also changed to be
    more informative.
  * Added a unit test for internal testing.  The test should not be
    run during normal operation and is disabled by default.

  ASTERISK-30280


#### pbx_app: Update outdated pbx_exec channel snapshots.
  Author: Naveen Albert
  Date:   2022-12-21

  pbx_exec makes a channel snapshot before executing applications.
  This doesn't cause an issue during normal dialplan execution
  where pbx_exec is called over and over again in succession.
  However, if pbx_exec is called "one off", e.g. using
  ast_pbx_exec_application, then a channel snapshot never ends
  up getting made after the executed application returns, and
  inaccurate snapshot information will linger for a while, causing
  "core show channels", etc. to show erroneous info.

  This is fixed by manually making a channel snapshot at the end
  of ast_pbx_exec_application, since we anticipate that pbx_exec
  might not get called again immediately.

  ASTERISK-30367 #close


#### res_pjsip_session: Use Caller ID for extension matching.
  Author: Naveen Albert
  Date:   2022-11-26

  Currently, there is no Caller ID available to us when
  checking for an extension match when handling INVITEs.
  As a result, extension patterns that depend on the Caller ID
  are not matched and calls may be incorrectly rejected.

  The Caller ID is not available because the supplement that
  adds Caller ID to the session does not execute until after
  this check. Supplement callbacks cannot yet be executed
  at this point since the session is not yet in the appropriate
  state.

  To fix this without impacting existing behavior, the Caller ID
  number is now retrieved before attempting to pattern match.
  This ensures pattern matching works correctly and there is
  no behavior change to the way supplements are called.

  ASTERISK-28767 #close


#### pbx_builtins: Remove deprecated and defunct functionality.
  Author: Naveen Albert
  Date:   2022-11-29

  This removes the ImportVar and SetAMAFlags applications
  which have been deprecated since Asterisk 12, but were
  never removed previously.

  Additionally, it removes remnants of defunct options
  that themselves were removed years ago.

  ASTERISK-30335 #close


#### res_pjsip_sdp_rtp.c: Use correct timeout when put on hold.
  Author: Ben Ford
  Date:   2022-12-12

  When a call is put on hold and it has moh_passthrough and rtp_timeout
  set on the endpoint, the wrong timeout will be used. rtp_timeout_hold is
  expected to be used, but rtp_timeout is used instead. This change adds a
  couple of checks for locally_held to determine if rtp_timeout_hold needs
  to be used instead of rtp_timeout.

  ASTERISK-30350


#### app_voicemail_odbc: Fix string overflow warning.
  Author: Naveen Albert
  Date:   2022-11-14

  Fixes a negative offset warning by initializing
  the buffer to empty.

  Additionally, although it doesn't currently complain
  about it, the size of a buffer is increased to
  accomodate the maximum size contents it could have.

  ASTERISK-30240 #close


#### streams:  Ensure that stream is closed in ast_stream_and_wait on error
  Author: Peter Fern
  Date:   2022-11-22

  When ast_stream_and_wait returns an error (for example, when attempting
  to stream to a channel after hangup) the stream is not closed, and
  callers typically do not check the return code. This results in leaking
  file descriptors, leading to resource exhaustion.

  This change ensures that the stream is closed in case of error.

  ASTERISK-30198 #close
  Reported-by: Julien Alie


#### func_callerid: Warn about invalid redirecting reason.
  Author: Naveen Albert
  Date:   2022-11-26

  Currently, if a user attempts to set a Caller ID related
  function to an invalid value, a warning is emitted,
  except for when setting the redirecting reason.
  We now emit a warning if we were unable to successfully
  parse the user-provided reason.

  ASTERISK-30332 #close


#### app_sendtext: Remove references to removed applications.
  Author: Naveen Albert
  Date:   2022-12-10

  Removes see-also references to applications that don't
  exist anymore (removed in Asterisk 19),
  so these dead links don't show up on the wiki.

  ASTERISK-30347 #close


#### res_pjsip: Fix path usage in case dialing with '@'
  Author: Igor Goncharovsky
  Date:   2022-11-04

  Fix aor lookup on sip path addition. Issue happens in case of dialing
  with @ and overriding user part of RURI.

  ASTERISK-30100 #close
  Reported-by: Yury Kirsanov


#### res_geoloc: fix NULL pointer dereference bug
  Author: Alexandre Fournier
  Date:   2022-12-09

  The `ast_geoloc_datastore_add_eprofile` function does not return 0 on
  success, it returns the size of the underlying datastore. This means
  that the datastore will be freed and its pointer set to NULL when no
  error occured at all.

  ASTERISK-30346


#### res_pjsip_aoc: Don't assume a body exists on responses.
  Author: Joshua C. Colp
  Date:   2022-12-13

  When adding AOC to an outgoing response the code
  assumed that a body would exist for comparing the
  Content-Type. This isn't always true.

  The code now checks to make sure the response has
  a body before checking the Content-Type.

  ASTERISK-21502


#### app_if: Fix format truncation errors.
  Author: Naveen Albert
  Date:   2022-12-12

  Fixes format truncation warnings in gcc 12.2.1.

  ASTERISK-30349 #close


#### chan_alsa: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-14

  ASTERISK-30298


#### manager: AOC-S support for AOCMessage
  Author: Michael Kuron
  Date:   2022-11-01

  ASTERISK-21502


#### chan_mgcp: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-15

  Also removes res_pktcops to avoid merge conflicts
  with ASTERISK~30301.

  ASTERISK-30299


#### res_pjsip_aoc: New module for sending advice-of-charge with chan_pjsip
  Author: Michael Kuron
  Date:   2022-10-23

  chan_sip supported sending AOC-D and AOC-E information in SIP INFO
  messages in an "AOC" header in a format that was originally defined by
  Snom. In the meantime, ETSI TS 124 647 introduced an XML-based AOC
  format that is supported by devices from multiple vendors, including
  Snom phones with firmware >= 8.4.2 (released in 2010).

  This commit adds a new res_pjsip_aoc module that inserts AOC information
  into outgoing messages or sends SIP INFO messages as described below.
  It also fixes a small issue in res_pjsip_session which didn't always
  call session supplements on outgoing_response.

  * AOC-S in the 180/183/200 responses to an INVITE request
  * AOC-S in SIP INFO (if a 200 response has already been sent or if the
    INVITE was sent by Asterisk)
  * AOC-D in SIP INFO
  * AOC-D in the 200 response to a BYE request (if the client hangs up)
  * AOC-D in a BYE request (if Asterisk hangs up)
  * AOC-E in the 200 response to a BYE request (if the client hangs up)
  * AOC-E in a BYE request (if Asterisk hangs up)

  The specification defines one more, AOC-S in an INVITE request, which
  is not implemented here because it is not currently possible in
  Asterisk to have AOC data ready at this point in call setup. Once
  specifying AOC-S via the dialplan or passing it through from another
  SIP channel's INVITE is possible, that might be added.

  The SIP INFO requests are sent out immediately when the AOC indication
  is received. The others are inserted into an appropriate outgoing
  message whenever that is ready to be sent. In the latter case, the XML
  is stored in a channel variable at the time the AOC indication is
  received. Depending on where the AOC indications are coming from (e.g.
  PRI or AMI), it may not always be possible to guarantee that the AOC-E
  is available in time for the BYE.

  Successfully tested AOC-D and both variants of AOC-E with a Snom D735
  running firmware 10.1.127.10. It does not appear to properly support
  AOC-S however, so that could only be tested by inspecting SIP traces.

  ASTERISK-21502 #close
  Reported-by: Matt Jordan <mjordan@digium.com>


#### res_hep: Add support for named capture agents.
  Author: Naveen Albert
  Date:   2022-11-21

  Adds support for the capture agent name field
  of the Homer protocol to Asterisk by allowing
  users to specify a name that will be sent to
  the HEP server.

  ASTERISK-30322 #close


#### res_pjsip: Fix typo in from_domain documentation
  Author: Marcel Wagner
  Date:   2022-11-25

  This fixes a small typo in the from_domain documentation on the endpoint documentation

  ASTERISK-30328 #close


#### app_if: Adds conditional branch applications
  Author: Naveen Albert
  Date:   2021-06-28

  Adds the If, ElseIf, Else, ExitIf, and EndIf
  applications for conditional execution
  of a block of dialplan, similar to the While,
  EndWhile, and ExitWhile applications. The
  appropriate branch is executed at most once
  if available and may be broken out of while
  inside.

  ASTERISK-29497


#### res_pjsip_session.c: Map empty extensions in INVITEs to s.
  Author: Naveen Albert
  Date:   2022-10-17

  Some SIP devices use an empty extension for PLAR functionality.

  Rather than rejecting these empty extensions, we now use the s
  extension for such calls to mirror the existing PLAR functionality
  in Asterisk (e.g. chan_dahdi).

  ASTERISK-30265 #close


#### res_pjsip: Update contact_user to point out default
  Author: Marcel Wagner
  Date:   2022-11-17

  Updates the documentation for the 'contact_user' field to point out the
  default outbound contact if no contact_user is specified 's'

  ASTERISK-30316 #close


#### res_pjsip_header_funcs: Add custom parameter support.
  Author: Naveen Albert
  Date:   2022-07-21

  Adds support for custom URI and header parameters
  in the From header in PJSIP. Parameters can be
  both set and read using this function.

  ASTERISK-30150 #close


#### app_voicemail: Fix missing email in msg_create_from_file.
  Author: Naveen Albert
  Date:   2022-11-03

  msg_create_from_file currently does not dispatch emails,
  which means that applications using this function, such
  as MixMonitor, will not trigger notifications to users
  (only AMI events are sent our currently). This is inconsistent
  with other ways users can receive voicemail.

  This is fixed by adding an option that attempts to send
  an email and falling back to just the notifications as
  done now if that fails. The existing behavior remains
  the default.

  ASTERISK-30283 #close


#### ari: Destroy body variables in channel create.
  Author: Joshua C. Colp
  Date:   2022-12-08

  When passing a JSON body to the 'create' channel route
  it would be converted into Asterisk variables, but never
  freed resulting in a memory leak.

  This change makes it so that the variables are freed in
  all cases.

  ASTERISK-30344


#### res_adsi: Fix major regression caused by media format rearchitecture.
  Author: Naveen Albert
  Date:   2022-11-23

  The commit that rearchitected media formats,
  a2c912e9972c91973ea66902d217746133f96026 (ASTERISK_23114)
  introduced a regression by improperly translating code in res_adsi.c.
  In particular, the pointer to the frame buffer was initialized
  at the top of adsi_careful_send, rather than dynamically updating it
  for each frame, as is required.

  This resulted in the first frame being repeatedly sent,
  rather than advancing through the frames.
  This corrupted the transmission of the CAS to the CPE,
  which meant that CPE would never respond with the DTMF acknowledgment,
  effectively completely breaking ADSI functionality.

  This issue is now fixed, and ADSI now works properly again.

  ASTERISK-29793 #close


#### func_presencestate: Fix invalid memory access.
  Author: Naveen Albert
  Date:   2022-11-13

  When parsing information from AstDB while loading,
  it is possible that certain pointers are never
  set, which leads to invalid memory access and
  then, fatally, invalid free attempts on this memory.
  We now initialize to NULL to prevent this.

  ASTERISK-30311 #close


#### sig_analog: Fix no timeout duration.
  Author: Naveen Albert
  Date:   2022-12-01

  ASTERISK_28702 previously attempted to fix an
  issue with flash hook hold timing out after
  just under 17 minutes, when it should have never
  been timing out. It fixed this by changing 999999
  to INT_MAX, but it did so in chan_dahdi, which
  is the wrong place since ss_thread is now in
  sig_analog and the one in chan_dahdi is mostly
  dead code.

  This fixes this by porting the fix to sig_analog.

  ASTERISK-30336 #close


#### xmldoc: Allow XML docs to be reloaded.
  Author: Naveen Albert
  Date:   2022-11-05

  The XML docs are currently only loaded on
  startup with no way to update them during runtime.
  This makes it impossible to load modules that
  use ACO/Sorcery (which require documentation)
  if they are added to the source tree and built while
  Asterisk is running (e.g. external modules).

  This adds a CLI command to reload the XML docs
  during runtime so that documentation can be updated
  without a full restart of Asterisk.

  ASTERISK-30289 #close


#### rtp_engine.h: Update examples using ast_format_set.
  Author: Naveen Albert
  Date:   2022-11-24

  This file includes some doxygen comments referencing
  ast_format_set. This is an obsolete API that was
  removed years back, but documentation was not fully
  updated to reflect that. These examples are
  updated to the current way of doing things
  (using the format cache).

  ASTERISK-30327 #close


#### app_osplookup: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-18

  ASTERISK-30302


#### chan_skinny: Remove deprecated module.
  Author: Mike Bradeen
  Date:   2022-11-16

  ASTERISK-30300


#### app_mixmonitor: Add option to use real Caller ID for voicemail.
  Author: Naveen Albert
  Date:   2022-11-04

  MixMonitor currently uses the Connected Line as the Caller ID
  for voicemails. This is due to the implementation being written
  this way for use with Digium phones. However, in general this
  is not correct for generic usage in the dialplan, and people
  may need the real Caller ID instead. This adds an option to do that.

  ASTERISK-30286 #close


#### manager: prevent file access outside of config dir
  Author: Mike Bradeen
  Date:   2022-10-03

  Add live_dangerously flag to manager and use this flag to
  determine if a configuation file outside of AST_CONFIG_DIR
  should be read.

  ASTERISK-30176


#### pjsip_transport_events: Fix possible use after free on transport
  Author: George Joseph
  Date:   2022-10-10

  It was possible for a module that registered for transport monitor
  events to pass in a pjsip_transport that had already been freed.
  This caused pjsip_transport_events to crash when looking up the
  monitor for the transport.  The fix is a two pronged approach.

  1. We now increment the reference count on pjsip_transports when we
  create monitors for them, then decrement the count when the
  transport is going to be destroyed.

  2. There are now APIs to register and unregister monitor callbacks
  by "transport key" which is a string concatenation of the remote ip
  address and port.  This way the module needing to monitor the
  transport doesn't have to hold on to the transport object itself to
  unregister.  It just has to save the transport_key.

  * Added the pjsip_transport reference increment and decrement.

  * Changed the internal transport monitor container key from the
    transport->obj_name (which may not be unique anyway) to the
    transport_key.

  * Added a helper macro AST_SIP_MAKE_REMOTE_IPADDR_PORT_STR() that
    fills a buffer with the transport_key using a passed-in
    pjsip_transport.

  * Added the following functions:
    ast_sip_transport_monitor_register_key
    ast_sip_transport_monitor_register_replace_key
    ast_sip_transport_monitor_unregister_key
    and marked their non-key counterparts as deprecated.

  * Updated res_pjsip_pubsub and res_pjsip_outbound_register to use
    the new "key" monitor functions.

  NOTE: res_pjsip_registrar also uses the transport monitor
  functionality but doesn't have a persistent object other than
  contact to store a transport key.  At this time, it continues to
  use the non-key monitor functions.

  ASTERISK-30244


#### pjproject: 2.13 security fixes
  Author: Ben Ford
  Date:   2022-11-29

  Backports two security fixes (c4d3498 and 450baca) from pjproject 2.13.

  ASTERISK-30338


#### pbx_builtins: Allow Answer to return immediately.
  Author: Naveen Albert
  Date:   2022-11-11

  The Answer application currently waits for up to 500ms
  for media, even if users specify a different timeout.

  This adds an option to not wait for media on the channel
  by doing a raw answer instead. The default 500ms threshold
  is also documented.

  ASTERISK-30308 #close


#### chan_dahdi: Allow FXO channels to start immediately.
  Author: Naveen Albert
  Date:   2022-11-11

  Currently, chan_dahdi will wait for at least one
  ring before an incoming call can enter the dialplan.
  This is generally necessary in order to receive
  the Caller ID spill and/or distinctive ringing
  detection.

  However, if neither of these is required, then there
  is nothing gained by waiting for one ring and this
  unnecessarily delays call setup. Users can now
  use immediate=yes to make FXO channels (FXS signaled)
  begin processing dialplan as soon as Asterisk receives
  the call.

  ASTERISK-30305 #close


#### sla: Prevent deadlock and crash due to autoservicing.
  Author: Naveen Albert
  Date:   2022-09-24

  SLAStation currently autoservices the station channel before
  creating a thread to actually dial the trunk. This leads
  to duplicate servicing of the channel which causes assertions,
  deadlocks, crashes, and moreover not the correct behavior.

  Removing the autoservice prevents the crash, but if the station
  hangs up before the trunk answers, the call hangs since the hangup
  was never serviced on the channel.

  This is fixed by not autoservicing the channel, but instead
  servicing it in the thread dialing the trunk, since it is doing
  so synchronously to begin with. Instead of sleeping for 100ms
  in a loop, we simply use the channel for timing, and abort
  if it disappears.

  The same issue also occurs with SLATrunk when a call is answered,
  because ast_answer invokes ast_waitfor_nandfds. Thus, we use
  ast_raw_answer instead which does not cause any conflict and allows
  the call to be answered normally without thread blocking issues.

  ASTERISK-29998 #close


#### Build system: Avoid executable stack.
  Author: Jaco Kroon
  Date:   2022-11-07

  Found in res_geolocation, but I believe others may have similar issues,
  thus not linking to a specific issue.

  Essentially gcc doesn't mark the stack for being non-executable unless
  it's compiling the source, this informs ld via gcc to mark the object as
  not requiring an executable stack (which a binary blob obviously
  doesn't).

  ASTERISK-30321

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### func_json: Fix memory leak.
  Author: Naveen Albert
  Date:   2022-11-10

  A memory leak was present in func_json due to
  using ast_json_free, which just calls ast_free,
  as opposed to recursively freeing the JSON
  object as needed. This is now fixed to use the
  right free functions.

  ASTERISK-30293 #close


#### test_json: Remove duplicated static function.
  Author: Naveen Albert
  Date:   2022-11-10

  Removes the function mkstemp_file and uses
  ast_file_mkftemp from file.h instead.

  ASTERISK-30295 #close


#### res_agi: Respect "transmit_silence" option for "RECORD FILE".
  Author: Joshua C. Colp
  Date:   2022-11-16

  The "RECORD FILE" command in res_agi has its own
  implementation for actually doing the recording. This
  has resulted in it not actually obeying the option
  "transmit_silence" when recording.

  This change causes it to now send silence if the
  option is enabled.

  ASTERISK-30314


#### file.c: Don't emit warnings on winks.
  Author: Naveen Albert
  Date:   2022-11-06

  Adds an ignore case for wink since it should
  pass through with no warning.

  ASTERISK-30290 #close


#### app_mixmonitor: Add option to delete files on exit.
  Author: Naveen Albert
  Date:   2022-11-03

  Adds an option that allows MixMonitor to delete
  its copy of any recording files before exiting.

  This can be handy in conjunction with options
  like m, which copy the file elsewhere, and the
  original files may no longer be needed.

  ASTERISK-30284 #close


#### translate.c: Prefer better codecs upon translate ties.
  Author: Naveen Albert
  Date:   2021-05-27

  If multiple codecs are available for the same
  resource and the translation costs between
  multiple codecs are the same, ties are
  currently broken arbitrarily, which means a
  lower quality codec would be used. This forces
  Asterisk to explicitly use the higher quality
  codec, ceteris paribus.

  ASTERISK-29455


#### manager: Update ModuleCheck documentation.
  Author: Naveen Albert
  Date:   2022-11-03

  The ModuleCheck XML documentation falsely
  claims that the module's version number is returned.
  This has not been the case since 14, since the version
  number is not available anymore, but the documentation
  was not changed at the time. It is now updated to
  reflect this.

  ASTERISK-30285 #close


#### runUnittests.sh:  Save coredumps to proper directory
  Author: George Joseph
  Date:   2022-11-02

  Fixed the specification of "outputdir" when calling ast_coredumper
  so the txt files are saved in the correct place.

  ASTERISK-30282


#### chan_rtp: Make usage of ast_rtp_instance_get_local_address clearer
  Author: George Joseph
  Date:   2022-11-02

  unicast_rtp_request() was setting the channel variables like this:

  pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_ADDRESS",
      ast_sockaddr_stringify_addr(&local_address));
  ast_rtp_instance_get_local_address(instance, &local_address);
  pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_PORT",
      ast_sockaddr_stringify_port(&local_address));

  ...which made it appear that UNICASTRTP_LOCAL_ADDRESS was being
  set before local_address was set.  In fact, the address part of
  local_address was set earlier in the function, just not the port.
  This was confusing however so ast_rtp_instance_get_local_address()
  is now being called before setting UNICASTRTP_LOCAL_ADDRESS.

  ASTERISK-30281


#### res_pjsip: prevent crash on websocket disconnect
  Author: Mike Bradeen
  Date:   2022-10-13

  When a websocket (or potentially any stateful connection) is quickly
  created then destroyed, it is possible that the qualify thread will
  destroy the transaction before the initialzing thread is finished
  with it.

  Depending on the timing, this can cause an assertion within pjsip.

  To prevent this, ast_send_stateful_response will now create the group
  lock and add a reference to it before creating the transaction.

  While this should resolve the crash, there is still the potential that
  the contact will not be cleaned up properly, see:ASTERISK~29286. As a
  result, the contact has to 'time out' before it will be removed.

  ASTERISK-28689


#### tcptls: Prevent crash when freeing OpenSSL errors.
  Author: Naveen Albert
  Date:   2022-10-27

  write_openssl_error_to_log has been erroneously
  using ast_free instead of free, which will
  cause a crash when MALLOC_DEBUG is enabled since
  the memory was not allocated by Asterisk's memory
  manager. This changes it to use the actual free
  function directly to avoid this.

  ASTERISK-30278 #close


#### res_pjsip_outbound_registration: Allow to use multiple proxies for registration
  Author: Igor Goncharovsky
  Date:   2022-09-09

  Current registration code use pjsip_parse_uri to verify outbound_proxy
  that is different from the reading this option for the endpoint. This
  made value with multiple proxies invalid for registration pjsip settings.
  Removing URI validation helps to use registration through multiple proxies.

  ASTERISK-30217 #close


#### tests: Fix compilation errors on 32-bit.
  Author: Naveen Albert
  Date:   2022-10-23

  Fix compilation errors caused by using size_t
  instead of uintmax_t and non-portable format
  specifiers.

  ASTERISK-30273 #close


#### res_pjsip: return all codecs on a re-INVITE without SDP
  Author: Henning Westerholt
  Date:   2022-08-26

  Currently chan_pjsip on receiving a re-INVITE without SDP will only
  return the codecs that are previously negotiated and not offering
  all enabled codecs.

  This causes interoperability issues with different equipment (e.g.
  from Cisco) for some of our customers and probably also in other
  scenarios involving 3PCC infrastructure.

  According to RFC 3261, section 14.2 we SHOULD return all codecs
  on a re-INVITE without SDP

  The PR proposes a new parameter to configure this behaviour:
  all_codecs_on_empty_reinvite. It includes the code, documentation,
  alembic migrations, CHANGES file and example configuration additions.

  ASTERISK-30193 #close


#### res_pjsip_notify: Add option support for AMI.
  Author: Naveen Albert
  Date:   2022-10-14

  The PJSIP notify CLI commands allow for using
  "options" configured in pjsip_notify.conf.

  This allows these same options to be used in
  AMI actions as well.

  Additionally, as part of this improvement,
  some repetitive common code is refactored.

  ASTERISK-30263 #close


#### res_pjsip_logger: Add method-based logging option.
  Author: Naveen Albert
  Date:   2022-07-21

  Expands the pjsip logger to support the ability to filter
  by SIP message method. This can make certain types of SIP debugging
  easier by only logging messages of particular method(s).

  ASTERISK-30146 #close

  Co-authored-by: Sean Bright <sean@seanbright.com>

#### Dialing API: Cancel a running async thread, may not cancel all calls
  Author: Frederic LE FOLL
  Date:   2022-10-06

  race condition: ast_dial_join() may not cancel outgoing call, if
  function is called just after called party answer and before
  application execution (bit is_running_app not yet set).

  This fix adds ast_softhangup() calls in addition to existing
  pthread_kill() when is_running_app is not set.

  ASTERISK-30258


#### chan_dahdi: Fix unavailable channels returning busy.
  Author: Naveen Albert
  Date:   2022-10-23

  This fixes dahdi_request to properly set the cause
  code to CONGESTION instead of BUSY if no channels
  were actually available.

  Currently, the cause is erroneously set to busy
  if the channel itself is found, regardless of its
  current state. However, if the channel is not available
  (e.g. T1 down, card not operable, etc.), then the
  channel itself may not be in a functional state,
  in which case CHANUNAVAIL is the correct cause to use.

  This adds a simple check to ensure that busy tone
  is only returned if a channel is encountered that
  has an owner, since that is the only possible way
  that a channel could actually be busy.

  ASTERISK-30274 #close


#### res_pjsip_pubsub: Prevent removing subscriptions.
  Author: Naveen Albert
  Date:   2022-10-16

  pjproject does not provide any mechanism of removing
  event packages, which means that once a subscription
  handler is registered, it is effectively permanent.

  pjproject will assert if the same event package is
  ever registered again, so currently unloading and
  loading any Asterisk modules that use subscriptions
  will cause a crash that is beyond our control.

  For that reason, we now prevent users from being
  able to unload these modules, to prevent them
  from ever being loaded twice.

  ASTERISK-30264 #close


#### say: Don't prepend ampersand erroneously.
  Author: Naveen Albert
  Date:   2022-09-28

  Some logic in say.c for determining if we need
  to also add an ampersand for file seperation was faulty,
  as non-successful files would increment the count, causing
  a leading ampersand to be added improperly.

  This is fixed, and a unit test that captures this regression
  is also added.

  ASTERISK-30248 #close


#### res_crypto: handle unsafe private key files
  Author: Philip Prindeville
  Date:   2022-09-16

  ASTERISK-30213 #close


#### audiohook: add directional awareness
  Author: Mike Bradeen
  Date:   2022-09-29

  Add enum to allow setting optional direction. If set to only one
  direction, only feed matching-direction frames to the associated
  slin factory.

  This prevents mangling the transcoder on non-mixed frames when the
  READ and WRITE frames would have otherwise required it.  Also
  removes the need to mute or discard the un-wanted frames as they
  are no longer added in the first place.

  res_stasis_snoop is changed to use this addition to set direction
  on audiohook based on spy direction.

  If no direction is set, the ast_audiohook_init will init this enum
  to BOTH which maintains existing functionality.

  ASTERISK-30252


#### cdr: Allow bridging and dial state changes to be ignored.
  Author: Naveen Albert
  Date:   2022-06-01

  Allows bridging, parking, and dial messages to be globally
  ignored for all CDRs such that only a single CDR record
  is generated per channel.

  This is useful when CDRs should endure for the lifetime of
  an entire channel and bridging and dial updates in the
  dialplan should not result in multiple CDR records being
  created for the call. With the ignore bridging option,
  bridging changes have no impact on the channel's CDRs.
  With the ignore dial state option, multiple Dials and their
  outcomes have no impact on the channel's CDRs. The
  last disposition on the channel is preserved in the CDR,
  so the actual disposition of the call remains available.

  These two options can reduce the amount of "CDR hacks" that
  have hitherto been necessary to ensure that CDR was not
  "spoiled" by these messages if that was undesired, such as
  putting a dummy optimization-disabled local channel between
  the caller and the actual call and putting the CDR on the channel
  in the middle to ensure that CDR would persist for the entire
  call and properly record start, answer, and end times.
  Enabling these options is desirable when calls correspond
  to the entire lifetime of channels and the CDR should
  reflect that.

  Current default behavior remains unchanged.

  ASTERISK-30091 #close


#### res_tonedetect: Add ringback support to TONE_DETECT.
  Author: Naveen Albert
  Date:   2022-09-30

  Adds support for detecting audible ringback tone
  to the TONE_DETECT function using the p option.

  ASTERISK-30254 #close


#### chan_dahdi: Resolve format truncation warning.
  Author: Naveen Albert
  Date:   2022-10-01

  Fixes a format truncation warning in notify_message.

  ASTERISK-30256 #close


#### res_crypto: don't modify fname in try_load_key()
  Author: Philip Prindeville
  Date:   2022-09-16

  "fname" is passed in as a const char *, but strstr() mangles that
  into a char *, and we were attempting to modify the string in place.
  This is an unwanted (and undocumented) side-effect.

  ASTERISK-30213


#### res_crypto: use ast_file_read_dirs() to iterate
  Author: Philip Prindeville
  Date:   2022-09-15

  ASTERISK-30213


#### res_geolocation: Update wiki documentation
  Author: George Joseph
  Date:   2022-09-27

  Also added a note to the geolocation.conf.sample file
  and added a README to the res/res_geolocation/wiki
  directory.


#### res_pjsip: Add mediasec capabilities.
  Author: Maximilian Fridrich
  Date:   2022-07-26

  This patch adds support for mediasec SIP headers and SDP attributes.
  These are defined in RFC 3329, 3GPP TS 24.229 and
  draft-dawes-sipcore-mediasec-parameter. The new features are
  implemented so that a backbone for RFC 3329 is present to streamline
  future work on RFC 3329.

  With this patch, Asterisk can communicate with Deutsche Telekom trunks
  which require these fields.

  ASTERISK-30032


#### res_prometheus: Do not crash on invisible bridges
  Author: Holger Hans Peter Freyther
  Date:   2022-09-20

  Avoid crashing by skipping invisible bridges and checking the
  snapshot for a null pointer. In effect this is how the bridges
  are enumerated in res/ari/resource_bridges.c already.

  ASTERISK-30239
  ASTERISK-30237


#### db: Fix incorrect DB tree count for AMI.
  Author: Naveen Albert
  Date:   2022-09-24

  The DBGetTree AMI action's ListItem previously
  always reported 1, regardless of the count. This
  is corrected to report the actual count.

  ASTERISK-30245 #close
  patches:
    gettreecount.diff submitted by Birger Harzenetter (license 5870)


#### res_pjsip_geolocation: Change some notices to debugs.
  Author: Naveen Albert
  Date:   2022-09-19

  If geolocation is not in use for an endpoint, the NOTICE
  log level is currently spammed with messages about this,
  even though nothing is wrong and these messages provide
  no real value. These log messages are therefore changed
  to debugs.

  ASTERISK-30241 #close


#### func_logic: Don't emit warning if both IF branches are empty.
  Author: Naveen Albert
  Date:   2022-09-21

  The IF function currently emits warnings if both IF branches
  are empty. However, there is no actual necessity that either
  branch be non-empty as, unlike other conditional applications/
  functions, nothing is inherently done with IF, and both
  sides could legitimately be empty. The warning is thus turned
  into a debug message.

  ASTERISK-30243 #close


#### features: Add no answer option to Bridge.
  Author: Naveen Albert
  Date:   2022-09-11

  Adds the n "no answer" option to the Bridge application
  so that answer supervision can not automatically
  be provided when Bridge is executed.

  Additionally, a mechanism (dialplan variable)
  is added to prevent bridge targets (typically the
  target of a masquerade) from answering the channel
  when they enter the bridge.

  ASTERISK-30223 #close


#### app_bridgewait: Add option to not answer channel.
  Author: Naveen Albert
  Date:   2022-09-09

  Adds the n option to not answer the channel when calling
  BridgeWait, so the application can be used without
  forcing answer supervision.

  ASTERISK-30216 #close


#### app_amd: Add option to play audio during AMD.
  Author: Naveen Albert
  Date:   2022-08-15

  Adds an option that will play an audio file
  to the party while AMD is running on the
  channel, so the called party does not just
  hear silence.

  ASTERISK-30179 #close


#### test: initialize capture structure before freeing
  Author: Philip Prindeville
  Date:   2022-09-15

  ASTERISK-30232 #close


#### func_export: Add EXPORT function
  Author: Naveen Albert
  Date:   2021-05-17

  Adds the EXPORT function, which allows write
  access to variables and functions on other
  channels.

  ASTERISK-29432 #close


#### res_pjsip: Add 100rel option "peer_supported".
  Author: Maximilian Fridrich
  Date:   2022-07-26

  This patch adds a new option to the 100rel parameter for pjsip
  endpoints called "peer_supported". When an endpoint with this option
  receives an incoming request and the request indicated support for the
  100rel extension, then Asterisk will send 1xx responses reliably. If
  the request did not indicate 100rel support, Asterisk sends 1xx
  responses normally.

  ASTERISK-30158


#### manager: be more aggressive about purging http sessions.
  Author: Jaco Kroon
  Date:   2022-09-05

  If we find that n_max (currently hard wired to 1) sessions were purged,
  schedule the next purge for 1ms into the future rather than 5000ms (as
  per current).  This way we will purge up to 1000 sessions per second
  rather than 1 every 5 seconds.

  This mitigates a build-up of sessions should http sessions gets
  established faster than 1 per 5 seconds.

  Signed-off-by: Jaco Kroon <jaco@uls.co.za>

#### func_scramble: Fix null pointer dereference.
  Author: Naveen Albert
  Date:   2022-09-10

  Fix segfault due to null pointer dereference
  inside the audiohook callback.

  ASTERISK-30220 #close


#### func_strings: Add trim functions.
  Author: Naveen Albert
  Date:   2022-09-11

  Adds TRIM, LTRIM, and RTRIM, which can be used
  for trimming leading and trailing whitespace
  from strings.

  ASTERISK-30222 #close


#### res_crypto: Memory issues and uninitialized variable errors
  Author: George Joseph
  Date:   2022-09-16

  ASTERISK-30235


#### res_geolocation: Fix issues exposed by compiling with -O2
  Author: George Joseph
  Date:   2022-09-16

  Fixed "may be used uninitialized" errors in geoloc_config.c.

  ASTERISK-30234


#### res_crypto: don't complain about directories
  Author: Philip Prindeville
  Date:   2022-09-13

  ASTERISK-30226 #close


#### res_pjsip: Add user=phone on From and PAID for usereqphone=yes
  Author: Mike Bradeen
  Date:   2022-08-15

  Adding user=phone to local-side uri's when user_eq_phone=yes is set for
  an endpoint. Previously this would only add the header to the To and R-URI.

  ASTERISK-30178


#### res_geolocation: Fix segfault when there's an empty element
  Author: George Joseph
  Date:   2022-09-13

  Fixed a segfault caused by var_list_from_loc_info() encountering
  an empty location info element.

  Fixed an issue in ast_strsep() where a value with only whitespace
  wasn't being preserved.

  Fixed an issue in ast_variable_list_from_quoted_string() where
  an empty value was considered a failure.

  ASTERISK-30215
  Reported by: Dan Cropp


#### res_musiconhold: Add option to not play music on hold on unanswered channels
  Author: sungtae kim
  Date:   2022-08-14

  This change adds an option, answeredonly, that will prevent music on
  hold on channels that are not answered.

  ASTERISK-30135


#### res_pjsip: Add TEL URI support for basic calls.
  Author: Ben Ford
  Date:   2022-08-02

  This change allows TEL URI requests to come through for basic calls. The
  allowed requests are INVITE, ACK, BYE, and CANCEL. The From and To
  headers will now allow TEL URIs, as well as the request URI.

  Support is only for TEL URIs present in traffic from a remote party.
  Asterisk does not generate any TEL URIs on its own.

  ASTERISK-26894


#### res_crypto: Use EVP API's instead of legacy API's
  Author: Philip Prindeville
  Date:   2022-03-24

  ASTERISK-30046 #close


#### test: Add coverage for res_crypto
  Author: Philip Prindeville
  Date:   2022-05-03

  We're validating the following functionality:

  encrypting a block of data with RSA
  decrypting a block of data with RSA
  signing a block of data with RSA
  verifying a signature with RSA
  encrypting a block of data with AES-ECB
  encrypting a block of data with AES-ECB

  as well as accessing test keys from the keystore.

  ASTERISK-30045 #close


#### res_crypto: make keys reloadable on demand for testing
  Author: Philip Prindeville
  Date:   2022-07-26

  ASTERISK-30045


#### test: Add test coverage for capture child process output
  Author: Philip Prindeville
  Date:   2022-05-03

  ASTERISK-30037 #close


#### main/utils: allow checking for command in $PATH
  Author: Philip Prindeville
  Date:   2022-07-26

  ASTERISK-30037


#### test: Add ability to capture child process output
  Author: Philip Prindeville
  Date:   2022-05-02

  ASTERISK-30037


#### res_crypto: Don't load non-regular files in keys directory
  Author: Philip Prindeville
  Date:   2022-04-26

  ASTERISK-30046


#### func_frame_trace: Remove bogus assertion.
  Author: Naveen Albert
  Date:   2022-09-08

  The FRAME_TRACE function currently asserts if it sees
  a MASQUERADE_NOTIFY. However, this is a legitimate thing
  that can happen so asserting is inappropriate, as there
  are no clear negative ramifications of such a thing. This
  is adjusted to be like the other frames to print out
  the subclass.

  ASTERISK-30210 #close


#### lock.c: Add AMI event for deadlocks.
  Author: Naveen Albert
  Date:   2022-07-27

  Adds an AMI event to indicate that a deadlock
  has likely started, when Asterisk is compiled
  with DETECT_DEADLOCKS enabled. This can make
  it easier to perform automated deadlock detection
  and take appropriate action (such as doing a core
  dump). Unlike the deadlock warnings, the AMI event
  is emitted only once per deadlock.

  ASTERISK-30161 #close


#### app_confbridge: Add end_marked_any option.
  Author: Naveen Albert
  Date:   2022-09-04

  Adds the end_marked_any option, which can be used
  to kick a user from a conference if any marked user
  leaves.

  ASTERISK-30211 #close


#### pbx_variables: Use const char if possible.
  Author: Naveen Albert
  Date:   2022-09-03

  Use const char for char arguments to
  pbx_substitute_variables_helper_full_location
  that can do so (context and exten).

  ASTERISK-30209 #close


#### res_geolocation: Add two new options to GEOLOC_PROFILE
  Author: George Joseph
  Date:   2022-08-25

  Added an 'a' option to the GEOLOC_PROFILE function to allow
  variable lists like location_info_refinement to be appended
  to instead of replacing the entire list.

  Added an 'r' option to the GEOLOC_PROFILE function to resolve all
  variables before a read operation and after a Set operation.

  Added a few missing parameters to the ones allowed for writing
  with GEOLOC_PROFILE.

  Fixed a bug where calling GEOLOC_PROFILE to read a parameter
  might actually update the profile object.

  Cleaned up XML documentation a bit.

  ASTERISK-30190


#### res_geolocation:  Allow location parameters on the profile object
  Author: George Joseph
  Date:   2022-08-18

  You can now specify the location object's format, location_info,
  method, location_source and confidence parameters directly on
  a profile object for simple scenarios where the location
  information isn't common with any other profiles.  This is
  mutually exclusive with setting location_reference on the
  profile.

  Updated appdocsxml.dtd to allow xi:include in a configObject
  element.  This makes it easier to link to complete configOptions
  in another object.  This is used to add the above fields to the
  profile object without having to maintain the option descriptions
  in two places.

  ASTERISK-30185


#### res_geolocation: Add profile parameter suppress_empty_ca_elements
  Author: George Joseph
  Date:   2022-08-17

  Added profile parameter "suppress_empty_ca_elements" that
  will cause Civic Address elements that are empty to be
  suppressed from the outgoing PIDF-LO document.

  Fixed a possible SEGV if a sub-parameter value didn't have a
  value.

  ASTERISK-30177


#### res_geolocation:  Add built-in profiles
  Author: George Joseph
  Date:   2022-08-16

  The trigger to perform outgoing geolocation processing is the
  presence of a geoloc_outgoing_call_profile on an endpoint. This
  is intentional so as to not leak location information to
  destinations that shouldn't receive it.   In a totally dynamic
  configuration scenario however, there may not be any profiles
  defined in geolocation.conf.  This makes it impossible to do
  outgoing processing without defining a "dummy" profile in the
  config file.

  This commit adds 4 built-in profiles:
    "<prefer_config>"
    "<discard_config>"
    "<prefer_incoming>"
    "<discard_incoming>"
  The profiles are empty except for having their precedence
  set and can be set on an endpoint to allow processing without
  entries in geolocation.conf.  "<discard_config>" is actually the
  best one to use in this situation.

  ASTERISK-30182


#### res_pjsip_sdp_rtp: Skip formats without SDP details.
  Author: Joshua C. Colp
  Date:   2022-08-30

  When producing an outgoing SDP we iterate through the configured
  formats and produce SDP information. It is possible for some
  configured formats to not have SDP information available. If this
  is the case we skip over them to allow the SDP to still be
  produced.

  ASTERISK-29185


#### cli: Prevent assertions on startup from bad ao2 refs.
  Author: Naveen Albert
  Date:   2022-05-03

  If "core show channels" is run before startup has completed, it
  is possible for bad ao2 refs to occur because the system is not
  yet fully initialized. This will lead to an assertion failing.

  To prevent this, initialization of CLI builtins is moved to be
  later along in the main load sequence. Core CLI commands are
  loaded at the same time, but channel-related commands are loaded
  later on.

  ASTERISK-29846 #close


#### pjsip: Add TLS transport reload support for certificate and key.
  Author: Joshua C. Colp
  Date:   2022-08-19

  This change adds support using the pjsip_tls_transport_restart
  function for reloading the TLS certificate and key, if the filenames
  remain unchanged. This is useful for Let's Encrypt and other
  situations. Note that no restart of the transport will occur if
  the certificate and key remain unchanged.

  ASTERISK-30186


#### res_tonedetect: Fix typos referring to wrong variables.
  Author: Naveen Albert
  Date:   2022-08-25

  Fixes two typos that cause fax detection to not work.
  One refers to the wrong frame variable, and the other
  refers to the subclass.integer instead of the frametype
  as it should.

  ASTERISK-30192 #close


#### alembic: add missing ps_endpoints columns
  Author: Mike Bradeen
  Date:   2022-08-17

  The following required columns were missing,
  now added to the ps_endpoints table:

  incoming_call_offer_pref
  outgoing_call_offer_pref
  stir_shaken_profile

  ASTERISK-29453


#### chan_dahdi.c: Resolve a format-truncation build warning.
  Author: Sean Bright
  Date:   2022-08-19

  With gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0:

  > chan_dahdi.c:4129:18: error: ‘%s’ directive output may be truncated
  >   writing up to 255 bytes into a region of size between 242 and 252
  >   [-Werror=format-truncation=]

  This removes the error-prone sizeof(...) calculations in favor of just
  doubling the size of the base buffer.


#### res_pjsip_pubsub: Postpone destruction of old subscriptions on RLS update
  Author: Alexei Gradinari
  Date:   2022-08-03

  Set termination state to old subscriptions to prevent queueing and sending
  NOTIFY messages on exten/device state changes.

  Postpone destruction of old subscriptions until all already queued tasks
  that may be using old subscriptions have completed.

  ASTERISK-29906


#### channel.h: Remove redundant declaration.
  Author: Sean Bright
  Date:   2022-08-15

  The DECLARE_STRINGFIELD_SETTERS_FOR() declares ast_channel_name_set()
  for us, so no need to declare it separately.


#### features: Add transfer initiation options.
  Author: Naveen Albert
  Date:   2022-02-05

  Adds additional control options over the transfer
  feature functionality to give users more control
  in how the transfer feature sounds and works.

  First, the "transfer" sound that plays when a transfer is
  initiated can now be customized by the user in
  features.conf, just as with the other transfer sounds.

  Secondly, the user can now specify the transfer extension
  in advance by using the TRANSFER_EXTEN variable. If
  a valid extension is contained in this variable, the call
  will automatically be transferred to this destination.
  Otherwise, it will fall back to collecting the extension
  from the user as is always done now.

  ASTERISK-29899 #close


#### CI: Fixing path issue on venv check
  Author: Mike Bradeen
  Date:   2022-08-31

  ASTERISK-26826


#### CI: use Python3 virtual environment
  Author: Mike Bradeen
  Date:   2022-08-11

  Requires Python3 testsuite changes

  ASTERISK-26826


#### general: Very minor coding guideline fixes.
  Author: Naveen Albert
  Date:   2022-07-28

  Fixes a few coding guideline violations:
  * Use of C99 comments
  * Opening brace on same line as function prototype

  ASTERISK-30163 #close


#### res_geolocation: Address user issues, remove complexity, plug leaks
  Author: George Joseph
  Date:   2022-08-05

  * Added processing for the 'confidence' element.
  * Added documentation to some APIs.
  * removed a lot of complex code related to the very-off-nominal
    case of needing to process multiple location info sources.
  * Create a new 'ast_geoloc_eprofile_to_pidf' API that just takes
    one eprofile instead of a datastore of multiples.
  * Plugged a huge leak in XML processing that arose from
    insufficient documentation by the libxml/libxslt authors.
  * Refactored stylesheets to be more efficient.
  * Renamed 'profile_action' to 'profile_precedence' to better
    reflect it's purpose.
  * Added the config option for 'allow_routing_use' which
    sets the value of the 'Geolocation-Routing' header.
  * Removed the GeolocProfileCreate and GeolocProfileDelete
    dialplan apps.
  * Changed the GEOLOC_PROFILE dialplan function as follows:
    * Removed the 'profile' argument.
    * Automatically create a profile if it doesn't exist.
    * Delete a profile if 'inheritable' is set to no.
  * Fixed various bugs and leaks
  * Updated Asterisk WiKi documentation.

  ASTERISK-30167


#### chan_iax2: Add missing options documentation.
  Author: Naveen Albert
  Date:   2022-07-30

  Adds missing dial resource option documentation.

  ASTERISK-30164 #close


#### app_confbridge: Fix memory leak on updated menu options.
  Author: Naveen Albert
  Date:   2022-08-01

  If the CONFBRIDGE function is used to dynamically set
  menu options, a memory leak occurs when a menu option
  that has been set is overridden, since the menu entry
  is not destroyed before being freed. This ensures that
  it is.

  Additionally, logic that duplicates the destroy function
  is removed in lieu of the destroy function itself.

  ASTERISK-28422 #close


#### Geolocation: Wiki Documentation
  Author: George Joseph
  Date:   2022-07-19


#### manager: Remove documentation for nonexistent action.
  Author: Naveen Albert
  Date:   2022-07-28

  The manager XML documentation documents a "FilterList"
  action, but there is no such action. Therefore, this can
  lead to confusion when people try to use a documented
  action that does not, in fact, exist. This is removed
  as the action never did exist in the past, nor would it
  be trivial to add since we only store the regex_t
  objects, so the filter list can't actually be provided
  without storing that separately. Most likely, the
  documentation was originally added (around version 10)
  in anticipation of something that never happened.

  ASTERISK-29917 #close


#### cdr.conf: Remove obsolete app_mysql reference.
  Author: Naveen Albert
  Date:   2022-07-27

  The CDR sample config still mentions that app_mysql
  is available in the addons directory, but this is
  incorrect as it was removed as of 19. This removes
  that to avoid confusion.

  ASTERISK-30160 #close


#### general: Remove obsolete SVN references.
  Author: Naveen Albert
  Date:   2022-07-27

  There are a handful of files in the tree that
  reference an SVN link for the coding guidelines.

  This removes these because the links are dead
  and the vast majority of source files do not
  contain these links, so this is more consistent.

  app_skel still maintains an (up to date) link
  to the coding guidelines.

  ASTERISK-30159 #close


#### app_meetme: Add missing AMI documentation.
  Author: Naveen Albert
  Date:   2022-07-23

  The MeetmeList and MeetmeListRooms AMI
  responses are currently completely undocumented.
  This adds documentation for these responses.

  ASTERISK-30018 #close


#### general: Improve logging levels of some log messages.
  Author: Naveen Albert
  Date:   2022-07-22

  Adjusts some logging levels to be more or less important,
  that is more prominent when actual problems occur and less
  prominent for less noteworthy things.

  ASTERISK-30153 #close


#### app_confbridge: Add missing AMI documentation.
  Author: Naveen Albert
  Date:   2022-07-23

  Documents the ConfbridgeListRooms AMI response,
  which is currently not documented.

  ASTERISK-30020 #close


#### func_srv: Document field parameter.
  Author: Naveen Albert
  Date:   2022-07-23

  Adds missing documentation for the field parameter
  for the SRVRESULT function.

  ASTERISK-30151
  Reported by: Chris Young


#### pbx_functions.c: Manually update ast_str strlen.
  Author: Naveen Albert
  Date:   2022-07-23

  When ast_func_read2 is used to read a function using
  its read function (as opposed to a native ast_str read2
  function), the result is copied directly by the function
  into the ast_str buffer. As a result, the ast_str length
  remains initialized to 0, which is a bug because this is
  not the real string length.

  This can cascade and have issues elsewhere, such as when
  reading substrings of functions that only register read
  as opposed to read2 callbacks. In this case, since reading
  ast_str_strlen returns 0, the returned substring is empty
  as opposed to the actual substring. This has caused
  the ast_str family of functions to behave inconsistently
  and erroneously, in contrast to the pbx_variables substitution
  functions which work correctly.

  This fixes this issue by manually updating the ast_str length
  when the result is copied directly into the ast_str buffer.

  Additionally, an assertion and a unit test that previously
  exposed these issues are added, now that the issue is fixed.

  ASTERISK-29966 #close


#### build: fix bininstall launchd issue on cross-platform build
  Author: Sergey V. Lobanov
  Date:   2022-02-19

  configure script detects /sbin/launchd, but the result of this
  check is not used in Makefile (bininstall). Makefile also detects
  /sbin/launchd file to decide if it is required to install
  safe_asterisk.

  configure script correctly detects cross compile build and sets
  PBX_LAUNCHD=0

  In case of building asterisk on MacOS host for Linux target using
  external toolchain (e.g. OpenWrt toolchain), bininstall does not
  install safe_asterisk (due to /sbin/launchd detection in Makefile),
  but it is required on target (Linux).

  This patch adds HAVE_SBIN_LAUNCHD=@PBX_LAUNCHD@ to makeopts.in to
  use the result of /sbin/launchd detection from configure script in
  Makefile.
  Also this patch uses HAVE_SBIN_LAUNCHD in Makefile (bininstall) to
  decide if it is required to install safe_asterisk.

  ASTERISK-29905 #close


#### manager: Fix incomplete filtering of AMI events.
  Author: Naveen Albert
  Date:   2022-07-12

  The global event filtering code was only in one
  possible execution path, so not all events were
  being properly filtered out if requested. This moves
  that into the universal AMI handling code so all
  events are properly handled.

  Additionally, the CLI listing of disabled events can
  also get truncated, so we now print out everything.

  ASTERISK-30137 #close


#### db: Add AMI action to retrieve DB keys at prefix.
  Author: Naveen Albert
  Date:   2022-07-11

  Adds the DBGetTree action, which can be used to
  retrieve all of the DB keys beginning with a
  particular prefix, similar to the capability
  provided by the database show CLI command.

  ASTERISK-30136 #close


#### Update master branch for Asterisk 21
  Author: George Joseph
  Date:   2022-07-20


