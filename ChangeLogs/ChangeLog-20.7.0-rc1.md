
Change Log for Release asterisk-20.7.0-rc1
========================================

Links:
----------------------------------------

 - [Full ChangeLog](https://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-20.7.0-rc1.md)  
 - [GitHub Diff](https://github.com/asterisk/asterisk/compare/20.6.0...20.7.0-rc1)  
 - [Tarball](https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-20.7.0-rc1.tar.gz)  
 - [Downloads](https://downloads.asterisk.org/pub/telephony/asterisk)  

Summary:
----------------------------------------

- translate.c: implement new direct comp table mode                               
- README.md: Removed outdated link                                                
- strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.              
- .github: Add force_cherry_pick option to Releaser                               
- .github: Remove start_version from Releaser                                     
- res_rtp_asterisk.c: Correct coefficient in MOS calculation.                     
- dsp.c: Fix and improve potentially inaccurate log message.                      
- pjsip show channelstats: Prevent possible segfault when faxing                  
- Reduce startup/shutdown verbose logging                                         
- configure: Rerun bootstrap on modern platform.                                  
- Upgrade bundled pjproject to 2.14.                                              
- app_speech_utils.c: Allow partial speech results.                               
- utils: Make behavior of ast_strsep* match strsep.                               
- app_chanspy: Add 'D' option for dual-channel audio                              
- .github: Update github-script to v7 and fix a rest bug                          
- app_if: Fix next priority calculation.                                          
- res_pjsip_t38.c: Permit IPv6 SDP connection addresses.                          
- BuildSystem: Bump autotools versions on OpenBSD.                                
- main/utils: Simplify the FreeBSD ast_get_tid() handling                         
- res_pjsip_session.c: Correctly format SDP connection addresses.                 
- rtp_engine.c: Correct sample rate typo for L16/44100.                           
- manager.c: Fix erroneous reloads in UpdateConfig.                               
- res_calendar_icalendar: Print iCalendar error on parsing failure.               
- app_confbridge: Don't emit warnings on valid configurations.                    
- app_voicemail: add NoOp alembic script to maintain sync                         
- chan_dahdi: Allow MWI to be manually toggled on channels.                       
- chan_rtp.c: MulticastRTP missing refcount without codec option                  
- chan_rtp.c: Change MulticastRTP nameing to avoid memory leak                    
- func_frame_trace: Add CLI command to dump frame queue.                          

User Notes:
----------------------------------------

- ### Upgrade bundled pjproject to 2.14.                                              
  Bundled pjproject has been upgraded to 2.14. For more
  information on what all is included in this change, check out the
  pjproject Github page: https://github.com/pjsip/pjproject/releases

- ### app_speech_utils.c: Allow partial speech results.                               
  The SpeechBackground dialplan application now supports a 'p'
  option that will return partial results from speech engines that
  provide them when a timeout occurs.

- ### app_chanspy: Add 'D' option for dual-channel audio                              
  The ChanSpy application now accepts the 'D' option which
  will interleave the spied audio within the outgoing frames. The
  purpose of this is to allow the audio to be read as a Dual channel
  stream with separate incoming and outgoing audio. Setting both the
  'o' option and the 'D' option and results in the 'D' option being
  ignored.

- ### chan_dahdi: Allow MWI to be manually toggled on channels.                       
  The 'dahdi set mwi' now allows MWI on channels
  to be manually toggled if needed for troubleshooting.
  Resolves: #440


Upgrade Notes:
----------------------------------------


Closed Issues:
----------------------------------------

  - #406: [improvement]: pjsip: Upgrade bundled version to pjproject 2.14
  - #440: [new-feature]: chan_dahdi: Allow manually toggling MWI on channels
  - #492: [improvement]: res_calendar_icalendar: Print icalendar error if available on parsing failure
  - #527: [bug]: app_voicemail_odbc no longer working after removal of macrocontext.
  - #529: [bug]: MulticastRTP without selected codec leeds to "FRACK!, Failed assertion bad magic number 0x0 for object" after ~30 calls
  - #533: [improvement]: channel.c, func_frame_trace.c: Improve debuggability of channel frame queue
  - #551: [bug]: manager: UpdateConfig triggers reload with "Reload: no"
  - #560: [bug]: EndIf() causes next priority to be skipped
  - #565: [bug]: Application Read() returns immediately
  - #569: [improvement]: Add option to interleave input and output frames on spied channel
  - #572: [improvement]: Copy partial speech results when Asterisk is ready to move on but the speech backend is not
  - #582: [improvement]: Reduce unneeded logging during startup and shutdown
  - #586: [bug]: The "restrict" keyword used in chan_iax2.c isn't supported in older gcc versions
  - #592: [bug]: In certain circumstances, "pjsip show channelstats" can segfault when a fax session is active
  - #595: [improvement]: dsp.c: Fix and improve confusing warning message.
  - #597: [bug]: wrong MOS calculation
  - #601: [new-feature]: translate.c: implement new direct comp table mode (PR #585)

Commits By Author:
----------------------------------------

- ### Ben Ford (1):
  - Upgrade bundled pjproject to 2.14.

- ### Brad Smith (2):
  - main/utils: Simplify the FreeBSD ast_get_tid() handling
  - BuildSystem: Bump autotools versions on OpenBSD.

- ### George Joseph (5):
  - .github: Update github-script to v7 and fix a rest bug
  - Reduce startup/shutdown verbose logging
  - pjsip show channelstats: Prevent possible segfault when faxing
  - .github: Remove start_version from Releaser
  - .github: Add force_cherry_pick option to Releaser

- ### Joshua C. Colp (1):
  - utils: Make behavior of ast_strsep* match strsep.

- ### Mike Bradeen (2):
  - app_voicemail: add NoOp alembic script to maintain sync
  - app_chanspy: Add 'D' option for dual-channel audio

- ### Naveen Albert (7):
  - func_frame_trace: Add CLI command to dump frame queue.
  - chan_dahdi: Allow MWI to be manually toggled on channels.
  - res_calendar_icalendar: Print iCalendar error on parsing failure.
  - manager.c: Fix erroneous reloads in UpdateConfig.
  - app_if: Fix next priority calculation.
  - configure: Rerun bootstrap on modern platform.
  - dsp.c: Fix and improve potentially inaccurate log message.

- ### PeterHolik (2):
  - chan_rtp.c: Change MulticastRTP nameing to avoid memory leak
  - chan_rtp.c: MulticastRTP missing refcount without codec option

- ### Sean Bright (5):
  - app_confbridge: Don't emit warnings on valid configurations.
  - rtp_engine.c: Correct sample rate typo for L16/44100.
  - res_pjsip_session.c: Correctly format SDP connection addresses.
  - res_pjsip_t38.c: Permit IPv6 SDP connection addresses.
  - strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.

- ### Sebastian Jennen (1):
  - translate.c: implement new direct comp table mode

- ### Shyju Kanaprath (1):
  - README.md: Removed outdated link

- ### cmaj (1):
  - app_speech_utils.c: Allow partial speech results.

- ### romryz (1):
  - res_rtp_asterisk.c: Correct coefficient in MOS calculation.


Detail:
----------------------------------------

- ### translate.c: implement new direct comp table mode                               
  Author: Sebastian Jennen  
  Date:   2024-02-25  

  The new mode lists for each codec translation the actual real cost in cpu microseconds per second translated audio.
  This allows to compare the real cpu usage of translations and helps in evaluation of codec implementation changes regarding performance (regression testing).

  - add new table mode
  - hide the 999999 comp values, as these only indicate an issue with transcoding
  - hide the 0 values, as these also do not contain any information (only indicate a multistep transcoding)

  Resolves: #601

- ### README.md: Removed outdated link                                                
  Author: Shyju Kanaprath  
  Date:   2024-02-23  

  Removed outdated link http://www.quicknet.net from README.md

  cherry-pick-to: 18
  cherry-pick-to: 20
  cherry-pick-to: 21

- ### strings.h: Ensure ast_str_buffer(…) returns a 0 terminated string.              
  Author: Sean Bright  
  Date:   2024-02-17  

  If a dynamic string is created with an initial length of 0,
  `ast_str_buffer(…)` will return an invalid pointer.

  This was a secondary discovery when fixing #65.


- ### .github: Add force_cherry_pick option to Releaser                               
  Author: George Joseph  
  Date:   2024-02-20  


- ### .github: Remove start_version from Releaser                                     
  Author: George Joseph  
  Date:   2023-10-17  


- ### res_rtp_asterisk.c: Correct coefficient in MOS calculation.                     
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

- ### dsp.c: Fix and improve potentially inaccurate log message.                      
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

- ### pjsip show channelstats: Prevent possible segfault when faxing                  
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

- ### Reduce startup/shutdown verbose logging                                         
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

- ### configure: Rerun bootstrap on modern platform.                                  
  Author: Naveen Albert  
  Date:   2024-02-12  

  The last time configure was run, it was run on a system that
  did not enable -std=gnu11 by default, which meant that the
  restrict qualifier would not be recognized on certain platforms.
  This regenerates the configure files from running bootstrap.sh,
  so that these should be recognized on all supported platforms.

  Resolves: #586

- ### Upgrade bundled pjproject to 2.14.                                              
  Author: Ben Ford  
  Date:   2024-02-05  

  Fixes: #406

  UserNote: Bundled pjproject has been upgraded to 2.14. For more
  information on what all is included in this change, check out the
  pjproject Github page: https://github.com/pjsip/pjproject/releases


- ### app_speech_utils.c: Allow partial speech results.                               
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


- ### utils: Make behavior of ast_strsep* match strsep.                               
  Author: Joshua C. Colp  
  Date:   2024-01-31  

  Given the scenario of passing an empty string to the
  ast_strsep functions the functions would return NULL
  instead of an empty string. This is counter to how
  strsep itself works.

  This change alters the behavior of the functions to
  match that of strsep.

  Fixes: #565

- ### app_chanspy: Add 'D' option for dual-channel audio                              
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


- ### .github: Update github-script to v7 and fix a rest bug                          
  Author: George Joseph  
  Date:   2024-02-05  

  Need to update the github-script to v7 to squash deprecation
  warnings.

  Also fixed the API name for github.rest.pulls.requestReviewers.


- ### app_if: Fix next priority calculation.                                          
  Author: Naveen Albert  
  Date:   2024-01-28  

  Commit fa3922a4d28860d415614347d9f06c233d2beb07 fixed
  a branching issue but "overshoots" when calculating
  the next priority. This fixes that; accompanying
  test suite tests have also been extended.

  Resolves: #560

- ### res_pjsip_t38.c: Permit IPv6 SDP connection addresses.                          
  Author: Sean Bright  
  Date:   2024-01-29  

  The existing code prevented IPv6 addresses from being properly parsed.

  Fixes #558


- ### BuildSystem: Bump autotools versions on OpenBSD.                                
  Author: Brad Smith  
  Date:   2024-01-27  

  Bump up to the more commonly used and modern versions of
  autoconf and automake.


- ### main/utils: Simplify the FreeBSD ast_get_tid() handling                         
  Author: Brad Smith  
  Date:   2024-01-27  

  FreeBSD has had kernel threads for 20+ years.


- ### res_pjsip_session.c: Correctly format SDP connection addresses.                 
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


- ### rtp_engine.c: Correct sample rate typo for L16/44100.                           
  Author: Sean Bright  
  Date:   2024-01-28  

  Fixes #555


- ### manager.c: Fix erroneous reloads in UpdateConfig.                               
  Author: Naveen Albert  
  Date:   2024-01-25  

  Currently, a reload will always occur if the
  Reload header is provided for the UpdateConfig
  action. However, we should not be doing a reload
  if the header value has a falsy value, per the
  documentation, so this makes the reload behavior
  consistent with the existing documentation.

  Resolves: #551

- ### res_calendar_icalendar: Print iCalendar error on parsing failure.               
  Author: Naveen Albert  
  Date:   2023-12-14  

  If libical fails to parse a calendar, print the error message it provdes.

  Resolves: #492

- ### app_confbridge: Don't emit warnings on valid configurations.                    
  Author: Sean Bright  
  Date:   2024-01-21  

  The numeric bridge profile options `internal_sample_rate` and
  `maximum_sample_rate` are documented to accept the special values
  `auto` and `none`, respectively. While these values currently work,
  they also emit warnings when used which could be confusing for users.

  In passing, also ensure that we only accept the documented range of
  sample rate values between 8000 and 192000.

  Fixes #546


- ### app_voicemail: add NoOp alembic script to maintain sync                         
  Author: Mike Bradeen  
  Date:   2024-01-17  

  Adding a NoOp alembic script for the voicemail database to maintain
  version sync with other branches.

  Fixes: #527

- ### chan_dahdi: Allow MWI to be manually toggled on channels.                       
  Author: Naveen Albert  
  Date:   2023-11-10  

  This adds a CLI command to manually toggle the MWI status
  of a channel, useful for troubleshooting or resetting
  MWI devices, similar to the capabilities offered with
  SIP messaging to manually control MWI status.

  UserNote: The 'dahdi set mwi' now allows MWI on channels
  to be manually toggled if needed for troubleshooting.

  Resolves: #440

- ### chan_rtp.c: MulticastRTP missing refcount without codec option                  
  Author: PeterHolik  
  Date:   2024-01-15  

  Fixes: #529

- ### chan_rtp.c: Change MulticastRTP nameing to avoid memory leak                    
  Author: PeterHolik  
  Date:   2024-01-16  

  Fixes: asterisk#536

- ### func_frame_trace: Add CLI command to dump frame queue.                          
  Author: Naveen Albert  
  Date:   2024-01-12  

  This adds a simple CLI command that can be used for
  analyzing all frames currently queued to a channel.

  A couple log messages are also adjusted to be more
  useful in tracing bridging problems.

  Resolves: #533

