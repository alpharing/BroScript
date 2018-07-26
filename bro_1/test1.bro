# FTP brute-forcing detector, triggering when too many rejected usernames or
# failed passwords have occurred from a single address.

@load base/protocols/ftp
@load base/frameworks/sumstats
@load base/utils/time

module FTP;

export {

	# Notify FTP brute force Type
	redef enum Notice::Type += {
		## Indicates a host bruteforcing FTP logins by watching for too
		## many rejected usernames or failed passwords.
		Bruteforcing
	};

	# How many rejected usernames or passwords are required before being
	# considered to be bruteforcing.
	const bruteforce_threshold: double = 20 &redef;

	# The time period in which the threshold needs to be crossed before
	# being reset.
	const bruteforce_measurement_interval = 15mins &redef;
}

event bro_init()
	{
		# Sumstat Reducer Part
		local r1: SumStats::Reducer =	[	$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), 					
											$unique_max=double_to_count(bruteforce_threshold+2)
										];
		
		# Sumstat Sumstat Part
		# threshold_Crossed is Callback Function
		SumStats::create([	$name="ftp-detect-bruteforcing",
	                  	    $epoch=bruteforce_measurement_interval,
	                  	    $reducers=set(r1),
	                  	    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
							{	return result["ftp.failed_auth"]$num+0.0;},
							$threshold=bruteforce_threshold,
							$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
							{
								local r = result["ftp.failed_auth"];
								local dur = duration_to_mins_secs(r$end-r$begin);
								local plural = r$unique>1 ? "s" : "";
								local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);

							# Making Notice.log field information
							NOTICE([$note=FTP::Bruteforcing,
									$src=key$host,
									$msg=message,
									$identifier=cat(key$host)]);
							}
						]);
	}

# Sumstat Observe Part
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local cmd = c$ftp$cmdarg$cmd;
	# USER typo or PASS typo
	if ( cmd == "USER" || cmd == "PASS" )
		{
		# Permanent Negative Completion reply
		if ( FTP::parse_ftp_reply_code(code)$x == 5 )
			SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}
	}
