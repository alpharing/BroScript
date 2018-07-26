
@load base/protocols/http
@load base/frameworks/sumstats
@load base/utils/time
@load base/frameworks/notice

module HTTP;

export {

	# Notify HTTP - SQL Injection
	redef enum Notice::Type += {
		SQLInjection
	};

	const sqli_requests_threshold: double = 20 &redef;

}

	
