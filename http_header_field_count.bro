#this is a the slighest modification to the header-names.bro script included in bro 
#it takes the client side headers and counts them allowing anyone to profile  http 
#traffic better
#TODO: figure out a way so only the count is included in the http.log rather than both the count and client header names.
#so if anyone is logging this they are not killed with logging licensing


##! Extract and include the header names used for each request in the HTTP
##! logging stream.  The headers in the logging stream will be stored in the
##! same order which they were seen on the wire.

@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP header names sent by the client.  No
		## header values are included here, just the header names.
		client_header_names:  vector of string &log &optional;
                client_header_count:  count &log &optional;	
		## The vector of HTTP header names sent by the server.  No
		## header values are included here, just the header names.
#		server_header_names:  vector of string &log &optional;
	};
	
	## A boolean value to determine if client header names are to be logged.
	const log_client_header_names = F &redef;
	
	## A boolean value to determine if the fields in the http header are to be logged
	const log_header_count = T &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! c?$http )
		return;

	if ( is_orig )
		{
		if ( log_client_header_names && log_header_count )
			{
			if ( ! c$http?$client_header_names && ! c$http?$client_header_count )
				c$http$client_header_names = vector();
			c$http$client_header_names[|c$http$client_header_names|] = name;
                        c$http$client_header_count = |c$http$client_header_names|; 
			}
		}
}

