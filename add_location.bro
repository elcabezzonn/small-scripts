module HTTP;

export {
    redef record Info += {
        # Extend this record with an optional, logged field named "location".
        location: string    &log &optional;
      
      };
}


# if there is a redirect in a http connection, log the location header.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
   
      # Write the location value into the HTTP state of the connection.
    if ( name == "LOCATION" )
    {
        c$http$location = value;
    }
}
