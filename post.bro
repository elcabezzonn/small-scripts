@load base/protocols/http

module HTTP;

export {

const http_resp_whitelist = set("otf.msn.com", "www.bing.com", "go.microsoft.com", "dmd.metaservices.microsoft.com");

}


event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list){
  if (c$http?$method) {
      if (is_orig && c$http$method == "POST" && c$http?$referrer == F && c$http$host ! in http_resp_whitelist) {
      print fmt("%s   %s", c$id$resp_h,  c$http$host);
      # notice option if you would rather place this in the notice log 
#      NOTICE([$note=Post_with_no_referrer,
#              $conn=c,
#              $identifier=cat(c$id$resp_h,c$http$host,c$http$method)]);
  
      }
    }
}
 
