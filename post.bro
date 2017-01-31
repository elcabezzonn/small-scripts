#run the script below if you find more post requests that you would lke to place in the list. the script will place them in the 
#format you see in the const http_resp_whitelist.. have not gotten the egrep part to account for country domains yet, eg .co.uk .com.au 
#bro -Cr pcap_goes_here  post.bro  
#| awk '{print $2}' | egrep -o '\.[^\.]+\.[^\.]+$' | sed 's/^/\/\\/' | sed 's/$/\$\/ | /' | sort -u


@load base/protocols/http
#this script looks for http POST requests from untrusted domains with a blank referrer field. 

module HTTP;

export {
  #this sets up the regex for which websites you want to whitelist
const http_resp_whitelist = 
/\.msn.com$/ | 
/\.bing.com$/ | 
/\.microsoft.com$/ | 
/\.symcd.com$/ | 
/\.google.com$/ |
/\.digicert.com$/ |  
/\.entrust.net$/ |  
/\.usertrust.com$/ |  
/\.comodoca.com$/ |  
/\.netsolssl.com$/ | 
/\.godaddy.com$/ |  
/\.msocsp.com$/ | 
/\.geotrust.com$/ | 
/\.verisign.com$/ &redef;
}


event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list){
  if (c$http?$method) 
        {
      if (is_orig && c$http$method == "POST" && c$http?$referrer == F &&  http_resp_whitelist ! in  c$http$host) {
      print fmt("%s   %s", c$id$resp_h,  c$http$host);
      # notice option if you would rather place this in the notice log 
#      NOTICE([$note=Post_with_no_referrer,
#              $conn=c,
#              $identifier=cat(c$id$resp_h,c$http$host,c$http$method)]);
  
      }
    }
}
 
