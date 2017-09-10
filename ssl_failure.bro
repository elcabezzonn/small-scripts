#saw this traffic in 2017-04-25-Smoke-Loader-post-infection-traffic.pcap on malwaretrafficanalysis.net if anyones interested to look
#definitely a test script, supposed to run over pcaps, where you can easily identify the local host 


export {
        redef enum Notice::Type += { 
                multiple_ssl_failures::Found 
        };

      }




event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
{
  if (!is_orig && desc == 40)
  {
    SumStats::observe("odd SSL failure",
                      [$host=c$id$orig_h],
                      [$str=cat(c$id$resp_h)]); 
  }
}


event bro_init()
{
  local r1 = SumStats::Reducer($stream="odd SSL failure",
                               $apply=set(SumStats::SUM));



  SumStats::create([$name="SSL failure",
                    $epoch=20secs,
                    $reducers=set(r1),
                    $threshold=5.0,
                    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                                {
                                return result["odd SSL failure"]$sum;
                                },

                    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                                {
                                NOTICE([$note=multiple_ssl_failures::Found,
                                        $msg=fmt("%s did more than 5 failed ssl connections within 5 seconds", key$host)]);
                                  }]);
#                                print fmt("%s more than 5 failed ssl connections within 5 seconds", key$host);
}



