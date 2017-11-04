#script to add subnet and subnet description to the conn log from a table it loads from slubnet.bro
@load ./slubnet.bro
@load base/utils/site

module Conn;

export {
  redef record Info += {
    subnet_desc: string &log &optional;
    Subnet:      subnet &log &optional;
  };
}

event connection_state_remove(c: connection)
{
  #Chubnets is a module in slubnet.bro
  for ( i in Chubnets::stankum)
  if (c$id$orig_h in Chubnets::stankum[i])
  {
    c$conn$subnet_desc = i;
    c$conn$Subnet = Chubnets::stankum[i];
  }
}
