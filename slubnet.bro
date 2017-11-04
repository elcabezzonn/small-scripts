#where you would keep the list of subnets. if they are huge i would want it in another file to have a clean script.
#if your subnet information is only a few entries, you should consider putting it in the code? dno if it makes a difference for efficency

module Chubnets;

export {
  const stankum: table[string] of subnet = {
    ["2nd floor evilcorp"] = 192.168.1.1/25,
    ["basement corridor"]  = 192.168.1.128/25
  } &redef;
}
