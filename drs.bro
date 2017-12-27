#got this idea from sean metcalf's awesome article titled "Mimikatz DCSync Usage, Exploitation, and Detection"
#reference: https://adsecurity.org/?p=1729
#loading smb is necessary at times
@load policy/protocols/smb

@load base/frameworks/notice


export {
        redef enum Notice::Type += { 
                ## Indicates that a host was attempting a replication of the domain_controller.
                DCSync_attempt::Found 
        };

#this is where you would place your domain controllers 
const domain_controllers: set[addr] = {  
} &redef;

}

event dce_rpc_request(c: connection, fid: count, opnum: count, stub_len: count)
{
  if ( c$dce_rpc?$operation && c$dce_rpc$operation != "DRSGetNCChanges" ) {
    return;
    }
  if ( c$id$orig_h in domain_controllers ) {
    return;
  }
  
    NOTICE([$note=DCSync_attempt::Found,
            $msg=fmt("---- Replication from an unauthorized address ---"),
            $conn=c]);
  
 }


