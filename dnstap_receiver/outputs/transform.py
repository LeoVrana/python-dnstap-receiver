import json
import yaml

from datetime import datetime, timezone
from tld import get_tld
from tld.exceptions import TldBadUrl

def processed_qname(qname: str) -> str:
    if qname[-1] == ".":
        qname = qname[:-1]
        
    try:
        if not qname.startswith("http"):
            dom_obj = get_tld(f"http://{qname}", as_object=True)
        else:
            dom_obj = get_tld(qname, as_object=True)
    except:
        print(f"Error in parsing qname: {qname}")
        return ""

    if dom_obj.subdomain:
        dom = ".".join([dom_obj.subdomain, dom_obj.domain, dom_obj.tld])
    else:
        dom = ".".join([dom_obj.domain, dom_obj.tld])
    
    return dom

def remove_ip_info(tapmsg) -> dict:
    tapmsg["query-ip"] = "..."
    return tapmsg
            
def convert_dnstap(fmt: str, tapmsg: dict, cfg: dict={}):
    """
    convert dnstap message:
    takes msg and transformer class and then
    """
    tapmsg["datetime"] = datetime.fromtimestamp(tapmsg["timestamp"], tz=timezone.utc).isoformat()

    ## Get the full config for the logger. If hide query IP, then scrub it.
    if cfg.get("transforms", {}).get("hide-query-ip", False):
        tapmsg = remove_ip_info(tapmsg) 

    if fmt == "text":
        msg_list = []
        msg_list.append("%s" % tapmsg["datetime"])
        msg_list.append("%s" % tapmsg["identity"])
        msg_list.append("%s" % tapmsg["message"])
        msg_list.append("%s" % tapmsg["rcode"]) 
        msg_list.append("%s" % tapmsg["query-ip"])
        msg_list.append("%s" % tapmsg["query-port"])
        msg_list.append("%s" % tapmsg["family"])
        msg_list.append("%s" % tapmsg["protocol"])
        msg_list.append("%sb" % tapmsg["length"])
        msg_list.append("%s" % tapmsg["qname"])
        msg_list.append("%s" % tapmsg["rrtype"])
        msg_list.append("%s" % tapmsg["latency"])
        
        # geoip activated ?
        if "country" in tapmsg:
            msg_list.append("%s" % tapmsg["country"])
            msg_list.append("%s" % tapmsg["city"])
            
        msg = " ".join(msg_list)
        del msg_list
        return msg.encode()
        
    elif fmt == "json":
        # delete some unneeded keys
        tapmsg.pop("payload", None)
        # tapmsg.pop("time-sec")
        # tapmsg.pop("time-nsec")
        
        msg = json.dumps(tapmsg)
        return msg.encode()
        
    elif fmt == "yaml":
        # delete some unneeded keys
        del tapmsg["payload"]; del tapmsg["time-sec"]; del tapmsg["time-nsec"];
        
        msg = yaml.dump(tapmsg)
        return msg.encode()
        
    else:
        return tapmsg
    