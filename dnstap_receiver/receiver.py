import argparse
import logging
import asyncio
import yaml
import signal
import sys
import json
import time

import ssl
import pkgutil
import pathlib
import cachetools

import geoip2.database

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

# import all inputs
from dnstap_receiver.inputs import input_socket
from dnstap_receiver.inputs import input_sniffer
from dnstap_receiver.inputs import input_tcpclient

# import all outputs
from dnstap_receiver.outputs import output_stdout
from dnstap_receiver.outputs import output_stdout_router
from dnstap_receiver.outputs import output_file
from dnstap_receiver.outputs import output_syslog
from dnstap_receiver.outputs import output_tcp
from dnstap_receiver.outputs import output_metrics
from dnstap_receiver.outputs import output_dnstap
from dnstap_receiver.outputs import output_kafka
from dnstap_receiver.outputs import output_pgsql
from dnstap_receiver.outputs import output_rabbitmq
from dnstap_receiver.outputs import output_elasticsearch

from dnstap_receiver import api_server
from dnstap_receiver import statistics

DFLT_LISTEN_IP = "0.0.0.0"
DFLT_LISTEN_PORT = 6000

TEST_MSG_1 = {
    "identity": "res310.xsjc2.OHAAAAAI", 
    "qname": "dom1.com.", 
    "rrtype": "AAAA", 
    "query-ip": "::1", 
    "query-port": 36817, 
    "response-ip": "::1", 
    "response-port": 53, 
    "latency": "-", 
    "message": "CLIENT_RESPONSE", 
    "family": "INET6", 
    "protocol": "UDP", 
    "length": 75, 
    "timestamp": 1669081561.9376786, 
    "type": "response", 
    "rcode": "NOERROR", 
    "id": 17983, 
    "datetime": "2022-11-22T01:46:01.937679+00:00"
}

TEST_MSG_2 = {"identity": "res310.xsjc2.OHAAAAAI", "qname": "whatever.org", "rrtype": "A", "query-ip": "205.207.155.31", "query-port": 56039, "response-ip": "205.207.155.50", "response-port": 53, "latency": "-", "message": "CLIENT_RESPONSE", "family": "INET", "protocol": "UDP", "length": 137, "timestamp": 1669081519.537276, "type": "response", "rcode": "NXDOMAIN", "id": 60643, "datetime": "2022-11-22T01:45:19.537276+00:00"}

TEST_MSGS = [TEST_MSG_1, TEST_MSG_2]


# command line arguments definition
parser = argparse.ArgumentParser()
parser.add_argument("-l", 
                    help="IP of the dnsptap server to receive dnstap payloads (default: %(default)r)",
                    default=DFLT_LISTEN_IP)
parser.add_argument("-p", type=int,
                    help="Port the dnstap receiver is listening on (default: %(default)r)",
                    default=DFLT_LISTEN_PORT)               
parser.add_argument("-u", help="read dnstap payloads from unix socket")
parser.add_argument('-v', action='store_true', help="verbose mode")   
parser.add_argument('-t', action='store_true', help="test mode")   
parser.add_argument("-c", help="external config file")   

# get event loop
loop = asyncio.get_event_loop()
shutdown_task = None

def merge_cfg(u, o):
    """merge config"""
    for k,v in u.items():
        if k in o and isinstance(v, dict):
            merge_cfg(u=v,o=o[k])
        else:
            o[k] = v

def load_yaml(f):
    """load yaml file"""
    try:
        cfg =  yaml.safe_load(f) 
    except FileNotFoundError:
        print("default config file not found")
        sys.exit(1)
    except yaml.parser.ParserError:
        print("invalid default yaml config file")
        sys.exit(1)
    return cfg 
    
def setup_config(args):
    """load default config and update it with arguments if provided"""
    # Set the default configuration file
    f = pkgutil.get_data(__package__, 'dnstap.conf')
    cfg = load_yaml(f)

    # Overwrites then with the external file ?    
    if args.c and pathlib.Path(args.c).suffix == ".json":
        cfg_ext = json.load(open(args.c, "r"))
        merge_cfg(u=cfg_ext,o=cfg)
    elif args.c:
        cfg_ext = load_yaml(open(args.c, 'r'))
        merge_cfg(u=cfg_ext,o=cfg)

    # Or searches for a file named dnstap.conf in /etc/dnstap_receiver/       
    else:
        etc_conf = "/etc/dnstap_receiver/dnstap.conf"
        f = pathlib.Path(etc_conf)
        if f.exists():
            cfg_etc = load_yaml(open(etc_conf, 'r'))
            merge_cfg(u=cfg_etc,o=cfg)
            
    # update default config with command line arguments
    if args.v:
        cfg["trace"]["verbose"] = args.v    
    if args.u is not None:
        cfg["input"]["unix-socket"]["enable"] = True
        cfg["input"]["unix-socket"]["path"] = args.u
    if args.l != DFLT_LISTEN_IP:
        cfg["input"]["tcp-socket"]["local-address"] = args.l
    if args.l != DFLT_LISTEN_PORT:
        cfg["input"]["tcp-socket"]["local-port"] = args.p

    return cfg
    
def setup_logger(cfg):
    """setup main logger"""

    loglevel = logging.DEBUG if cfg["verbose"] else logging.INFO
    logfmt = '%(asctime)s %(levelname)s %(message)s'
    
    clogger.setLevel(loglevel)
    clogger.propagate = False
    
    if cfg["file"] is None:
        lh = logging.StreamHandler(stream=sys.stdout )
    else:
        lh = logging.FileHandler(cfg["file"])
    lh.setLevel(loglevel)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    clogger.addHandler(lh)
    
def setup_outputs(cfg, stats, start_shutdown):
    """setup outputs"""
    conf = cfg["output"]

    queues_list = []
    if conf.get("syslog", {}).get("enable", False):
        if not output_syslog.checking_conf(cfg=conf["syslog"]): return
        queue_syslog = asyncio.Queue()
        queues_list.append(queue_syslog)
        loop.create_task(output_syslog.handle(conf["syslog"], queue_syslog, stats, start_shutdown))

    if conf.get("tcp-socket", {}).get("enable", False):
        if not output_tcp.checking_conf(cfg=conf["tcp-socket"]): return
        queue_tcpsocket = asyncio.Queue()
        queues_list.append(queue_tcpsocket)
        loop.create_task(output_tcp.handle(conf["tcp-socket"], queue_tcpsocket, stats, start_shutdown))
                                               
    if conf.get("file", {}).get("enable", False):
        if not output_file.checking_conf(cfg=conf["file"]): return
        queue_file = asyncio.Queue()
        queues_list.append(queue_file)
        loop.create_task(output_file.handle(conf["file"], queue_file, stats, start_shutdown))
                                              
    if conf.get("stdout", {}).get("enable", False):
        if not output_stdout.checking_conf(cfg=conf["stdout"]): return
        queue_stdout = asyncio.Queue()
        queues_list.append(queue_stdout)
        loop.create_task(output_stdout.handle(conf["stdout"], queue_stdout, stats, start_shutdown))

    if conf.get("stdout-router", {}).get("enable", False):
        if not output_stdout_router.checking_conf(cfg=conf["stdout-router"]): return
        queue_stdout_router = asyncio.Queue()
        queues_list.append(queue_stdout_router)
        loop.create_task(output_stdout_router.handle(conf["stdout-router"], queue_stdout, stats, start_shutdown))

    if conf["metrics"]["enable"]:
        if not output_metrics.checking_conf(cfg=conf["metrics"]): return
        queue_metrics = asyncio.Queue()
        queues_list.append(queue_metrics)
        loop.create_task(output_metrics.handle(conf["metrics"], queue_metrics, stats, start_shutdown))

    if conf.get("dnstap", {}).get("enable", False):
        if not output_dnstap.checking_conf(cfg=conf["dnstap"]): return
        queue_dnstap = asyncio.Queue()
        queues_list.append(queue_dnstap)
        loop.create_task(output_dnstap.handle(conf["dnstap"], queue_dnstap, stats, start_shutdown))

    if conf.get("kafka", {}).get("enable", False):
        if not output_kafka.checking_conf(cfg=conf["kafka"]): return
        queue_kafka = asyncio.Queue()
        queues_list.append(queue_kafka)
        loop.create_task(output_kafka.handle(conf["kafka"], queue_kafka, stats, start_shutdown))

    ## Adding support for logging to multiple kafka topics.
    if conf["kafka-router"]["enable"]:
        if not output_dnstap.checking_conf(cfg=conf["kafka-router"]): return
        queue_kafka_router = asyncio.Queue()
        queues_list.append(queue_kafka_router)
        loop.create_task(output_kafka_router.handle(conf["kafka-router"], queue_kafka_router, stats, start_shutdown))

    if conf.get("pgsql", {}).get("enable", False):
        if not output_pgsql.checking_conf(cfg=conf["pgsql"]): return
        queue_pgsql = asyncio.Queue()
        queues_list.append(queue_pgsql)
        loop.create_task(output_pgsql.handle(conf["pgsql"], queue_pgsql, stats, start_shutdown))

    if conf.get("rabbitmq", {}).get("enable", False):
        if not output_rabbitmq.checking_conf(cfg=conf["rabbitmq"]): return
        queue_rabbitmq = asyncio.Queue()
        queues_list.append(queue_rabbitmq)
        loop.create_task(output_rabbitmq.handle(conf["rabbitmq"], queue_rabbitmq, stats, start_shutdown))

    if conf.get("elasticsearch", {}).get("enable", False):
        if not output_elasticsearch.checking_conf(cfg=conf["elasticsearch"]): return
        queue_elasticsearch = asyncio.Queue()
        queues_list.append(queue_elasticsearch)
        loop.create_task(output_elasticsearch.handle(conf["elasticsearch"], queue_elasticsearch, stats, start_shutdown))

    return queues_list
    
def setup_inputs(cfg, queues_outputs, stats, geoip_reader, start_shutdown):
    """setup inputs"""
    cache = cachetools.TTLCache(maxsize=1000000, ttl=60)
    cfg_input = cfg["input"]
    
    # asynchronous unix 
    if cfg_input.get("unix-socket", {}).get("enable", False):
        loop.create_task(input_socket.start_unixsocket(cfg, queues_outputs, stats, geoip_reader, cache, start_shutdown))
        
    # sniffer
    elif cfg_input.get("sniffer", {}).get("enable", False):
        queue_sniffer = asyncio.Queue()
        loop.create_task(input_sniffer.watch_buffer(cfg_input["sniffer"], queue_sniffer, queues_outputs, stats, cache, start_shutdown))
        loop.run_in_executor(None, input_sniffer.start_input, cfg_input["sniffer"], queue_sniffer, start_shutdown)
    
    # tcp client input
    elif cfg_input.get("tcp-client", {}).get("enable", False):
        loop.create_task(input_socket.start_tcpclient(cfg, queues_outputs, stats, geoip_reader, cache, start_shutdown))
        
    # default one tcp socket
    else:
        loop.create_task(input_socket.start_tcpsocket(cfg, queues_outputs, stats, geoip_reader, cache, start_shutdown))

def setup_webserver(cfg, stats):
    """setup web api"""
    if not cfg["web-api"]["enable"]: return

    svr = api_server.create_server(loop, cfg=cfg["web-api"], stats=stats, cfg_stats=cfg["statistics"])
    if svr is None: return
        
    loop.create_task( svr)
    
def setup_geoip(cfg):
    if not cfg["enable"]: return None
    if cfg["city-database"] is None: return None
    
    reader = None
    try:
        reader = geoip2.database.Reader(cfg["city-database"])
    except Exception as e:
        clogger.error("geoip setup: %s" % e)
        
    return reader

def start_shutdown_task(signal, loop, start_shutdown):
    global shutdown_task
    if not shutdown_task:
        shutdown_task = asyncio.create_task(
            shutdown(signal, loop, start_shutdown)
        )

async def shutdown(signal, loop, start_shutdown):
    """perform graceful shutdown"""

    clogger.info("starting shutting down process")
    start_shutdown.set()

    current_task = asyncio.current_task()
    tasks = [
        task for task in asyncio.all_tasks()
        if task is not current_task
    ]

    clogger.info("waiting for all tasks to exit")
    await asyncio.gather(*tasks, return_exceptions=True)

    clogger.debug("all tasks have exited, stopping loop")
    loop.stop()


def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # setup config
    cfg = setup_config(args=args)
  
    # setup logging
    setup_logger(cfg=cfg["trace"])

    # setup geoip if enabled 
    geoip_reader = setup_geoip(cfg=cfg["geoip"])
    
    # prepare shutdown handling
    start_shutdown = asyncio.Event()
    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: start_shutdown_task(sig, loop, start_shutdown))

    # add debug message if external config is used
    if args.c: clogger.debug("External config file loaded")
    
    # start receiver
    clogger.debug("Start receiver...")
    stats = statistics.Statistics(cfg=cfg["statistics"])
    loop.create_task(statistics.watcher(stats, start_shutdown))
    
    # prepare outputs
    queues_outputs = setup_outputs(cfg, stats, start_shutdown)

    # prepare inputs
    setup_inputs(cfg, queues_outputs, stats, geoip_reader, start_shutdown)

    # start the http api
    setup_webserver(cfg, stats)

    # if test, send one message in and then quit
    if args.t:
        clogger.info("test condition indicated. testing 2 dns messages for loggers.")

        for tm in TEST_MSGS:
            print(f"\nPutting tm in queue: {tm}\n")
            for q in queues_outputs:
                q.put_nowait(tm.copy())

        loop.run_forever()
                
        loop.close()
                
    else:
        # run event loop 
        try:
            loop.run_forever()
        finally:
            clogger.info("exiting, please wait..")
            loop.close()
            clogger.debug("shut down eventloop")

    # close geoip
    if geoip_reader is not None: geoip_reader.close()
