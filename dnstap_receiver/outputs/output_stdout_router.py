import asyncio
import logging
import sys

clogger = logging.getLogger("dnstap_receiver.console")
tap_logger = logging.getLogger("dnstap_receiver.output.stdout")

from dnstap_receiver.outputs import transform

class FakeProducer:
    """
    config needs: 
    {
        "db_file": "/path/to/dbfile"
    }
    optionally:
    {
        "main_delimiter": ":", ## this is the delimiter between a domain and 
                               ## the sub_delimiter-delimited list of topics.

        "sub_delimiter": ","   ## for each domain, this separates the topics its
                               ## messages should be routed to.
    }
    """

    def __init__(self, config):
        self.config = config

        if not self.config:
            clogger.critical("No file_parser config found. Unable to route messages.")
            ## TODO: Handle this.
            
        self.parse_db_file(config)
        

    def parse_db_file(self, parser_config):
        db_file = parser_config.get("db_file", False)
        if not db_file:
            clogger.critical("No db_file specified in stdout_router config.")

        file_path = parser_config.get("file_path", None)
        main_delimiter = parser_config.get("main_delimiter", ":")
        sub_delimiter = parser_config.get("sub_delimiter", ",")


        dom_map = {}
        self.topics = set()
        
        with open(db_file, "r") as f:
            for line in f:
                line = line.strip()
                dom, topics = line.split(main_delimiter)
                topics = topics.split(sub_delimiter)
                dom_map[dom] = topics
                self.topics = self.topics.union(topics)
    
        self.dom_map = dom_map
    
    
    def produce(self, msg):
        qname = msg["qname"]
        msg_topics = self.dom_map.get(transform.processed_qname(qname), [])
        for m_t in msg_topics:
            print(f"Produced message topic: {m_t} | qname: {qname}\nProduced message: {msg}\n")
    
def setup_loggers():
    """setup loggers"""
    logfmt = '%(message)s'
    
    tap_logger.setLevel(logging.INFO)
    tap_logger.propagate = False
    
    lh = logging.StreamHandler(stream=sys.stdout)
    lh.setLevel(logging.INFO)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    tap_logger.addHandler(lh)

def handle_msg(tapmsg: dict, producer: FakeProducer) -> None:
    # convert dnstap message
    msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
    
    ## NEW: If transform returns none, that means it should not be converted to this.
    if not msg:
        return
    
    # print to stdout
    producer.produce(msg)

    
async def handle(output_cfg, queue, metrics, start_shutdown):
    """stdout output handler"""

    # init logger
    setup_loggers()
    ## router = StdoutLogRouter(output_cfg, topic, start_shutdown)
    
    producer = FakeProducer(output_cfg)
        
    while not start_shutdown.is_set():
        # read item from queue
        try:
            print("Waiting for tapmsg...", end="\r")
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue

        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg, cfg=output_cfg)
        
        ## NEW: If transform returns none, that means it should not be logged.
        if not msg:
            continue
            
        ## breaking out into this function to make it more testable.
        producer.produce(tapmsg)
        
        # all done
        queue.task_done()
        

## dnspy/env/lib/python3.8/site-packages/dnstap_receiver/