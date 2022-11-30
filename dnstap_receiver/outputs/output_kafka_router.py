import asyncio
import logging
import threading

try:
    import confluent_kafka
    has_kafka = True
except:
    has_kafka = False

clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver.outputs import transform


## TODO: Add load of database, all tasks from router
## produce according to parsed topics.

class Router:
    def __init__(self, config, start_shutdown):
        self.loop = asyncio.get_event_loop()
        self.start_shutdown = start_shutdown
        self.config = config
        self.polling_task = asyncio.create_task(self.polling_task())
        self.producer = confluent_kafka.Producer(config['rdkafka-config'])            
        self.parse_db_file(config)
        
    async def polling_task(self):
        while not self.start_shutdown.is_set():
            await asyncio.to_thread(self.producer.poll, 1)

        clogger.debug("Output handler: kafka: performing last flush")
        self.producer.flush()
        clogger.info("Output handler: kafka: polling task stopped")
        

    def parse_db_file(self, parser_config):
        db_file = parser_config.get("db_file", False)
        if not db_file:
            clogger.critical("No db_file specified in kafka-router config.")

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
            self.producer.produce(m_t, msg)
            self.producer.poll(0)


###########

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: kafka")

    valid_conf = True

    if not has_kafka:
        valid_conf = False
        clogger.error("Output handler: kafka-router: confluent_kafka dependency is missing")

    if cfg["kafka-router"]["bootstrap.servers"] is None:
        valid_conf = False
        clogger.error("Output handler: kafka-router: no bootstrap.servers provided")

    ## Add this as default in config.
    if cfg["file_path"] is None:
        valid_conf = False
        clogger.error("Output handler: kafka-router: no topic provided")

    return valid_conf


async def handle(output_cfg, queue, metrics, start_shutdown):
    start_shutdown_producer = asyncio.Event()
    producer = Router(output_cfg, start_shutdown_producer)

    clogger.info("Output handler: kafka: Enabled")
    while not start_shutdown.is_set():
        try:
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
            
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg, cfg=output_cfg)
        
        if not msg:
            continue

        producer.produce(msg)
        queue.task_done()

    # tell producer to shut down
    clogger.info("Output handler: kafka: Triggering producer shutdown")
    start_shutdown_producer.set()
