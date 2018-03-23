#include <dtrace.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/module.h>

#include "dlog_client.h"
#include "dl_memory.h"
#include "dl_utils.h"

static int event_handler(struct module *, int, void *);
static void konsumer_main(void *);

static moduledata_t konsumer_conf = {
	"konsumer",
	event_handler,
	NULL
};
	
static struct proc *dlog_client_proc;

/* Configure the distributed log logging level. */
unsigned short PRIO_LOG = PRIO_LOW;

void * my_malloc(unsigned long len);
void my_free(void *addr);

const dlog_malloc_func dlog_alloc = my_malloc;
const dlog_free_func dlog_free = my_free;

MALLOC_DECLARE(M_DLOG);
MALLOC_DEFINE(M_DLOG, "dlog", "DLog memory");

void
my_free(void *addr)
{
	return free(addr, M_DLOG);
}

void *
my_malloc(unsigned long len)
{
	return malloc(len, M_DLOG, M_NOWAIT);
}

static char const * const DLC_DEFAULT_CLIENT_ID = "konsole";
static char const * const DLC_DEFAULT_TOPIC  = "default";
static char const * const DLC_DEFAULT_HOSTNAME  = "localhost";
static const int DLC_DEFAULT_PORT = 9092;

static void dlp_on_response(struct dl_response const * const);

static void
dlp_on_response(struct dl_response const * const response)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_topic *produce_topic;
	int partition;

	DLOGTR1(PRIO_LOW, "correlation id = %d\n", response->dlrs_correlation_id);
	DLOGTR1(PRIO_LOW, "api key= %d\n", response->dlrs_api_key);

	switch (response->dlrs_api_key) {
	case DL_PRODUCE_API_KEY:
		produce_response = response->dlrs_message.dlrs_produce_message;

		DLOGTR1(PRIO_LOW, "ntopics= %d\n", produce_response->dlpr_ntopics);

		SLIST_FOREACH(produce_topic,
			&produce_response->dlpr_topics, dlprt_entries) {

			DLOGTR1(PRIO_LOW, "Topic: %s\n",
				sbuf_data(produce_topic->dlprt_topic_name));

			for (partition = 0;
			    partition < produce_topic->dlprt_npartitions;
			    partition++) {

				DLOGTR1(PRIO_LOW, "Partition: %d\n",
				    produce_topic->dlprt_partitions[partition].dlprp_partition);

				DLOGTR1(PRIO_LOW, "ErrorCode: %d\n",
				    produce_topic->dlprt_partitions[partition].dlprp_error_code);

				DLOGTR1(PRIO_LOW, "Base offset: %ld\n",
					produce_topic->dlprt_partitions[partition].dlprp_offset);
			};
		};
		break;
	default:
		DLOGTR1(PRIO_HIGH, "Unexcepted Response %d\n",
		    response->dlrs_api_key);
		break;
	}

}



static int
event_handler(struct module *module, int event, void *arg)
{
	int e = 0, rc;

	switch(event) {
	case MOD_LOAD:
		DLOGTR0(PRIO_LOW, "Loading Konsumer kernel module\n");
		rc = kproc_create(konsumer_main, NULL, &dlog_client_proc, 0, 0, "konsumer");
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading Konsumer kernel module\n");
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static void
konsumer_main(void *argp)
{
	struct dlog_handle *handle;
	struct dl_client_configuration cc;
	struct sbuf *client_id;
	struct sbuf *hostname;
	struct sbuf *topic;
	int port = DLC_DEFAULT_PORT;

	dtrace_icookie_t cookie;
	cookie = dtrace_interrupt_disable();
	dtrace_interrupt_enable(cookie);

	/* Configure the default values for the client_id, topic and hostname. */
	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, DLC_DEFAULT_CLIENT_ID);
	sbuf_finish(client_id);

	hostname = sbuf_new_auto();
	sbuf_cpy(hostname, DLC_DEFAULT_HOSTNAME);
	sbuf_finish(hostname);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, DLC_DEFAULT_TOPIC);
	sbuf_finish(topic);

	/* Configure and initialise the distributed log client. */
	cc.dlcc_on_response = dlp_on_response;
	cc.dlcc_client_id = client_id;
	cc.to_resend = true;
	cc.resend_timeout = 40;
	cc.resender_thread_sleep_length = 10;
	cc.request_notifier_thread_sleep_length = 3;
	cc.reconn_timeout = 5;
	cc.poll_timeout = 3000;

	handle = dlog_client_open(hostname, port, &cc);
        if (handle == NULL) {
	 	DLOGTR0(PRIO_HIGH,	
		    "Error initialising the distributed log client.\n");
		kproc_exit(-1);
	}
	
	pause("test", 3);
  
	if (dlog_produce(handle, topic, "key", strlen("key"), "test", strlen("test")) == 0) {
		DLOGTR0(PRIO_LOW, "Successfully produced message to DLog\n");
	}
	pause("test", 3);

	/* Close the distributed log before finishing. */
	dlog_client_close(handle);

	/* Delete the sbufs used by the DLog client. */
	sbuf_delete(topic);
	sbuf_delete(hostname);
	sbuf_delete(client_id);

	kproc_exit(0);
}

DECLARE_MODULE(konsumer, konsumer_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(konsumer, 1);
MODULE_DEPEND(konsumer, dtrace, 1, 1, 1);
