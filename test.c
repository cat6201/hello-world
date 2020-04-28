#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <time.h>

#define ZYLOG_MAX_MESSAGE_LEN		1024
#define BUF_LEN 256
/* Netconf daemon offline reason code. */
enum{
    DNS_FAILED = 0,
    GATEWAY_UNAVAILABLE,
    PING_FAILED,
    CERT_FAILED,
    REASON_CODE_MAX
};

struct {
    int32_t index;
    char *reason;
} reason_table[] = { 
    {  DNS_FAILED, " DNS queries failed."  },  
    {  GATEWAY_UNAVAILABLE, " Gateway is unavailable."  },  
    {  PING_FAILED, " Ping failed."  },  
    {  CERT_FAILED, " Get certificate failed." },
    {  -1, NULL  }//end
}, *reason_item = reason_table;

int32_t zylog_agent_in_netconf(char* msg, uint32_t* reason_code, int write_zylog)
{
	char log_buf[ZYLOG_MAX_MESSAGE_LEN] = {'\0'};
	char* end_pointer = NULL;
	char db_msg[BUF_LEN];
	char db_reason[BUF_LEN] = {'\0'};
	char db_log[BUF_LEN];

	if(*reason_code){   /* Reason recorded */
		sprintf( log_buf, "%s Relevant to", msg );
		for( reason_item = reason_table; reason_item->reason; ++reason_item){
			printf("%d %d\n", 1U << reason_item->index, reason_item->index);
			printf("reason_code = %d\n", *reason_code);
			if( *reason_code & (1U << reason_item->index) ){
				strncat( log_buf, reason_item->reason, ( ZYLOG_MAX_MESSAGE_LEN - strlen(log_buf) - 1 ) );
				printf("log_buf = %s\n", log_buf);
				printf("%ld\n", ( ZYLOG_MAX_MESSAGE_LEN - strlen(log_buf) - 1 ));
				strncat( db_reason, reason_item->reason, ( ZYLOG_MAX_MESSAGE_LEN - strlen(log_buf) - 1 ) );
				printf("db_reason = %s, strlen(db_reason) = %ld\n", db_reason, strlen(db_reason));
			}
		}
		sprintf(db_log,"(%s)",db_reason);
		printf("db_log = %s\n", db_log);
		end_pointer = strrchr(db_log, '.');
		//end_pointer = NULL;
		*end_pointer = ' ';
		//set_to_db(NEBULA_TABLE_NAME, STATUS_KEY_NAME, "connect_failed_reason", db_log, db_msg);
	} else {
		sprintf( log_buf, "%s", msg );
	}
	printf("log_buf = %s\n", log_buf);
	return 0;
}

typedef struct {
	double width, height;
} size_s;

size_s width_height(char *papertype){
	return
		!strcasecmp(papertype, "A4") ? (size_s) {.width=210, .height=297}
	: !strcasecmp(papertype, "Letter") ? (size_s) {.width=216, .height=279}
	: !strcasecmp(papertype, "Legal") ? (size_s) {.width=216, .height=356}
	: (size_s) {.width=NAN, .height=NAN};
}

void fnA(){
	printf("A\n");
}

void fnB(){
	printf("B\n");
}

typedef struct
{
	uint64_t interval;	 /* How often to call the task */
	void (*proc)(void); /* pointer to function returning void */
} TIMED_TASK;
static const TIMED_TASK timed_task[] =
{
	{ 2,		fnA },
	{ 6,		fnB },
	{ 0, NULL }
};
uint64_t getTick() {
	struct timespec ts;
	clock_gettime( CLOCK_REALTIME, &ts );

	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void main2(void)
{
	uint64_t time = 0, tick = getTick()/1000;
	const TIMED_TASK *ptr;
	/* Initialization code goes here. Then enter the main loop */
	while (1)
	{
		//time = getTick()/1000 - tick;
		//printf("%ld\n", getTick()/1000);
		++time;
		printf("%" PRIu64 "\n", time);
		for (ptr = timed_task; ptr->interval !=0; ptr++)
		{
			if (!(time % ptr->interval))
			{
				/* Time to call the function */
				(ptr->proc)();
			}
		}
		sleep(1);
	}
}

#define PORTAL_MAC_STR_LEN          32
#define UAM_USERNAME_LEN            64
#define PORTAL_ASSO_TIME_LEN        16
#define PORTAL_LOGOUT_TIME_LEN      16
#define PORTAL_METHOD_LEN           16
#define PORTAL_LOCALE_LEN           16
#define PORTAL_GENDER_LEN           16
#define PORTAL_AGE_LEN          16
#define SOCIAL_LOGIN_ATTRIBUTE_UNACQUIRED   "N/A"
#define PORTAL_SSID_LEN             64
#define PROFILE_NAME_LEN            64

typedef struct auth_sta_s
{
	struct auth_sta_s *next;
	char mac_addr[PORTAL_MAC_STR_LEN];
	char user[UAM_USERNAME_LEN];
	char asso_time[PORTAL_ASSO_TIME_LEN];
	char logout_time[PORTAL_LOGOUT_TIME_LEN];
	char auth_type[PORTAL_METHOD_LEN];
	char locale[PORTAL_LOCALE_LEN];
	char gender[PORTAL_GENDER_LEN];
	char age[PORTAL_AGE_LEN];
	char ssid[PORTAL_SSID_LEN];
	char ssid_profile[PROFILE_NAME_LEN];
} auth_sta_t;

static void get_sta_from_line(char *line, auth_sta_t *sta) {
	if(sta == NULL || line == NULL)
		return;
	char *tmpBegin = line;
	char *pch = NULL;
	size_t len = 0;
	int i = 0;
	do {
		/* MAC */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->mac_addr, tmpBegin, len);
		sta->mac_addr[len] = '\0';
		tmpBegin += (len + 1); 

		/* user */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->user, tmpBegin, len);
		sta->user[len] = '\0';
		tmpBegin += (len + 1); 

		/* asso_time */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->asso_time, tmpBegin, len);
		sta->asso_time[len] = '\0';
		tmpBegin += (len + 1); 

		/* logout_time */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->logout_time, tmpBegin, len);
		sta->logout_time[len] = '\0';
		tmpBegin += (len + 1); 

		/* auth_type */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->auth_type, tmpBegin, len);
		sta->auth_type[len] = '\0';
		tmpBegin += (len + 1);
		/* locale */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->locale, tmpBegin, len);
		sta->locale[len] = '\0';
		tmpBegin += (len + 1);

		/* gender */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->gender, tmpBegin, len);
		sta->gender[len] = '\0';
		tmpBegin += (len + 1);

		/* age */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->age, tmpBegin, len);
		sta->age[len] = '\0';
		tmpBegin += (len + 1);
		/* ssid */
		if ((pch = strchr(tmpBegin, ',')) == NULL) {
			break;
		}
		len = (size_t) (pch - tmpBegin);
		strncpy(sta->ssid, tmpBegin, len);
		sta->ssid[len] = '\0';
		tmpBegin += (len + 1);

		/* ssid_profile, the last element, which may end with newline (because we call fgets), we have to trim it */
		/* the last line in the file may not end with newline */
		strncpy(sta->ssid_profile, tmpBegin, 64);
		for (i = 0; i < 64; ++i) {
			if (sta->ssid_profile[i] == '\n') {
				sta->ssid_profile[i] = '\0';
			}
		}

	} while (0);
}

static void insert_sta(auth_sta_t **node, auth_sta_t *sta) {
    if(sta == NULL)
        return;

    if(*node == NULL) {
        *node = sta;
        (*node)->next = NULL;
    } else {
        sta->next = *node;
        *node = sta;
    }
}

void print(auth_sta_t **node){
	if(node == NULL)
	printf("NULL\n");
	auth_sta_t *tmp = *node;
	while(tmp){
		printf("mac=%s\n", (tmp->mac_addr)?tmp->mac_addr:"N/B");
		printf("user=%s\n", (tmp->user)?tmp->user:"N/B");
		printf("asso_time=%s\n", (tmp->asso_time)?tmp->asso_time:"N/B");
		printf("logout_time=%s\n", (tmp->logout_time)?tmp->logout_time:"N/B");
		printf("auth_type=%s\n", (tmp->auth_type)?tmp->auth_type:"N/B");
		printf("locale=%s\n", (tmp->locale)?tmp->locale:"N/B");
		printf("gender=%s\n", (tmp->gender)?tmp->gender:"N/B");
		printf("age=%s\n", (tmp->age)?tmp->age:"N/B");
		printf("ssid=%s\n", (tmp->ssid[0] != '\0')?tmp->ssid:"N/B");
		printf("ssid_profile=%s\n", (tmp->ssid_profile[0] != '\0')?tmp->ssid_profile:"N/B");
		tmp = tmp->next;
	}
}

struct uam_handle
{
    int fd; 

#define UAM_MODE_QUERY      0
#define UAM_MODE_LISTEN     1
    u_int8_t mode;
};

int
uam_destroy_handle(struct uam_handle *h)
{
    if (h) {
        close(h->fd);
        free(h);
    }    
    return 0;
}

void main(void) {
	struct uam_handle *h = malloc(sizeof(*h));
	printf("%p\n", h);
	uam_destroy_handle(h);
}
