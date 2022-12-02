/**
 * Combined bans module for charybis based IRCds.
 * -- hyperdrive 
 *
 * Examples:
 * 	
 *		/mode #channel +b $b:&~a;*!*@*fuck*$#banned <-- Ban anyone unidentified AND with fuck in host - also forward them to channel.
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"

static int _modinit(void);
static void _moddeinit(void);
static int eb_combined(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type);

DECLARE_MODULE_AV1(extb_combine, _modinit, _moddeinit, NULL, NULL, NULL, "$Revision: 2 $");

static int _modinit(void) {
	extban_table['b'] = eb_combined;

	return 0;
}

static void _moddeinit(void) {
	extban_table['b'] = NULL;
}

int ban_match(const char *ban, struct Client *client_p, struct Channel *chptr, long mode_type) {
	char src_host[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_iphost[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_althost[NICKLEN + USERLEN + HOSTLEN + 6];

	char extban[192];

	strcpy(extban, "$");
	memmove(ban, ban+1, strlen(ban));
	strcat(extban, ban);

	rb_sprintf(src_host, "%s!%s@%s", client_p->name, client_p->username, client_p->host);
	rb_sprintf(src_iphost, "%s!%s@%s", client_p->name, client_p->username, client_p->sockhost);

	if(client_p->localClient->mangledhost != NULL) {
		if(!strcmp(client_p->host, client_p->localClient->mangledhost)) {
			rb_sprintf(src_althost, "%s!%s@%s", client_p->name, client_p->username, client_p->orighost);
		} else if(!IsDynSpoof(client_p)) {
			rb_sprintf(src_althost, "%s!%s@%s", client_p->name, client_p->username, client_p->localClient->mangledhost);
		}
	}

	if(match(ban, src_host) ||
		match(ban, src_iphost) ||
		match_cidr(ban, src_iphost) ||
		match_extban(extban, client_p, chptr, mode_type) ||
		match(ban, src_althost)) {
		return 1;
	} else {
		return 0;
	}
}

static int eb_combined(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type) {
	(void)chptr;

	char ban1[192];
	char *ban2;

	if (data == NULL || strstr(data, ",") == NULL || strstr(data, "&m") != NULL) {
		return EXTBAN_INVALID;
	} else if (strstr(data, ",")) {
		strcpy(ban1, data); // first banmask
		strtok_r(ban1, ",", &ban2); // second banmask

		if(ban_match(ban1, client_p, chptr, mode_type) && ban_match(ban2, client_p, chptr, mode_type)) {
			return EXTBAN_MATCH;
		} else {
			return EXTBAN_NOMATCH;
		}
	} else {
		return EXTBAN_INVALID;
	}
}