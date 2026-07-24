#pragma once
#include <stdint.h>

/* List Kerberos tickets for the current logon session.
 * Tries klist first; falls back to LSA KerbQueryTicketCacheExMessage.
 * Returns heap-allocated string; caller must free(). */
char* kerb_list_tickets(void);

/* Import a base64-encoded .kirbi ticket via KerbSubmitTicketMessage.
 * Returns heap-allocated status string; caller must free(). */
char* kerb_pass_ticket(const char *b64_ticket);

/* Purge all Kerberos tickets for the current logon session
 * via KerbPurgeTicketCacheMessage.
 * Returns heap-allocated status string; caller must free(). */
char* kerb_purge(void);
