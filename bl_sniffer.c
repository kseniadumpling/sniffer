// https://people.csail.mit.edu/albert/bluez-intro/c404.html

#include "bl_sniffer.h"

int main() {
    inquiry_info *ii = NULL;
    char addr[19], name[248];
    int max_rsp = 255, len = 8;
    int flags = IREQ_CACHE_FLUSH;
    int num_rsp;

    int id = hci_get_route(NULL);
    printf("DBG: hci_get_route - id %d\n", id);
    if (id < 0) {
        perror("hci_get_route err");
        return -1;
    }

    int sock = hci_open_dev(id);
    printf("DBG: hci_open_dev - sc %d\n", sock);
    if (sock < 0) {
        perror("hci_open_dev err");
        return -1;
    }

    ii = (inquiry_info *)malloc(max_rsp * sizeof(inquiry_info));
    num_rsp = hci_inquiry(id, len, max_rsp, NULL, &ii, flags);
    printf("DBG: hci_inquiry - num_rsp %d\n", num_rsp);
    if (num_rsp < 0) {
        perror("hci_inquiry err");
    }

    for (int i = 0; i < num_rsp; i++) {
        ba2str(&(ii+i)->bdaddr, addr);
        memset(name, 0, sizeof(name));

        if (hci_read_remote_name(sock, &(ii+i)->bdaddr, sizeof(name), name, 0) < 0) {
            strcpy(name, "unknown");
        }

        printf("%s: %s", addr, name);
    }

    free(ii);
    close(sock);
    return 0;
}
