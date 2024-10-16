#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Add this line
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void discover_devices() {
    inquiry_info *ii = NULL;
    int max_rsp, num_rsp;
    int dev_id, sock, len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    dev_id = hci_get_route(NULL);
    sock = hci_open_dev(dev_id);
    if (dev_id < 0 || sock < 0) {
        perror("opening socket");
        return;
    }

    len  = 8; // Scan for 8 seconds
    max_rsp = 255;
    flags = IREQ_CACHE_FLUSH;
    ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));

    num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &ii, flags);
    if (num_rsp < 0) {
        perror("hci_inquiry");
        free(ii);
        close(sock);
        return;
    }

    printf(ANSI_COLOR_CYAN "\n\n--- Bluetooth Device Discovery ---\n\n" ANSI_COLOR_RESET);

    for (i = 0; i < num_rsp; i++) {
        ba2str(&(ii + i)->bdaddr, addr);
        memset(name, 0, sizeof(name));
        if (hci_read_remote_name(sock, &(ii + i)->bdaddr, sizeof(name), name, 0) < 0) {
            strcpy(name, "[unknown]");
        }

        printf(ANSI_COLOR_GREEN "Device %d:\n" ANSI_COLOR_RESET, i + 1);
        printf(ANSI_COLOR_YELLOW "  MAC Address: " ANSI_COLOR_RESET "%s\n", addr);
        printf(ANSI_COLOR_BLUE "  Name: " ANSI_COLOR_RESET "%s\n\n", name);
    }

    free(ii);
    close(sock);
}

int main() {
    discover_devices();
    return 0;
}
