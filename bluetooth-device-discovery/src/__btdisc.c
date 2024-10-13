#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <pthread.h>
#include <signal.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define BRIGHT_YELLOW     "\x1b[93m"
#define BRIGHT_GREEN      "\x1b[92m"
#define BRIGHT_PINK       "\x1b[95m"
#define BRIGHT_BLUE       "\x1b[94m"

volatile sig_atomic_t keep_running = 1;

void *discover_devices_continuous(void *arg) {
    int dev_id, sock, len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Could not get HCI device ID.\n");
        pthread_exit(NULL);
    }

    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Could not open HCI socket.\n");
        pthread_exit(NULL);
    }

    len  = 2; // Scan for 2 seconds per iteration
    flags = IREQ_CACHE_FLUSH;

    while (keep_running) {
        printf(BRIGHT_BLUE "\nScanning for devices...\n" ANSI_COLOR_RESET);

        inquiry_info *ii = NULL;
        int max_rsp = 255;
        ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
        if (ii == NULL) {
            fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Memory allocation failed.\n");
            close(sock);
            pthread_exit(NULL);
        }

        int num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &ii, flags);
        if (num_rsp < 0) {
            fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "HCI inquiry failed.\n");
            free(ii);
            close(sock);
            pthread_exit(NULL);
        }

        for (i = 0; i < num_rsp; i++) {
            ba2str(&(ii + i)->bdaddr, addr);
            memset(name, 0, sizeof(name));
            if (hci_read_remote_name(sock, &(ii + i)->bdaddr, sizeof(name), name, 0) < 0) {
                strcpy(name, "[unknown]");
            }

            printf(BRIGHT_GREEN "Found device:\n" ANSI_COLOR_RESET);
            printf(BRIGHT_YELLOW "  MAC Address: " ANSI_COLOR_RESET "%s\n", addr);
            printf(BRIGHT_PINK "  Name: " ANSI_COLOR_RESET "%s\n", name);
        }

        free(ii);
        sleep(1); // Pause for 1 second between scans
    }

    close(sock);
    pthread_exit(NULL);
}

void signal_handler(int signum) {
    keep_running = 0;
}

int main() {
    pthread_t discovery_thread;
    
    signal(SIGINT, signal_handler); // Capture Ctrl+C

    printf(ANSI_COLOR_CYAN "\n\n--- Continuous Bluetooth Device Discovery ---\n\n" ANSI_COLOR_RESET);
    printf(BRIGHT_YELLOW "Press Ctrl+C to stop.\n\n" ANSI_COLOR_RESET);

    if (pthread_create(&discovery_thread, NULL, discover_devices_continuous, NULL) != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Could not create discovery thread.\n");
        return 1;
    }

    pthread_join(discovery_thread, NULL); // Wait for the thread to finish

    printf(BRIGHT_BLUE "\nDiscovery stopped.\n" ANSI_COLOR_RESET);
    return 0;
}
