#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libbluetoothdiscovery.h"

#define MAX_RESPONSES 255
#define BLUETOOTH_NAME_MAX 248

// Global variables
static int dev_id;
static int inquiry_running = 0;
static BluetoothDevice *devices = NULL;
static int num_devices = 0;
static pthread_mutex_t device_list_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to handle inquiry results
static void handle_inquiry_results(int num_results, inquiry_info *results) {
    int i;
    for (i = 0; i < num_results; i++) {
        char addr[18];
        ba2str(&results[i].bdaddr, addr);

        // Allocate memory for the name dynamically
        char *name = malloc(BLUETOOTH_NAME_MAX);
        if (name == NULL) {
            perror("malloc");
            return; // Handle allocation error
        }
        memset(name, 0, BLUETOOTH_NAME_MAX);

        // Read the remote name with a timeout (e.g., 1 second)
        int timeout_ms = 1000; 
        if (hci_read_remote_name(dev_id, &results[i].bdaddr, BLUETOOTH_NAME_MAX, name, timeout_ms) < 0) {
            // Handle the error, maybe set a default name
            strcpy(name, "[unknown]"); 
        }

        // Add the device to the list
        pthread_mutex_lock(&device_list_mutex);
        devices = realloc(devices, (num_devices + 1) * sizeof(BluetoothDevice));
        if (devices == NULL) {
            perror("realloc");
            free(name); // Free the name buffer
            pthread_mutex_unlock(&device_list_mutex);
            return;
        }
        devices[num_devices].address = results[i].bdaddr;
        strncpy(devices[num_devices].name, name, BLUETOOTH_NAME_MAX);
        num_devices++;
        pthread_mutex_unlock(&device_list_mutex);

        free(name); // Free the name buffer after use
    }
}


// Function to start continuous discovery
static void* discovery_thread(void *arg) {
    inquiry_info *results = NULL;
    int max_responses = 255;
    int flags = IREQ_CACHE_FLUSH;

    while (inquiry_running) {
        // Allocate memory for inquiry results
        results = malloc(max_responses * sizeof(inquiry_info));
        if (results == NULL) {
            perror("malloc");
            continue; // Skip this iteration if allocation fails
        }

        int num_results = hci_inquiry(dev_id, 10, max_responses, NULL, &results, flags);
        if (num_results < 0) {
            perror("hci_inquiry");
        } else if (num_results > 0) {
            handle_inquiry_results(num_results, results);
        }

        free(results);
    }
    return NULL;
}

int bluetooth_init() {
    dev_id = hci_open_dev(0);
    if (dev_id < 0) {
        perror("hci_open_dev");
        return BT_ERROR_INIT;
    }
    return BT_SUCCESS;
}

int bluetooth_start_discovery() {
    if (inquiry_running) {
        return BT_ERROR_DISCOVERY;
    }
    pthread_t thread;
    inquiry_running = 1;
    if (pthread_create(&thread, NULL, discovery_thread, NULL) != 0) {
        perror("pthread_create");
        inquiry_running = 0;
        return BT_ERROR_DISCOVERY;
    }
    return BT_SUCCESS;
}

int bluetooth_stop_discovery() {
    if (!inquiry_running) {
        return BT_ERROR_DISCOVERY;
    }
    inquiry_running = 0;
    return BT_SUCCESS;
}

BluetoothDevice* bluetooth_get_devices(int *num_devices_out) {
    pthread_mutex_lock(&device_list_mutex);

    // Use num_devices_out to return the number of devices
    *num_devices_out = num_devices; 

    // Allocate memory for the copy
    BluetoothDevice *device_copy = malloc(num_devices * sizeof(BluetoothDevice));
    if (device_copy == NULL) {
        perror("malloc");
        pthread_mutex_unlock(&device_list_mutex);
        return NULL;
    }

    // Copy the data
    memcpy(device_copy, devices, num_devices * sizeof(BluetoothDevice));

    pthread_mutex_unlock(&device_list_mutex);
    return device_copy;
}

void bluetooth_free_devices(BluetoothDevice *devices) {
    free(devices);
}
