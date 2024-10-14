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
static BluetoothDevice *device = NULL;
static pthread_mutex_t device_list_mutex = PTHREAD_MUTEX_INITIALIZER;

int bluetooth_init_adapter() {
    dev_id = hci_open_dev(0);
    if (dev_id < 0) {
        perror("hci_open_dev");
        return BT_ERROR_INIT;
    }
    return BT_SUCCESS;
}

int bluetooth_stop_adapter() {
    
}
