#ifndef BTDISC_H
#define BTDISC_H

#include <bluetooth/bluetooth.h>
#include <pthread.h> // For thread safety

// Maximum device name length
#define BLUETOOTH_NAME_MAX 248

// Error codes
#define BT_SUCCESS 0
#define BT_ERROR_INIT -1
#define BT_ERROR_DISCOVERY -2
#define BT_ERROR_MEMORY -3

// Structure to represent a discovered device
typedef struct {
    bdaddr_t address; 
    char name[BLUETOOTH_NAME_MAX];
} BluetoothDevice;

// Initialize the discovery library
int bluetooth_init();

// Start continuous Bluetooth device discovery
int bluetooth_start_discovery();

// Stop continuous discovery
int bluetooth_stop_discovery();

// Get a list of discovered devices
BluetoothDevice* bluetooth_get_devices(int *num_devices);

// Free the memory allocated for the device list
void bluetooth_free_devices(BluetoothDevice *devices);

#endif 
