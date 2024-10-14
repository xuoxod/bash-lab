#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bluetooth/hci_lib.h> // Include for hci_open_dev()
#include <sys/ioctl.h> // For ioctl()
#include <sys/time.h> // For gettimeofday()

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define BRIGHT_YELLOW     "\x1b[93m"
#define BRIGHT_GREEN      "\x1b[92m"
#define BRIGHT_PINK       "\x1b[95m"
#define BRIGHT_BLUE       "\x1b[94m"

// Common RFCOMM channels
const int common_channels[] = {1, 3, 5, 7, 17, 19, 21, 23, 25, 27, 29, 31};
const int num_common_channels = sizeof(common_channels) / sizeof(common_channels[0]);

// Structure to hold Bluetooth device information
typedef struct {
    char mac_address[18];
    char name[248];
} BluetoothDeviceInfo;

// Function to get the current time in milliseconds
long long getCurrentTimeMillis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Function to get the MAC address from user input
int get_mac_address_from_user(char *mac_address) {
    printf(BRIGHT_YELLOW "Enter Bluetooth MAC address (XX:XX:XX:XX:XX:XX): " ANSI_COLOR_RESET);
    if (scanf("%17s", mac_address) != 1) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Invalid MAC address format.\n");
        return -1;
    }
    return 0;
}

// Function to get a MAC address from a CSV file, selecting only one
BluetoothDeviceInfo get_mac_address_from_csv(const char *filename) {
    BluetoothDeviceInfo device = {0}; // Initialize with zeros

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Could not open CSV file: %s\n", filename);
        return device; // Return an empty device
    }

    char line[256];
    // Skip the header line
    fgets(line, sizeof(line), fp); 

    // Read the first data line (assuming only one device is needed)
    if (fgets(line, sizeof(line), fp) != NULL) {
        char *token = strtok(line, ",");
        if (token != NULL) {
            strncpy(device.mac_address, token, sizeof(device.mac_address) - 1);
        }
        token = strtok(NULL, ",");
        if (token != NULL) {
            strncpy(device.name, token, sizeof(device.name) - 1);
        }
    }

    fclose(fp);
    return device;
}

// Function to check if a device supports RFCOMM
int check_rfcomm_support(int dev_id, const char *mac_address) {
    struct hci_request rq = {0};
    struct hci_dev_info info = {0};
    int status;

    // Get device information
    rq.dev = dev_id;
    rq.type = HCI_REQ_DEV_INFO;
    rq.arg = &info;
    status = hci_send_req(dev_id, &rq, sizeof(info));
    if (status < 0) {
        perror("hci_send_req");
        return -1;
    }

    // Check if RFCOMM is supported
    if (info.rfcomm_max_ports > 0) {
        return 1; // RFCOMM supported
    } else {
        return 0; // RFCOMM not supported
    }
}

// Function to find available RFCOMM channels on a device
int find_rfcomm_channels(int dev_id, const char *mac_address) {
    struct hci_request rq = {0};
    struct hci_dev_info info = {0};
    int status;
    int channel = -1;

    // Get device information
    rq.dev = dev_id;
    rq.type = HCI_REQ_DEV_INFO;
    rq.arg = &info;
    status = hci_send_req(dev_id, &rq, sizeof(info));
    if (status < 0) {
        perror("hci_send_req");
        return -1;
    }

    // Check if RFCOMM is supported
    if (info.rfcomm_max_ports > 0) {
        // Iterate through common channels and check if they are available
        for (int i = 0; i < num_common_channels; i++) {
            if (info.rfcomm_ports[common_channels[i] - 1] == 0) {
                channel = common_channels[i];
                break;
            }
        }
    }

    return channel;
}

// Function to connect to a Bluetooth device
int connect_to_device(int dev_id, const char *mac_address, int channel) {
    struct sockaddr_rc addr = {0};
    int sock, status;

    // Allocate a socket
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set connection parameters
    addr.rc_family = AF_BLUETOOTH;
    str2ba(mac_address, &addr.rc_bdaddr);
    addr.rc_channel = (uint8_t)channel;

    // Connect to the server
    printf(BRIGHT_BLUE "Connecting to %s on channel %d...\n" ANSI_COLOR_RESET, mac_address, channel);
    status = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (status < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    printf(BRIGHT_GREEN "Connection successful!\n" ANSI_COLOR_RESET);
    return sock;
}

// Function to handle communication with the connected device
void *handle_connection(void *arg) {
    int sock = *(int *)arg;
    char buffer[1024];
    ssize_t bytes_read;

    while ((bytes_read = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf(BRIGHT_CYAN "Received: %s\n" ANSI_COLOR_RESET, buffer);
    }

    if (bytes_read == 0) {
        printf(BRIGHT_YELLOW "Connection closed by remote device.\n" ANSI_COLOR_RESET);
    } else if (bytes_read < 0) {
        perror("read");
    }

    close(sock);
    pthread_exit(NULL);
}

// Function to initialize the Bluetooth adapter
int bluetooth_init_adapter() {
    int dev_id = hci_open_dev(0); // Open the default Bluetooth device
    if (dev_id < 0) {
        perror("hci_open_dev");
        return -1; // Indicate an error
    }
    // You might want to store dev_id for later use if needed
    return dev_id; // Indicate success
}

// Function to attempt pairing with a device
int pair_with_device(int dev_id, const char *mac_address) {
    struct hci_request rq = {0};
    struct hci_dev_info info = {0};
    int status;
    int attempt = 0;
    int max_attempts = 3;

    // Get device information
    rq.dev = dev_id;
    rq.type = HCI_REQ_DEV_INFO;
    rq.arg = &info;
    status = hci_send_req(dev_id, &rq, sizeof(info));
    if (status < 0) {
        perror("hci_send_req");
        return -1;
    }

    // Check if pairing is needed
    if (info.flags & HCI_DEV_FLAG_LINK_NO_ENCRYPT) {
        printf(BRIGHT_YELLOW "Pairing with device %s is required.\n" ANSI_COLOR_RESET, mac_address);

        // Attempt pairing
        while (attempt < max_attempts) {
            status = hci_create_connection(dev_id, mac_address, 0, 0, 0, 0);
            if (status >= 0) {
                printf(BRIGHT_GREEN "Pairing successful!\n" ANSI_COLOR_RESET);
                return 0;
            } else {
                printf(BRIGHT_YELLOW "Pairing attempt %d failed. Retrying...\n" ANSI_COLOR_RESET, attempt + 1);
                attempt++;
                sleep(1); // Wait for a second before retrying
            }
        }

        printf(BRIGHT_RED "Pairing failed after %d attempts.\n" ANSI_COLOR_RESET, max_attempts);
        return -1;
    } else {
        printf(BRIGHT_GREEN "Device %s is already paired.\n" ANSI_COLOR_RESET, mac_address);
        return 0;
    }
}

int main(int argc, char *argv[]) {
    char mac_address[18];
    int sock;
    pthread_t comm_thread;
    int dev_id;
    int channel = common_channels[0]; // Default channel

    if (argc > 3) {
        fprintf(stderr, "Usage: %s [mac_address|csv_filename] [channel]\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        // Check if the argument looks like a CSV filename
        if (strstr(argv[1], ".csv") != NULL) {
            BluetoothDeviceInfo device = get_mac_address_from_csv(argv[1]);
            if (device.mac_address[0] == '\0') {
                return 1; // Error getting MAC address from CSV
            }
            strcpy(mac_address, device.mac_address);
            printf(BRIGHT_BLUE "Connecting to device from CSV: %s (%s)\n" ANSI_COLOR_RESET, device.name, device.mac_address);
        } else {
            // Assume it's a MAC address
            strncpy(mac_address, argv[1], sizeof(mac_address) - 1);
        }
    } else if (argc == 3) {
        // Check if the argument looks like a CSV filename
        if (strstr(argv[1], ".csv") != NULL) {
            BluetoothDeviceInfo device = get_mac_address_from_csv(argv[1]);
            if (device.mac_address[0] == '\0') {
                return 1; // Error getting MAC address from CSV
            }
            strcpy(mac_address, device.mac_address);
            printf(BRIGHT_BLUE "Connecting to device from CSV: %s (%s)\n" ANSI_COLOR_RESET, device.name, device.mac_address);
        } else {
            // Assume it's a MAC address
            strncpy(mac_address, argv[1], sizeof(mac_address) - 1);
        }
        // Get the channel from the command line argument
        channel = atoi(argv[2]);
    } else {
        if (get_mac_address_from_user(mac_address) == -1) {
            return 1;
        }
    }

    // Initialize Bluetooth adapter
    dev_id = bluetooth_init_adapter();
    if (dev_id < 0) {
        return 1; // Exit if initialization fails
    }

    // Check if the device supports RFCOMM
    if (check_rfcomm_support(dev_id, mac_address) == 0) {
        printf(BRIGHT_RED "Error: Device %s does not support RFCOMM.\n" ANSI_COLOR_RESET, mac_address);
        return 1; 
    }

    // Find available RFCOMM channels on the device
    int found_channel = find_rfcomm_channels(dev_id, mac_address);
    if (found_channel != -1) {
        printf(BRIGHT_GREEN "Found available RFCOMM channel: %d\n" ANSI_COLOR_RESET, found_channel);
        channel = found_channel; // Use the found channel
    } else {
        printf(BRIGHT_YELLOW "No available RFCOMM channels found on device %s. Using default channel %d.\n" ANSI_COLOR_RESET, mac_address, channel);
    }

    // Attempt pairing if needed
    if (pair_with_device(dev_id, mac_address) != 0) {
        return 1;
    }

    // Connect to the device
    sock = connect_to_device(dev_id, mac_address, channel);
    if (sock < 0) {
        return 1;
    }

    // Create a thread to handle communication
    if (pthread_create(&comm_thread, NULL, handle_connection, &sock) != 0) {
        perror("pthread_create");
        close(sock);
        return 1;
    }

    // Main thread can do other things or wait for the communication thread
    pthread_join(comm_thread, NULL);

    return 0;
}
