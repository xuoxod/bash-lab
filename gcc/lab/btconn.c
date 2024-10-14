#include <sys/socket.h> // Should come before netinet/in.h
#include <sys/ioctl.h>  // Should come before bluetooth/bluetooth.h
#include <stdint.h>    // Should be very early for type definitions
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <termios.h> // For colored text output

// Define ANSI color codes for terminal output
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
#define BRIGHT_CYAN        "\x1b[96m" 

// Structure to hold Bluetooth device information
typedef struct {
    char mac_address[18];
    char name[248];
} BluetoothDeviceInfo;

// Global flag for terminating threads gracefully
volatile sig_atomic_t keep_running = 1;

// Function to handle Ctrl+C signal
void signal_handler(int signum) {
    keep_running = 0;
}

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

// Function to read Bluetooth devices from a CSV file
BluetoothDeviceInfo *read_devices_from_csv(const char *filename, int *num_devices) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Could not open CSV file: %s\n", filename);
        return NULL;
    }

    // Skip the header line
    char line[256];
    fgets(line, sizeof(line), fp);

    // Count the number of devices in the CSV
    int count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        count++;
    }
    rewind(fp); // Reset file pointer to the beginning

    // Allocate memory for the devices
    BluetoothDeviceInfo *devices = malloc(count * sizeof(BluetoothDeviceInfo));
    if (devices == NULL) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Memory allocation failed.\n");
        fclose(fp);
        return NULL;
    }

    // Read the devices from the CSV
    int i = 0;
    fgets(line, sizeof(line), fp); // Skip the header line again
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *token = strtok(line, ",");
        if (token != NULL) {
            strncpy(devices[i].mac_address, token, sizeof(devices[i].mac_address) - 1);
        }
        token = strtok(NULL, ",");
        if (token != NULL) {
            strncpy(devices[i].name, token, sizeof(devices[i].name) - 1);
        }
        i++;
    }

    fclose(fp);
    *num_devices = count;
    return devices;
}

// Function to present the user with a choice of devices from the CSV
int choose_device(BluetoothDeviceInfo *devices, int num_devices) {
    if (num_devices == 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "No devices found in the CSV file.\n");
        return -1;
    }

    printf(BRIGHT_YELLOW "Available devices:\n" ANSI_COLOR_RESET);
    for (int i = 0; i < num_devices; i++) {
        printf("%d. %s (%s)\n", i + 1, devices[i].name, devices[i].mac_address);
    }

    int choice;
    do {
        printf(BRIGHT_YELLOW "Enter the number of the device to connect to: " ANSI_COLOR_RESET);
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > num_devices) {
            fprintf(stderr, ANSI_COLOR_RED "Error: " ANSI_COLOR_RESET "Invalid choice.\n");
            fflush(stdin); // Clear the input buffer
        }
    } while (choice < 1 || choice > num_devices);

    return choice - 1; // Adjust the choice to be zero-based
}


// Function to connect to a Bluetooth device with detailed status messages
int connect_to_device(const char *mac_address, int channel) {
    struct sockaddr_rc addr = {0};
    int sock, status;
    struct timeval timeout;

    // Allocate a socket
    printf(ANSI_COLOR_YELLOW "   Creating socket...\n" ANSI_COLOR_RESET);
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set connection parameters
    printf(ANSI_COLOR_YELLOW "   Setting connection parameters...\n" ANSI_COLOR_RESET);
    addr.rc_family = AF_BLUETOOTH;
    str2ba(mac_address, &addr.rc_bdaddr);
    addr.rc_channel = (uint8_t)channel;

    // Set a timeout for the connection attempt
    timeout.tv_sec = 10; // Set timeout to 10 seconds
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        close(sock);
        return -1;
    }

    // Connect to the server
    printf(BRIGHT_BLUE "   Connecting to %s on channel %d...\n" ANSI_COLOR_RESET, mac_address, channel);
    status = connect(sock, (struct sockaddr *) &addr, sizeof(addr));

    if (status < 0) {
        if (errno == EAGAIN || errno == EINPROGRESS) {
            fprintf(stderr, ANSI_COLOR_RED "Connection timed out.\n" ANSI_COLOR_RESET);
        } else {
            perror("connect");
        }
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

    while (keep_running && (bytes_read = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf(BRIGHT_CYAN "Received: %s\n" ANSI_COLOR_RESET, buffer);
    }

    if (bytes_read == 0) {
        printf(BRIGHT_YELLOW "Connection closed by remote device.\n" ANSI_COLOR_RESET);
    } else if (bytes_read < 0 && keep_running) { // Check keep_running here
        perror("read");
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    char mac_address[18];
    int sock;
    pthread_t comm_thread;
    int channel = 1; // Default to channel 1

    // Handle Ctrl+C signal for graceful termination
    signal(SIGINT, signal_handler);

    if (argc > 3) {
        fprintf(stderr, "Usage: %s [mac_address|csv_filename] [channel]\n", argv[0]);
        return 1;
    }

    // Handle command-line arguments
    if (argc == 2) {
        // If the argument contains ".csv", treat it as a filename
        if (strstr(argv[1], ".csv") != NULL) {
            int num_devices;
            BluetoothDeviceInfo *devices = read_devices_from_csv(argv[1], &num_devices);
            if (devices == NULL) {
                return 1; // Error reading from CSV
            }

            int choice = choose_device(devices, num_devices);
            if (choice == -1) {
                free(devices);
                return 1; // Error choosing device
            }

            strcpy(mac_address, devices[choice].mac_address);
            printf(BRIGHT_BLUE "Connecting to device from CSV: %s (%s)\n" ANSI_COLOR_RESET, devices[choice].name, devices[choice].mac_address);
            free(devices);
        } else {
            // Otherwise, treat it as a MAC address
            strncpy(mac_address, argv[1], sizeof(mac_address) - 1);
        }
    } else if (argc == 3) {
        // If the first argument contains ".csv", treat it as a filename
        if (strstr(argv[1], ".csv") != NULL) {
            int num_devices;
            BluetoothDeviceInfo *devices = read_devices_from_csv(argv[1], &num_devices);
            if (devices == NULL) {
                return 1; // Error reading from CSV
            }

            int choice = choose_device(devices, num_devices);
            if (choice == -1) {
                free(devices);
                return 1; // Error choosing device
            }

            strcpy(mac_address, devices[choice].mac_address);
            printf(BRIGHT_BLUE "Connecting to device from CSV: %s (%s)\n" ANSI_COLOR_RESET, devices[choice].name, devices[choice].mac_address);
            free(devices);
        } else {
            // Otherwise, treat the first argument as a MAC address
            strncpy(mac_address, argv[1], sizeof(mac_address) - 1);
        }
        // The second argument is the channel
        channel = atoi(argv[2]);
    } else {
        // No arguments provided, prompt the user for the MAC address
        if (get_mac_address_from_user(mac_address) == -1) {
            return 1;
        }
    }

    // Connect to the device
    sock = connect_to_device(mac_address, channel);
    if (sock < 0) {
        return 1; // Connection failed
    }

    // Create a thread to handle communication
    if (pthread_create(&comm_thread, NULL, handle_connection, &sock) != 0) {
        perror("pthread_create");
        close(sock);
        return 1;
    }

    // Main thread can do other things, but should allow graceful exit
    while (keep_running) {
        sleep(1); // Check for termination flag every second
    }

    // If the thread is still running, cancel it and wait for it to finish
    if (pthread_cancel(comm_thread) != 0) {
        perror("pthread_cancel");
    }
    pthread_join(comm_thread, NULL);

    return 0;
}
