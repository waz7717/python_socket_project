#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib") // Link Winsock library

#define SERVER_PORT 12345            // Server port to connect to
#define SERVER_ADDRESS "127.0.0.1"  // Server IP address (localhost)
#define BUFFER_SIZE 1024            // Buffer size for receiving/sending data

// Function to handle the "openRead" command, which requests file content from the server
void handleOpenReadCommand(SOCKET clientSocket, const char *fileName) {
    char command[BUFFER_SIZE];  // Buffer to hold the command to be sent
    char buffer[BUFFER_SIZE];   // Buffer to receive server response
    int recvResult;

    // Create the command string to open the file for reading
    snprintf(command, sizeof(command), "CM,openRead,%s", fileName);
    
    // Send the command to the server
    if (send(clientSocket, command, strlen(command), 0) < 0) {
        printf("Failed to send openRead command. Error Code: %d\n", WSAGetLastError());
        return;
    }

    // Receive the server's response (file content or error message)
    recvResult = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (recvResult < 0) {
        printf("Failed to receive response. Error Code: %d\n", WSAGetLastError());
        return;
    }

    buffer[recvResult] = '\0'; // Null-terminate the received data
    printf("File content: %s\n", buffer);  // Print the file content received from the server
}

int main() {
    WSADATA wsaData;            // Holds information about the Windows Sockets implementation
    SOCKET clientSocket;        // Socket used for communication with the server
    struct sockaddr_in serverAddr; // Structure holding server address details
    char buffer[BUFFER_SIZE];   // Buffer for receiving data from the server
    char userCommand[BUFFER_SIZE]; // Buffer to hold user input commands
    int recvResult;

    // Initialize Winsock (required for socket programming on Windows)
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", WSAGetLastError());
        return 1; // Exit if Winsock initialization fails
    }

    // Create a socket for communication (TCP socket)
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup(); // Clean up Winsock before exiting
        return 1;
    }

    // Set up the server address structure
    serverAddr.sin_family = AF_INET;              // Address family (IPv4)
    serverAddr.sin_port = htons(SERVER_PORT);     // Port number (network byte order)
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS); // IP address (in network byte order)

    // Connect to the server using the specified address and port
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        printf("Connection failed. Error Code: %d\n", WSAGetLastError());
        closesocket(clientSocket); // Close the socket on failure
        WSACleanup(); // Clean up Winsock before exiting
        return 1;
    }

    printf("Connected to server at %s:%d\n", SERVER_ADDRESS, SERVER_PORT);

    // Main loop to interact with the user
    while (1) {
        // Ask the user for a command
        printf("Enter command (e.g., openRead <filename> or exit): ");
        fgets(userCommand, sizeof(userCommand), stdin); // Get user input

        // Remove trailing newline character from the user input
        userCommand[strcspn(userCommand, "\n")] = '\0';

        // Parse the command and handle specific cases
        if (strncmp(userCommand, "openRead ", 9) == 0) {
            // If the command starts with "openRead", extract the file name
            char *fileName = userCommand + 9; // Extract file name after the "openRead " prefix
            handleOpenReadCommand(clientSocket, fileName); // Call function to handle the openRead command
        } else if (strcmp(userCommand, "exit") == 0) {
            // If the user enters "exit", break the loop and close the connection
            printf("Closing the connection...\n");
            break;
        } else {
            // For any other command, send it to the server and wait for a response
            if (send(clientSocket, userCommand, strlen(userCommand), 0) < 0) {
                printf("Failed to send command. Error Code: %d\n", WSAGetLastError());
                break;
            }

            // Receive the server's response to the command
            recvResult = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            if (recvResult < 0) {
                printf("Failed to receive response. Error Code: %d\n", WSAGetLastError());
                break;
            } else {
                buffer[recvResult] = '\0'; // Null-terminate the received data
                printf("Server response: %s\n", buffer); // Print the server's response
            }
        }
    }

    // Clean up resources and close the socket
    closesocket(clientSocket);
    WSACleanup(); // Clean up Winsock resources

    return 0;
}
