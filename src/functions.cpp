#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include "functions.h"
#include "configuration.h"

// struct Location {
//     float longitude;
//     float latitude;
//     float speed;
// };

// struct Log {
//     char *message_type;
//     char *message_info;
//     char *file;
// };

// struct User {
//     char *user_id;
//     char *user_name;
//     float eye_threshold;
//     char *image;
// };

// Function to parse latitude from the string
float parse_latitude(const char *str) {
    const char *token = strstr(str, "Latitude(positive->north) :");
    if (token == NULL) {
        fprintf(stderr, "Latitude not found\n");
        return 0.0f;
    }
    return atof(token + strlen("Latitude(positive->north) :"));
}

// Function to parse longitude from the string
float parse_longitude(const char *str) {
    const char *token = strstr(str, "Longitude(positive->east) :");
    if (token == NULL) {
        fprintf(stderr, "Longitude not found\n");
        return 0.0f;
    }
    return atof(token + strlen("Longitude(positive->east) :"));
}

// Function to parse hSpeed from the string
float parse_hSpeed(const char *str) {
    const char *token = strstr(str, "hSpeed");
    if (token == NULL) {
        fprintf(stderr, "hSpeed not found\n");
        return 0.0f;
    }
    return atof(token + strlen("hSpeed"));
}

struct Location get_location()
{
    struct Location location;
    location.longitude = 139.6917;
    location.latitude = 35.6895;
    location.speed = 60.0;
    return location;
}

char *extract_substring(char *str, char start, char end)
{
    char *r_start, *r_end;
    r_start = strchr(str, start);
    if (r_start == NULL){
        return NULL;
    }

    r_start += 1;
    r_end = strchr(r_start, end);
    if (r_end == NULL){
        return NULL;
    }

    size_t length = r_end - r_start;
    char *substring = (char *)malloc(length + 1);
    if (substring == NULL) {
        return NULL;
    }

    strncpy(substring, r_start, length);
    substring[length] = '\0';

    return substring;
}

char* concat(int count, ...)
{
    va_list ap;
    int i;

    // Find required length to store merged string
    int len = 1; // room for NULL
    va_start(ap, count);
    for(i=0 ; i<count ; i++)
        len += strlen(va_arg(ap, char*));
    va_end(ap);

    // Allocate memory to concat strings
    char *merged = (char *)calloc(sizeof(char),len);
    int null_pos = 0;

    // Actually concatenate strings
    va_start(ap, count);
    for(i=0 ; i<count ; i++)
    {
        char *s = va_arg(ap, char*);
        strcpy(merged+null_pos, s);
        null_pos += strlen(s);
    }
    va_end(ap);

    return merged;
}


// Function to read the contents of a file
char* readFile(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", strerror(errno));
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for file content
    char* content = (char*)malloc(*size);
    if (!content) {
        fprintf(stderr, "Error allocating memory\n");
        fclose(file);
        return NULL;
    }

    // Read file content
    size_t bytesRead = fread(content, 1, *size, file);
    if (bytesRead != *size) {
        fprintf(stderr, "Error reading file\n");
        free(content);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return content;
}

// Function to encode binary data as Base64
char* base64Encode(const unsigned char* data, size_t inputLength, size_t* outputLength) {
    const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outputBufferSize = ((inputLength + 2) / 3) * 4;
    char* output = (char*)malloc(outputBufferSize + 1);
    if (!output) {
        return NULL;
    }

    size_t i = 0;
    size_t j = 0;

    while (i < inputLength) {
        unsigned char byte1 = i < inputLength ? data[i++] : 0;
        unsigned char byte2 = i < inputLength ? data[i++] : 0;
        unsigned char byte3 = i < inputLength ? data[i++] : 0;

        output[j++] = base64Chars[byte1 >> 2];
        output[j++] = base64Chars[((byte1 & 0x03) << 4) | ((byte2 & 0xf0) >> 4)];
        output[j++] = i <= inputLength + 1 ? base64Chars[((byte2 & 0x0f) << 2) | ((byte3 & 0xc0) >> 6)] : '=';
        output[j++] = i <= inputLength ? base64Chars[byte3 & 0x3f] : '=';
    }

    *outputLength = j;
    output[j] = '\0'; // Null-terminate the string
    return output;
}

char* getBase64String(const char* filename) {
    size_t fileSize;
    char* imageData = readFile(filename, &fileSize);
    if (!imageData) {
        return NULL;
    }

    // Base64 encode the image data
    size_t base64Size;
    char* base64Data = base64Encode((const unsigned char*)imageData, fileSize, &base64Size);
    free(imageData); // Free the original image data

    if (!base64Data) {
        fprintf(stderr, "Error encoding image data\n");
        return NULL;
    }

    return base64Data;
}

int push_gps_to_server(const char *bus_id)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    struct Location current_location = get_location();
    float latitude = current_location.latitude;
    float longitude = current_location.longitude;
    float speed = current_location.speed;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return 1;
    }

    // Resolve server address
    if ((server = gethostbyname(WEB_APP_URL)) == NULL) {
        perror("Host resolution error");
        return 1;
    }

    // Fill server address struct
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return 1;
    }

    // JSON data to send
    char json_data[256];
    sprintf(json_data, "{\"latitude\": %.6f, \"longitude\": %.6f, \"speed\": %.6f}", latitude, longitude, speed);

    // Construct HTTP request
    char request[1024];
    sprintf(request, "PUT /bus-monitoring/bus-monitorings/api/%s/gps HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: %ld\r\n"
                      "\r\n"
                      "%s",
                      bus_id, WEB_APP_URL, strlen(json_data), json_data);

    // Send HTTP request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Send failed");
        return 1;
    }

    char response[1024];
    int bytes_received = recv(sockfd, response, sizeof(response), 0);
    if (bytes_received < 0) {
        perror("Received failed");
        return 1;
    }
    response[bytes_received] = '\0';

    if (DEBUG)
    {
        printf("Client Request: \n%s\n", request);
        printf("Server Response: \n%s\n", response);
    }
    
    // Close the socket
    close(sockfd);

    return 0;
}


int push_bus_logs_to_server_backup(struct Log log, char *bus_id)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    char *message_info = log.message_info;
    char *message_type = log.message_type;
    char *file = log.file;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return 1;
    }

    // Resolve server address
    if ((server = gethostbyname(WEB_APP_URL)) == NULL) {
        perror("Host resolution error");
        return 1;
    }

    // Fill server address struct
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return 1;
    }

    // Image processing
    FILE *image = fopen(file, "rb");
    if (image == NULL) {
        perror("Image file opening failed");
        return 1;
    }
    fseek(image, 0L, SEEK_END);
    size_t filesize = ftell(image);
    rewind(image);

    // char* binary = malloc(filesize); //C
    char* binary = (char*)malloc(filesize); //C++
    if (binary == NULL) {
        printf("Failed to allocate memory for image data\n");
        fclose(image);
        return 1;
    }
    fread(binary, 1, filesize, image);
    // binary[filesize] = '\0';
    printf("File size: %ld\n", filesize);
    printf("Binary data: %s\n", binary);
    fclose(image);

    // Request header + body
    char boundary[] = "WebKitFormBoundary127sabx83n1234";
    char request_body[1024 * 1023];
    sprintf(request_body, "--%s\r\n"
                          "Content-Disposition: form-data; name=\"alertLevel\"\r\n\r\n%s\r\n"
                          "--%s\r\n"
                          "Content-Disposition: form-data; name=\"alertContent\"\r\n\r\n%s\r\n"
                          "--%s\r\n"
                          "Content-Disposition: form-data; name=\"file\"; filename=\"1_out.jpg\"\r\n"
                          "Content-Type: image/jpeg\r\n\r\n"
                          "%s\r\n"
                          "--%s--\r\n",
                          boundary, message_type, boundary, message_info, boundary, binary, boundary);

    char request[1024 * 1024];
    sprintf(request, "POST /bus-monitoring/bus-monitorings/api/%s/drivers HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Content-Type: multipart/form-data; boundary=%s\r\n\r\n"
                     "%s",
                     bus_id, WEB_APP_URL, strlen(request_body),boundary, request_body);

    // Send HTTP request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Send failed");
        return 1;
    }
    
    char response[1024];
    int bytes_received = recv(sockfd, response, sizeof(response), 0);
    if (bytes_received < 0) {
        perror("Received failed");
        return 1;
    }
    response[bytes_received] = '\0';

    printf("Client Request: \n%s\n", request);
    printf("Server Response: \n%s\n", response);

    // Close the socket
    close(sockfd);
    free(binary);

    return 0;
}

int register_user_to_ai_cloud()
{
    return 0;
}

struct User get_face_on_ai_cloud(const char *face)
{
    int sockfd;
    struct sockaddr_in server_addr;
    // struct hostent *server;
    //struct User user = {"UNK", "UNK", 0.2, face};
    struct User user;
    strcpy(user.user_name, "UNK");
    strcpy(user.user_id, "UNK");
    user.eye_threshold = 0.2;
    strcpy(user.image, face);
    // user.image = face;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return user;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(AI_API_PORT);
    server_addr.sin_addr.s_addr = inet_addr(AI_API_URL);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return user;
    }

    // JSON data to send
    char *base64Data = getBase64String((const char*)face);
    char json_data[1024 * 1023];
    //asprintf(&json_data, "{\"user_faces\": [\"%s\"]}", base64Data);
    sprintf(json_data, "{\"user_faces\": [\"%s\"]}", base64Data);

    // Construct HTTP request
    char request[1024 * 1024];
    sprintf(request, "POST /face/aiot/recognize HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %ld\r\n"
                     "\r\n"
                     "%s",
                     AI_API_URL, AI_API_PORT, strlen(json_data), json_data);

    // Send HTTP request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Send failed");
        return user;
    }

    char response[1024];
    int bytes_received = recv(sockfd, response, sizeof(response), 0);
    if (bytes_received < 0) {
        perror("Received failed");
        return user;
    }

    response[bytes_received] = '\0';

    char *display_name;
    char *user_id;
    float eye_threshold;
    char *json_start = strrchr(response, '{');
    char *token = strtok(json_start + 1, ",");
    while (token != NULL)
    {
        if (strstr(token, "display_name") != NULL)
        {
            display_name = extract_substring(token, '[', ']');
            strcpy(user.user_name, display_name);
            // user.user_name = display_name;
            if (strstr(display_name, "DMS") != NULL && strstr(display_name, "-") != NULL) {
                char *eye_threshold_str = strchr(display_name, '-') + 1;
                eye_threshold = atof(eye_threshold_str);
                user.eye_threshold = eye_threshold;
            }
        }
        if (strstr(token, "user_ids") != NULL)
        {
            user_id = extract_substring(token, '[', ']');
            // user.user_id = user_id;
            strcpy(user.user_id, user_id);
        }
        token = strtok(NULL, ",");
    }

    // Close the socket
    close(sockfd);
    free(base64Data);

    return user;
}

int remove_face_on_ai_cloud()
{
    return 0;
}

bool check_face_on_aiot_cloud(const char *face)
{
    struct User user = get_face_on_ai_cloud(face);
    if (strcmp(user.user_name, "\"UNK\"") == 0 || strcmp(user.user_name, "\"NOFACE\"") == 0 || strcmp(user.user_name, "UNK") == 0 || strcmp(user.user_name, "NOFACE") == 0) {
        return false;
    }
    return true;
}

int push_bus_logs_to_server(struct Log *log, const char *bus_id)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    char *message_info = log->message_info;
    char *message_type = log->message_type;
    char *file = log->file;

    if (!log->is_message_pushed){
        // Create a socket
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation error");
            return 1;
        }

        // Resolve server address
        if ((server = gethostbyname(WEB_APP_URL)) == NULL) {
            perror("Host resolution error");
            return 1;
        }

        // Fill server address struct
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

        // Connect to the server
        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            return 1;
        }

        // Image processing
        FILE *image = fopen(file, "rb");
        if (image == NULL) {
            perror("Image file opening failed");
            return 1;
        }
        fseek(image, 0L, SEEK_END);
        size_t filesize = ftell(image);
        rewind(image);

        // Request header + body
        char boundary[] = "WebKitFormBoundary127sabx83n1234";
        char boundary_close[128];
        sprintf(boundary_close, "\r\n--%s--\r\n", boundary);

        char request_body[1024];
        sprintf(request_body, "--%s\r\n"
                            "Content-Disposition: form-data; name=\"alertLevel\"\r\n\r\n%s\r\n"
                            "--%s\r\n"
                            "Content-Disposition: form-data; name=\"alertContent\"\r\n\r\n%s\r\n"
                            "--%s\r\n"
                            "Content-Disposition: form-data; name=\"file\"; filename=\"1_out.jpg\"\r\n"
                            "Content-Type: image/jpeg\r\n\r\n",
                            boundary, message_type, boundary, message_info, boundary);

        long content_length = strlen(request_body) + filesize + strlen(boundary_close);
        char request[1024*2];
        sprintf(request, "POST /bus-monitoring/bus-monitorings/api/%s/drivers HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "Content-Type: multipart/form-data; boundary=%s\r\n\r\n"
                        "%s",
                        bus_id, WEB_APP_URL, content_length, boundary, request_body);
        
        if (DEBUG)
        {
            printf("Client Request: \n%s\n", request);
            printf("(binary image data)\n");
            printf("%s\n", boundary_close);
        }
        
        // Send HTTP request
        if (send(sockfd, request, strlen(request), 0) < 0) {
            perror("Send failed");
            return 1;
        }
        // send(sockfd, request, strlen(request), 0);

        // char* binary = malloc(filesize); //C
        char* binary = (char*)malloc(filesize); //C++
        if (binary == NULL) {
            printf("Failed to allocate memory for image data\n");
            fclose(image);
            return 1;
        }
        fread(binary, 1, filesize, image);
        if (send(sockfd, binary, filesize, 0) < 0) {
            perror("Send failed");
            return 1;
        }
        fclose(image);

        if (send(sockfd, boundary_close, strlen(boundary_close), 0) < 0) {
            perror("Send failed");
            return 1;
        }

        char response[1024];
        int bytes_received = recv(sockfd, response, sizeof(response), 0);
        if (bytes_received < 0) {
            perror("Received failed");
            return 1;
        }
        response[bytes_received] = '\0';
        
        if (DEBUG) {
            printf("Server Response: \n%s\n", response);
        }

        const char *token = strstr(response, "HTTP/1.1 200");
        if (token != NULL) {
            log->is_message_pushed = true;
        }

        // Close the socket
        close(sockfd);
        free(binary);

    }
    return 0;
}


int push_bus_logs_to_server_b(struct Log *log, const char *bus_id)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    char *message_info = log->message_info;
    char *message_type = log->message_type;
    char *file = log->file;

    if (!log->is_message_pushed){
        // Create a socket
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation error");
            return 1;
        }

        // Resolve server address
        if ((server = gethostbyname(WEB_APP_URL)) == NULL) {
            perror("Host resolution error");
            return 1;
        }

        // Fill server address struct
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

        // Connect to the server
        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            return 1;
        }

        // Image processing
        FILE *image = fopen(file, "rb");
        if (image == NULL) {
            perror("Image file opening failed");
            return 1;
        }
        fseek(image, 0L, SEEK_END);
        size_t filesize = ftell(image);
        rewind(image);

        // Request header + body
        char boundary[] = "WebKitFormBoundary127sabx83n1234";
        char boundary_close[128];
        sprintf(boundary_close, "\r\n--%s--\r\n", boundary);

        char request_body[1024];
        sprintf(request_body, "--%s\r\n"
                            "Content-Disposition: form-data; name=\"alertLevel\"\r\n\r\n%s\r\n"
                            "--%s\r\n"
                            "Content-Disposition: form-data; name=\"alertContent\"\r\n\r\n%s\r\n"
                            "--%s\r\n"
                            "Content-Disposition: form-data; name=\"file\"; filename=\"1_out.jpg\"\r\n"
                            "Content-Type: image/jpeg\r\n\r\n",
                            boundary, message_type, boundary, message_info, boundary);

        long content_length = strlen(request_body) + filesize + strlen(boundary_close);
        char request[1024*2];
        sprintf(request, "POST /bus-monitoring/bus-monitorings/api/%s/drivers HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "Content-Type: multipart/form-data; boundary=%s\r\n\r\n"
                        "%s",
                        bus_id, WEB_APP_URL, content_length, boundary, request_body);
        
        if (DEBUG)
        {
            printf("Client Request: \n%s\n", request);
            printf("(binary image data)\n");
            printf("%s\n", boundary_close);
        }
        
        // Send HTTP request
        if (send(sockfd, request, strlen(request), 0) < 0) {
            perror("Send failed");
            return 1;
        }
        // send(sockfd, request, strlen(request), 0);

        // char* binary = malloc(filesize); //C
        char* binary = (char*)malloc(filesize); //C++
        if (binary == NULL) {
            printf("Failed to allocate memory for image data\n");
            fclose(image);
            return 1;
        }
        fread(binary, 1, filesize, image);
        if (send(sockfd, binary, filesize, 0) < 0) {
            perror("Send failed");
            return 1;
        }
        fclose(image);

        if (send(sockfd, boundary_close, strlen(boundary_close), 0) < 0) {
            perror("Send failed");
            return 1;
        }

        char response[1024];
        int bytes_received = recv(sockfd, response, sizeof(response), 0);
        if (bytes_received < 0) {
            perror("Received failed");
            return 1;
        }
        response[bytes_received] = '\0';
        
        if (DEBUG) {
            printf("Server Response: \n%s\n", response);
        }

        const char *token = strstr(response, "HTTP/1.1 200");
        if (token != NULL) {
            log->is_message_pushed = true;
        }

        // Close the socket
        close(sockfd);
        free(binary);

    }
    return 0;
}


char *send_ssh_command(const char *command)
{
    char *response = NULL;
    char ssh_command[256];
    char buffer[1024];

    sprintf(ssh_command, "ssh-keygen -f ~/.ssh/known_hosts -R \"%s\"", IOT_ADDRESS);
    popen(ssh_command, "r");

    sprintf(ssh_command, "ssh -o \"StrictHostKeyChecking no\" %s@%s \"%s\"", IOT_USER, IOT_ADDRESS, command);
    //sprintf(ssh_command, "ssh %s@%s \"%s\"", IOT_USER, IOT_ADDRESS, command);

    FILE *pipe = popen(ssh_command, "r");
    if (pipe == NULL) {
        fprintf(stderr, "Error opening pipe for command execution\n");
        exit(1);
    }

    // Read the output of the command
    size_t response_size = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        size_t buffer_len = strlen(buffer);
        // response = realloc(response, response_size + buffer_len + 1);
        response = (char*)realloc(response, response_size + buffer_len + 1);
        if (response == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            pclose(pipe);
            return NULL;
        }
        memcpy(response + response_size, buffer, buffer_len);
        response_size += buffer_len;
    }
    if (response != NULL) {
        response[response_size] = '\0';
    }
    
    pclose(pipe);
    return response;
}

struct Location get_gnss_info()
{
    struct Location location = {0, 0, 0};

    // char *hspeed = send_ssh_command("/legato/systems/current/bin/gnss get hSpeed");
    // char *position = send_ssh_command("/legato/systems/current/bin/gnss get loc3d");

    char *position = send_ssh_command("/legato/systems/current/bin/gnss get posInfo");
    
    float latitude = parse_latitude(position);
    if (latitude != 0.0f) {
        location.latitude = latitude;
    }

    float longitude = parse_longitude(position);
    if (longitude != 0.0f) {
        location.longitude = longitude;
    }

    float speed = parse_hSpeed(position);
    if (speed != 0.0f) {
        location.speed = speed;
    }

    return location;
}


// int main() {
    
//     struct Location location = get_gnss_info();

//     printf("longitude: %lf\n", location.longitude);
//     printf("latitude: %lf\n", location.latitude);
//     printf("speed: %lf\n", location.speed);

//     char bus_id[] = "11e8d384-d93f-4214-8a4f-5c46aeb4dd24";
//     char* filename1 = "images/18.jpeg";
//     char* filename2 = "images/pic_05.jpg";
//     char* filename3 = "images/thuong.jpg";
//     struct Log message = {"WARNING", "The driver is distracted", filename1, false};

//     if (message.is_message_pushed) {
//         printf("Message was pushed\n");
//     }
//     else {
//         printf("Message is NOT pushed\n");
//     }

//     push_gps_to_server(BUS_ID);
//     push_bus_logs_to_server(&message, BUS_ID);

//     if (message.is_message_pushed) {
//         printf("Message was pushed\n");
//     }
//     else {
//         printf("Message is NOT pushed\n");
//     }

//     struct User user = get_face_on_ai_cloud(filename1);
//     printf("\nUser name: %s", user.user_name);
//     if (check_face_on_aiot_cloud(filename1)){
//         printf("\nStatus: TRUE");
//     }
//     else {
//         printf("\nStatus: FALSE");
//     }
//     struct User user2 = get_face_on_ai_cloud(filename2);
//     printf("\nUser2 name: %s", user2.user_name);
//     if (check_face_on_aiot_cloud(filename2)){
//         printf("\nStatus: TRUE");
//     }
//     else {
//         printf("\nStatus: FALSE");
//     }
//     struct User user3 = get_face_on_ai_cloud(filename3);
//     printf("\nUser3 name: %s", user3.user_name);
//     if (check_face_on_aiot_cloud(filename3)){
//         printf("\nStatus: TRUE");
//     }
//     else {
//         printf("\nStatus: FALSE");
//     }

//     return 0;
// }