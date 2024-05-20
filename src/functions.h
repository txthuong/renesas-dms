#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stddef.h>
#include <stdbool.h>

struct Location {
    float longitude;
    float latitude;
    float speed;
};

struct Log {
    char message_type[64];
    char message_info[64];
    char file[64];
    bool is_message_pushed;
};

struct User {
    char user_id[64];
    char user_name[64];
    float eye_threshold;
    char image[64];
};

int push_gps_to_server(const char *bus_id);
int push_bus_logs_to_server_b(struct Log *log, const char *bus_id);
bool check_face_on_aiot_cloud(const char *face);
struct User get_face_on_ai_cloud(const char *face);
struct Location get_gnss_info();

#endif