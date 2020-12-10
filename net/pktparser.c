#include "pktparser.h"
#include <stdio.h>

// 0x0D
void parse_set_difficult(struct serverinfo *si, struct buffer *buf) {
    // 0: peaceful, 1: easy, 2: normal, 3: hard
    char diff, lock;
    deserialize_char(buf, &diff);
    deserialize_char(buf, &lock);
    fprintf(stderr, "difficult is: %s, %s", diff, lock);
}

// 0x17
void parse_plugin_message(struct serverinfo *si, struct buffer *buf) {
    // id
    // bytearray
}

// 0x30
/*
Invulnerable 	0x01
Flying 	0x02
Allow Flying 	0x04
Creative Mode(Instant Break) 	0x08
*/
void parse_player_ability() {
    char flag;
    float fly_speed, fov_modifier; // speed protion or slowness 
    // deserialize_char(buf, &flag);
    // deserialize_float(buf, &fly_speed); // 0.5 by default 
    // deserialize_float(buf, &fov_modifier); // 0.1 by default
}

// 0x10
void parse_declare_command() {
    int count, root;

    // deserialize_varint(buf, &count);
    // deserialize_node(buf, &node); // ???
    // deserialize_varint(buf, &root);

}

// 0x1A
void parse_player_status(struct serverinfo *si, struct buffer *buf) {
    int entityid;
    char entitystatus;
    // deserialize_int(buf, &entityid); // 0.5 by default
    // deserialize_char(buf, &entitystatus); // 0.5 by default
}

// 0x32
void parse_player_info(struct serverinfo *si, struct buffer *buf) {
}

// 0x34
void parse_player_position_and_look(struct serverinfo *si, struct buffer *buf) {
    double x, y, z;
    float yaw, pitch;
    char flag;
    int32_t tpid;
    // deserialize_double(buf, &x);
    // deserialize_double(buf, &y);
    // deserialize_double(buf, &z); 
    // deserialize_float(buf, &yaw);
    // deserialize_float(buf, &pitch);
    // deserialize_char(buf, &flag);
    // deserialize_varint(buf, &tpid);
}

// 0x35
void parse_unlock_recipes(struct serverinfo *si, struct buffer *buf) {
}

// 0x40
void parse_update_view_position(struct serverinfo *si, struct buffer *buf) {
    int32_t chunk_x, chunk_y;
    deserialize_varint(buf, &chunk_x);
    deserialize_varint(buf, &chunk_y);
}