#include "pktparser.h"
#include "serialize.h"
#include "auth.h"
#include "../utils.h"
#include <stdio.h>


//
void parse_setcompression(struct serverinfo *si, struct buffer *buf) {
    int32_t thresh;
    deserialize_varint(buf, &thresh);
    si->si_conninfo.thresh = thresh;
}

void parse_loginsuccess(struct serverinfo *si, struct buffer *buf) {
    si->si_conninfo.state = M_STATE_PLAY;
    // TODO: parse uuid string (16) 
    //             name string
}

void parse_keepalive(struct serverinfo *si, struct buffer *buf) {
    deserialize_long(buf, &si->si_conninfo.keepalive);
    // TODO: queue
    send_packet(M_REQ_KEEPALIVE, si, NULL, &si->si_conninfo.keepalive);
}

void parse_encryptreq(struct serverinfo *si, struct buffer *buf) {
    si->si_encinfo->e_id = new_buffer(10);
    si->si_encinfo->e_secret = new_buffer(16);
    si->si_encinfo->e_pubkey = new_buffer(128);
    si->si_encinfo->e_verify = new_buffer(128);
    if (!si->si_encinfo->e_id || !si->si_encinfo->e_pubkey || !si->si_encinfo->e_verify) {
        // TODO: error handle
    }

    deserialize_str(buf, si->si_encinfo->e_id);
    deserialize_str(buf, si->si_encinfo->e_pubkey);
    deserialize_str(buf, si->si_encinfo->e_verify);
    // TODO: queue
    send_packet(M_REQ_ENCRYPTRES, si, NULL, NULL);
}

// 0x0D
void parse_set_difficult(struct serverinfo *si, struct buffer *buf) {
    // 0: peaceful, 1: easy, 2: normal, 3: hard
    char diff, lock;
    deserialize_byte(buf, &diff);
    deserialize_byte(buf, &lock);
    // TODO: add event to message queue
    fprintf(stderr, "Difficulty: %d, %d\n", diff, lock);
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
void parse_player_ability(struct serverinfo *si, struct buffer *buf) {
    char flag;
    float fly_speed, fov_modifier; // speed protion or slowness etc..
    deserialize_byte(buf, &flag);
    deserialize_float(buf, &fly_speed); // 0.5 by default 
    deserialize_float(buf, &fov_modifier); // 0.1 by default
    fprintf(stderr, "player ability: %d， %f, %f\n", flag, fly_speed, fov_modifier);
}

// 0x10
void parse_declare_command(struct serverinfo *si, struct buffer *buf) {
    int count, root;
    deserialize_varint(buf, &count); // skip
    // deserialize_node(buf, &node); // ???
    // deserialize_varint(buf, &root);
    fprintf(stderr, "declare command: %d\n", count);
}

// 0x1A
void parse_player_status(struct serverinfo *si, struct buffer *buf) {
    int entityid;
    char entitystatus;
    // deserialize_int(buf, &entityid); // 0.5 by default
    // deserialize_char(buf, &entitystatus); // 0.5 by default
    // fprintf(stderr, "PLAY STATUS: %d\n", entityid);
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

    deserialize_double(buf, &x);
    deserialize_double(buf, &y);
    deserialize_double(buf, &z);
    deserialize_float(buf, &yaw);
    deserialize_float(buf, &pitch);
    deserialize_byte(buf, &flag);
    // deserialize_varint(buf, &tpid);
    fprintf(stderr, "player pos: %lf, %lf, %lf\n", x, y, z);

}

// 0x35
void parse_unlock_recipes(struct serverinfo *si, struct buffer *buf) {
}

// 0x40
void parse_update_view_position(struct serverinfo *si, struct buffer *buf) {
    int32_t chunk_x, chunk_y;
    deserialize_varint(buf, &chunk_x);
    deserialize_varint(buf, &chunk_y);
    fprintf(stderr, "update view： %d, %d\n", chunk_x, chunk_y);

}