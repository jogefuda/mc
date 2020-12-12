#ifndef __PKTPARSER_H
#define __PKTPARSER_H

#include "../minecraft.h"
#include "../utils.h"
#include <sys/types.h>

void parse_setcompression(struct serverinfo *si, struct buffer *buf);
void parse_loginsuccess(struct serverinfo *si, struct buffer *buf);
void parse_keepalive(struct serverinfo *si, struct buffer *buf);
void parse_encryptreq(struct serverinfo *si, struct buffer *buf);


void parse_set_difficult(struct serverinfo *si, struct buffer *buf);
void parse_plugin_message(struct serverinfo *si, struct buffer *buf);
void parse_player_ability();
void parse_declare_command(struct serverinfo *si, struct buffer *buf);
void parse_player_status(struct serverinfo *si, struct buffer *buf);
void parse_player_info(struct serverinfo *si, struct buffer *buf);
void parse_player_position_and_look(struct serverinfo *si, struct buffer *buf);
void parse_player_position_and_look(struct serverinfo *si, struct buffer *buf);
void parse_unlock_recipes(struct serverinfo *si, struct buffer *buf);
void parse_update_view_position(struct serverinfo *si, struct buffer *buf);

#endif //__PKTPARSER_H