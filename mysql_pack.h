
#ifndef __MYSQL_H__
#define __MYSQL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>


#define MYSQL_MAX_COLUMN_NAME_SIZE     256
#define MYSQL_MAX_BUFFER_SIZE          32768
#define MYSQL_MAX_SERVER_VERSION_SIZE  32
#define MYSQL_MAX_SCRAMBLE_SIZE        20
#define mysql_get_byte2(__buffer) \
    ((__buffer)[0] | \
    ((__buffer)[1] << 8))
#define mysql_get_byte3(__buffer) \
    ((__buffer)[0] | \
    ((__buffer)[1] << 8) | \
    ((__buffer)[2] << 16))
#define mysql_get_byte4(__buffer) \
    ((__buffer)[0] | \
    ((__buffer)[1] << 8) | \
    ((__buffer)[2] << 16) | \
    ((__buffer)[3] << 24))
#define mysql_get_byte8(__buffer) \
    ((uint64_t)(__buffer)[0] | \
    ((uint64_t)(__buffer)[1] << 8) | \
    ((uint64_t)(__buffer)[2] << 16) | \
    ((uint64_t)(__buffer)[3] << 24) | \
    ((uint64_t)(__buffer)[4] << 32) | \
    ((uint64_t)(__buffer)[5] << 40) | \
    ((uint64_t)(__buffer)[6] << 48) | \
    ((uint64_t)(__buffer)[7] << 56))
#define mysql_set_byte3(__buffer, __int) do { \
    (__buffer)[0]= (uint8_t)((__int) & 0xFF); \
    (__buffer)[1]= (uint8_t)(((__int) >> 8) & 0xFF); \
    (__buffer)[2]= (uint8_t)(((__int) >> 16) & 0xFF); } while (0)
#define mysql_set_byte4(__buffer, __int) do { \
    (__buffer)[0]= (uint8_t)((__int) & 0xFF); \
    (__buffer)[1]= (uint8_t)(((__int) >> 8) & 0xFF); \
    (__buffer)[2]= (uint8_t)(((__int) >> 16) & 0xFF); \
    (__buffer)[3]= (uint8_t)(((__int) >> 24) & 0xFF); } while (0)

typedef enum
{
    MYSQL_OK          = 0,
    MYSQL_ERROR       = -1,
    MYSQL_IO_WAIT     = -2,
    MYSQL_END         = 0,
} mysql_return_t;

typedef enum
{
	MYSQL_CAPABILITIES_NONE=                   0,
	MYSQL_CAPABILITIES_LONG_PASSWORD=          (1 << 0),
	MYSQL_CAPABILITIES_FOUND_ROWS=             (1 << 1),
	MYSQL_CAPABILITIES_LONG_FLAG=              (1 << 2),
	MYSQL_CAPABILITIES_CONNECT_WITH_DB=        (1 << 3),
	MYSQL_CAPABILITIES_NO_SCHEMA=              (1 << 4),
	MYSQL_CAPABILITIES_COMPRESS=               (1 << 5),
	MYSQL_CAPABILITIES_ODBC=                   (1 << 6),
	MYSQL_CAPABILITIES_LOCAL_FILES=            (1 << 7),
	MYSQL_CAPABILITIES_IGNORE_SPACE=           (1 << 8),
	MYSQL_CAPABILITIES_PROTOCOL_41=            (1 << 9),
	MYSQL_CAPABILITIES_INTERACTIVE=            (1 << 10),
	MYSQL_CAPABILITIES_SSL=                    (1 << 11),
	MYSQL_CAPABILITIES_IGNORE_SIGPIPE=         (1 << 12),
	MYSQL_CAPABILITIES_TRANSACTIONS=           (1 << 13),
	MYSQL_CAPABILITIES_RESERVED=               (1 << 14),
	MYSQL_CAPABILITIES_SECURE_CONNECTION=      (1 << 15),
	MYSQL_CAPABILITIES_MULTI_STATEMENTS=       (1 << 16),
	MYSQL_CAPABILITIES_MULTI_RESULTS=          (1 << 17),
	MYSQL_CAPABILITIES_PS_MULTI_RESULTS=       (1 << 18),
	MYSQL_CAPABILITIES_PLUGIN_AUTH=            (1 << 19),
	MYSQL_CAPABILITIES_SSL_VERIFY_SERVER_CERT= (1 << 30),
	MYSQL_CAPABILITIES_REMEMBER_OPTIONS=       (1 << 31),
	MYSQL_CAPABILITIES_CLIENT= (MYSQL_CAPABILITIES_LONG_PASSWORD |
			MYSQL_CAPABILITIES_FOUND_ROWS |
			MYSQL_CAPABILITIES_LONG_FLAG |
			MYSQL_CAPABILITIES_CONNECT_WITH_DB |
			MYSQL_CAPABILITIES_PLUGIN_AUTH |
			MYSQL_CAPABILITIES_TRANSACTIONS |
			MYSQL_CAPABILITIES_PROTOCOL_41 |
			MYSQL_CAPABILITIES_SECURE_CONNECTION)
} mysql_capabilities_t;

typedef struct {
	int size;
	int type;
	int flags;
	unsigned char charset;
	unsigned char decimals;
	char name[MYSQL_MAX_COLUMN_NAME_SIZE];

} mysql_column;

typedef struct {
	int insert_id;
	int warning_count;
	int affected_rows;
	int status;

	size_t column_current;
	size_t column_count;
	mysql_column column;

	int row_current;
	int row_count;

	size_t field_current;
	size_t field_total;
	size_t field_offset;
	size_t field_size;
	char *field;

} mysql_result;

typedef struct {
    unsigned char protocol_version;
    int capabilities;
    unsigned char charset;
    char server_version[MYSQL_MAX_SERVER_VERSION_SIZE];
    unsigned char scramble[MYSQL_MAX_SCRAMBLE_SIZE];
    int status;
    unsigned char *buffer;
    size_t buffer_size;
    unsigned char packet_index;
    size_t packet_size;
    mysql_result result;
} mysql_pack;

size_t mysql_pack_login(void *user, size_t user_len,
                     void *pass, size_t pass_len,
                     void *db, size_t db_len,
                     int capabilities,
                     unsigned char charset,
                     unsigned char *scramble,
                     void *buffer);
size_t mysql_pack_select(void *sql, size_t sql_len, void *buffer);

int mysql_pack_server_read(mysql_pack *pack, void *buffer, size_t size);
int mysql_pack_result_read(mysql_pack *pack, void *buffer, size_t size);
int mysql_pack_login_read(mysql_pack *pack);
int mysql_pack_select_read(mysql_pack *pack);
int mysql_pack_column_read(mysql_pack *pack);
int mysql_pack_row_read(mysql_pack *pack);
int mysql_pack_field_read(mysql_pack *pack);

typedef void (mysql_loop_column_read_t)(int index, int type, char *column, void *data);
typedef void (mysql_loop_row_read_t)(int row, int index, char *field, int field_len, void *data);
int mysql_pack_loop_read(mysql_pack *pack,
                         mysql_loop_column_read_t *column_read,
                         mysql_loop_row_read_t *row_read,
                         void *data);

#endif /* __MYSQL_H__ */

