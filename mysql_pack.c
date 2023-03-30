
#include <mysql_pack.h>

int mysql_packet_size_read(mysql_pack *pack)
{
	mysql_result *result = &pack->result;
	if (pack->buffer_size <= 5) {
		result->status = MYSQL_IO_WAIT;
		return MYSQL_ERROR;
	}

	pack->packet_size = mysql_get_byte3(pack->buffer);
	if (pack->buffer_size < pack->packet_size) {
		result->status = MYSQL_IO_WAIT;
		return MYSQL_ERROR;
	}

	if (pack->packet_size == 0) {
		result->status = MYSQL_ERROR;
		return MYSQL_ERROR;
	}

	if ((pack->packet_index != pack->buffer[3])) {
		result->status = MYSQL_ERROR;
		return MYSQL_ERROR;
	}

	pack->buffer += 4;
	pack->buffer_size-= 4;
	pack->packet_index++;
	return MYSQL_OK;
}

void mysql_packet_size_skip(mysql_pack *pack)
{
	if (pack->packet_size > 0) {
		pack->buffer += pack->packet_size;
		pack->buffer_size -= pack->packet_size;
		pack->packet_size = 0;
	}
}

int return_status(mysql_pack *pack, int status)
{
	return (pack->status = status);
}

int mysql_pack_server_read(mysql_pack *pack, void *buffer, size_t size)
{
	pack->buffer = buffer;
	pack->buffer_size = size;
	if (mysql_packet_size_read(pack)) {
		return MYSQL_ERROR;
	}

	unsigned char *ptr = NULL;
	pack->protocol_version = pack->buffer[0];
	pack->buffer++;
	ptr= memchr(pack->buffer, 0, pack->buffer_size - 1);
	if (ptr == NULL) {
		return MYSQL_ERROR;
	}

	if (pack->packet_size < (size_t)(46 + (ptr - pack->buffer))) {
		return MYSQL_ERROR;
	}

	strncpy(pack->server_version, (char *)pack->buffer, MYSQL_MAX_SERVER_VERSION_SIZE);
	pack->server_version[MYSQL_MAX_SERVER_VERSION_SIZE - 1]= 0;
	pack->buffer += ((ptr - pack->buffer) + 1);
	pack->buffer += 4;

	memcpy(pack->scramble, pack->buffer, 8);
	pack->buffer += 9;

	pack->capabilities= mysql_get_byte2(pack->buffer);
	pack->buffer += 2;

	pack->charset= pack->buffer[0];
	pack->buffer += 1;

	pack->status= mysql_get_byte2(pack->buffer);
	pack->buffer += 15;

	memcpy(pack->scramble + 8, pack->buffer, 12);
	pack->buffer += 13;

	pack->buffer_size -= pack->packet_size;
	pack->packet_size = 0;
	return MYSQL_OK;
}

void mysql_pack_scramble_hash(unsigned char *buffer, char *pass, unsigned char *scramble)
{
	int x;
	SHA1_CTX ctx;
	unsigned char hash_tmp1[SHA1_DIGEST_LENGTH];
	unsigned char hash_tmp2[SHA1_DIGEST_LENGTH];

	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char *)pass, strlen(pass));
	SHA1Final(hash_tmp1, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, hash_tmp1, SHA1_DIGEST_LENGTH);
	SHA1Final(hash_tmp2, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, scramble, SHA1_DIGEST_LENGTH);
	SHA1Update(&ctx, hash_tmp2, SHA1_DIGEST_LENGTH);
	SHA1Final(buffer, &ctx);

	for (x = 0; x < SHA1_DIGEST_LENGTH; x++) {
		buffer[x]= buffer[x] ^ hash_tmp1[x];
	}
}

size_t mysql_pack_login(void *user, size_t user_len,
					 void *pass, size_t pass_len,
					 void *db, size_t db_len,
					 int capabilities,
					 unsigned char charset,
					 unsigned char *scramble,
					 void *buffer)
{
	int packet_size= 4 /* Capabilities */
		+ 4   /* Max packet size */
		+ 1   /* Charset */
		+ 23  /* Unused */
		+ strlen(user) + 1
		+ 1   /* Scramble size */
		+ MYSQL_MAX_SCRAMBLE_SIZE
		+ strlen(db) + 1;

	if ((packet_size + 4) > MYSQL_MAX_BUFFER_SIZE) {
		return 0;
	}

	unsigned char *ptr = buffer;
	ptr[3]= 1; // packet index;
	ptr+= 4;

    capabilities = capabilities & MYSQL_CAPABILITIES_CLIENT;
    // capabilities |= MYSQL_CAPABILITIES_PROTOCOL_41;
	// capabilities = capabilities & MYSQL_CAPABILITIES_CLIENT;
	// capabilities &= ~MYSQL_CAPABILITIES_FOUND_ROWS;
	// capabilities &= ~(MYSQL_CAPABILITIES_COMPRESS | MYSQL_CAPABILITIES_SSL);

	mysql_set_byte4(ptr, capabilities);
	ptr+= 4;

	mysql_set_byte4(ptr, UINT32_MAX);
	ptr+= 4;

	ptr[0]= charset ? charset : 33; // charset UTF8
	ptr++;

	memset(ptr, 0, 23);
	ptr+= 23;

	memcpy(ptr, user, user_len);
	ptr+= user_len;
	ptr[0]= 0;
	ptr++;

	if (pass_len >  0) {
		ptr[0]= MYSQL_MAX_SCRAMBLE_SIZE;
		ptr++;

		mysql_pack_scramble_hash(ptr, pass, scramble);
		ptr+= MYSQL_MAX_SCRAMBLE_SIZE;

	} else {
		ptr[0]= 0;
		ptr++;
		packet_size-= MYSQL_MAX_SCRAMBLE_SIZE;
	}

	memcpy(ptr, db, db_len);
	ptr+= db_len;
	ptr[0]= 0;
	ptr++;

	int buffer_size = (4 + packet_size);
	if ((ptr - (unsigned char *)buffer) != (4 + packet_size)) {
		return 0;
	}

	ptr = buffer;
	mysql_set_byte3(ptr, packet_size);
	return buffer_size;
}

size_t mysql_pack_select(void *sql, size_t sql_len, void *buffer)
{
	unsigned char *ptr = buffer;
	int packet_size = 1 + sql_len;
	mysql_set_byte3(ptr, packet_size);
	ptr[3] = 0;
	ptr[4] = 3; // MYSQL QUERY

	memcpy(ptr + 5, sql, sql_len);
	return (5 + sql_len);
}

int mysql_unpack_length(mysql_pack *pack)
{
	int length;
	unsigned char bytes;
	if (pack->buffer[0] < 251) {
		length= pack->buffer[0];
		bytes= 1;

	} else if (pack->buffer[0] == 251) {
		pack->buffer++;
		pack->buffer_size--;
		pack->packet_size--;
		return 0;

	} else if (pack->buffer[0] == 252 && pack->buffer_size > 2) {
		length= mysql_get_byte2(pack->buffer + 1);
		bytes= 3;

	} else if (pack->buffer[0] == 253 && pack->buffer_size > 3) {
		length= mysql_get_byte3(pack->buffer + 1);
		bytes= 4;

	} else if (pack->buffer_size > 8) {
		length= mysql_get_byte8(pack->buffer + 1);
		bytes= 9;

	} else {
		return 0;
	}

	pack->buffer += bytes;
	pack->buffer_size-= bytes;
	pack->packet_size-= bytes;
	return length;
}

void mysql_unpack_string(mysql_pack *pack, char *buffer)
{
	int length = mysql_unpack_length(pack);
	if (buffer) {
        if (length < MYSQL_MAX_COLUMN_NAME_SIZE) {
            memcpy(buffer, pack->buffer, length);
            buffer[length] = 0;
        } else {
            *buffer = 0;
        }
    }

	pack->buffer += length;
	pack->buffer_size-= length;
	pack->packet_size-= length;
}

int mysql_pack_login_read(mysql_pack *pack)
{
	pack->packet_index = 2;
	if (mysql_packet_size_read(pack)) {
		return return_status(pack, MYSQL_ERROR);
	}

	if (pack->buffer[0] != 0) {
		return return_status(pack, MYSQL_ERROR);
	}

	pack->status = mysql_get_byte2(pack->buffer+1);
	if (pack->status) {
		return return_status(pack, MYSQL_ERROR);
	}

	mysql_packet_size_skip(pack);
	return MYSQL_OK;
}

int mysql_pack_select_read(mysql_pack *pack)
{
	pack->packet_index = 1;
	if (mysql_packet_size_read(pack)) {
		return return_status(pack, MYSQL_ERROR);
	}

	memset(&pack->result, 0 ,sizeof (mysql_result));
	if (pack->buffer[0] == 254) {
		pack->status= mysql_get_byte2(pack->buffer + 3);

		mysql_packet_size_skip(pack);
		return return_status(pack, MYSQL_END);


	} else if (pack->buffer[0] == 255) {
		mysql_packet_size_skip(pack);
		return return_status(pack, MYSQL_ERROR);

	} else {
		pack->result.column_count = mysql_unpack_length(pack);
		mysql_packet_size_skip(pack);
	}

	return MYSQL_OK;
}

int mysql_pack_result_read(mysql_pack *pack, void *buffer, size_t size)
{
	pack->buffer = buffer;
	pack->buffer_size = size;
	int ret = mysql_pack_login_read(pack);
	if (ret != MYSQL_OK) {
		return ret;
	}

	ret = mysql_pack_select_read(pack);
	if (ret != MYSQL_OK) {
		return ret;
	}

	return MYSQL_OK;
}

int mysql_pack_column_read(mysql_pack *pack)
{
	if (mysql_packet_size_read(pack)) {
		return return_status(pack, MYSQL_ERROR);
	}

	mysql_column *column = &pack->result.column;
	if (pack->packet_size == 5 && pack->buffer[0] == 254) {
		pack->result.warning_count= mysql_get_byte2(pack->buffer + 1);
		pack->status = mysql_get_byte2(pack->buffer + 3);
		pack->buffer += 5;
		pack->buffer_size-= 5;
		return return_status(pack, MYSQL_END);

	} else {

		mysql_unpack_string(pack, NULL); // catalog
		mysql_unpack_string(pack, NULL); // db
		mysql_unpack_string(pack, NULL); // table
		mysql_unpack_string(pack, NULL); // orig_table
		mysql_unpack_string(pack, column->name); // name
		mysql_unpack_string(pack, NULL); // orig_name

		column->charset = mysql_get_byte2(pack->buffer + 1);
		column->decimals= pack->buffer[10];
		column->size= mysql_get_byte4(pack->buffer + 3);
		column->type= pack->buffer[7];
		column->flags= mysql_get_byte2(pack->buffer + 8);

		pack->buffer += 13;
		pack->buffer_size-= 13;
		pack->packet_size-= 13;

		if (pack->packet_size > 0) {
			pack->buffer += pack->packet_size;
			pack->buffer_size-= pack->packet_size;
		}

		pack->result.column_current++;
	}

	return pack->result.column_current;
}

int mysql_pack_row_read(mysql_pack *pack)
{
	if (mysql_packet_size_read(pack)) {
		pack->result.status = MYSQL_ERROR;
		return MYSQL_ERROR;
	}

	mysql_result *result = &pack->result;
	if (pack->packet_size == 5 && pack->buffer[0] == 254) {
		result->row_current= 0;
		result->warning_count= mysql_get_byte2(pack->buffer + 1);
		pack->status= mysql_get_byte2(pack->buffer + 3);
		pack->buffer += 5;
		pack->buffer_size-= 5;

		result->status = MYSQL_END;
		return MYSQL_END;

	} else if (pack->buffer[0] == 255) {
		result->status = MYSQL_ERROR;
		return MYSQL_ERROR;

	} else {
		result->row_count++;
		result->row_current++;
		result->field_current= 0;
	}

	return result->row_current;
}

int mysql_pack_field_read(mysql_pack *pack)
{
	mysql_result *result = &pack->result;
	if (result->field_current == result->column_count) {
		return MYSQL_END;
	}

	if (pack->buffer_size <= 0) {
		result->status = MYSQL_IO_WAIT;
		return MYSQL_ERROR;
	}

	result->field_offset+= result->field_size;
	if (result->field_offset == result->field_total) {
		result->field_offset= 0;
		result->field_size= 0;
		result->field_total = mysql_unpack_length(pack);
		if ((pack->buffer_size) >= result->field_total)
			result->field_size = result->field_total;
		else
			result->field_size= pack->buffer_size;

	} else {
		if ((result->field_offset + pack->buffer_size) >=  result->field_total) {
			result->field_size= (result->field_total - result->field_offset);
		}  else {
			result->field_size= pack->buffer_size;
		}
	}

	if (result->field_size > pack->packet_size) {
		result->field_size = pack->packet_size;
	}

	result->field = (char *)pack->buffer;
	pack->buffer += result->field_size;
	pack->buffer_size-= result->field_size;
	pack->packet_size-= result->field_size;
	if ((result->field_offset + result->field_size) == result->field_total) {
		result->field_current++;
	}

	return result->field_current;
}

int mysql_pack_loop_read(mysql_pack *pack,
						 mysql_loop_column_read_t *column_read,
						 mysql_loop_row_read_t *row_read,
						 void *data)
{

	mysql_result *result = &pack->result;
	for (;;) {

		int col =  mysql_pack_column_read(pack);
		if (col == MYSQL_END) {
			break;
		}

		if (col == MYSQL_ERROR) {
			return result->status;
		}

		if (column_read) {
			column_read(result->column_current, result->column.type, result->column.name, data);
		}
	}

	for(;;) {

		int row = mysql_pack_row_read(pack);
		if (row == MYSQL_END) {
			break;
		}

		if (row == MYSQL_ERROR) {
			return result->status;
		}

		for(;;) {

			int index = mysql_pack_field_read(pack);
			if (index == MYSQL_END) {
				break;
			}

			if (index == MYSQL_ERROR) {
				return result->status;
			}

			if (row_read) {
				row_read(row, index, result->field, result->field_size, data);
			}
		}
	}

	return result->status;
}

