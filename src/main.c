#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#include <args_parser/args_parser.h>

#define BUFFER_SIZE 8192 // 4096

typedef struct {
	mode_t mode;
	char hash[96];
	char filename[256];
} FileHeader;

void get_file_name(char *path, char **name) {
	char *l_del = path;
	for(int i = 0; i < strlen(path); i++) {
		if(path[i] == '/')
			l_del = path + i + 1;
	}
	*name = l_del;
}

void show_help() {
	printf("Encryptor\n");
	printf("\tUsage:\n");
	printf("\t\tencryptor --encrypt --key secret --file x --output y\n");
	printf("\t\tencryptor --decrypt --key secret --file y --output z\n");
	printf("\tOptions:\n");
	printf("\t\t--encrypt | -e - encrypt file\n");
	printf("\t\t--decrypt | -d - decrypt file\n");
	printf("\t\t--key | -k [secret] - the key to encrypt or decrypt the file with\n");
	printf("\t\t--file | -f [file] - the file to encrypt or decrypt\n");
	printf("\t\t--output | -o [file] - the output file (the encrypted or decrypted file)\n");
	printf("\t\t--help | -h - displays this message\n");
}

void sha1(const char *message, char output_buffer[41]) {
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, message, strlen(message));
	SHA1_Final(hash, &ctx);
	for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(output_buffer + (i * 2), "%02x", hash[i]);
	}
	output_buffer[SHA_DIGEST_LENGTH * 2] = 0;
}

void md5(const char *message, char output_buffer[33]) {
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, message, strlen(message));
	MD5_Final(hash, &ctx);
	for(int i = 0; i <MD5_DIGEST_LENGTH; i++) {
		sprintf(output_buffer + (i * 2), "%02x", hash[i]);
	}
	output_buffer[MD5_DIGEST_LENGTH * 2] = 0;
}

void hash(const char *message, char output_buffer[97]) {
	char sha1_hash[65];
	char md5_hash[33];

	sha1(message, sha1_hash);
	md5(message, md5_hash);

	strcpy(output_buffer, sha1_hash);
	strcat(output_buffer, md5_hash);
}

unsigned int get_offset(const char *seed) {
	unsigned int ret = 1;
	for(int i = 0; i < strlen(seed); i++) {
		ret += (unsigned int)seed[i];
	}
	return ret % 256;
}

void encrypt_file(char *file, char *output, char *key) {
	struct stat stat_buffer;
	if(stat(output, &stat_buffer) != -1) {
		printf("%s: %s\n", output, "file already exists!");
		return;
	}
	if(stat(file, &stat_buffer) == -1) {
		printf("%s: %s\n", file, strerror(errno));
		return;
	}

	int rfd = open(file, O_SYNC, O_RDONLY);
	if(rfd == -1) {
		printf("%s: %s\n", file, strerror(errno));
		return;
	}
	int wfd = creat(output, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if(wfd == -1) {
		printf("%s: %s\n", output, strerror(errno));
		return;
	}

	char *name;
	get_file_name(file, &name);

	char hashstr[97];
	hash(key, hashstr);

	unsigned int header_offset = get_offset(hashstr);
	unsigned int body_offset = get_offset(key);
	unsigned int total_offset = (header_offset + body_offset) % 256;

	FileHeader *header = (FileHeader*) malloc(sizeof(FileHeader));
	memset(header, 0, sizeof(FileHeader));
	header->mode = stat_buffer.st_mode;
	strncpy(header->filename, name, 256);
	strncpy(header->hash, hashstr, 96);

	char *buffer = (char*) header;
	for(ssize_t i = 0; i < sizeof(FileHeader); i++) {
		buffer[i] += header_offset;
	}
	if(write(wfd, (void*)buffer, sizeof(FileHeader)) == -1) {
		perror("wfd\n");
	}

	free(header);
	
	buffer = (char*)malloc(sizeof(char) * BUFFER_SIZE);
	ssize_t read_count = 0;
	off_t total_size = stat_buffer.st_size;
	off_t done_size = 0;
	printf("encrypting...\n");
	while((read_count = read(rfd, (void*)buffer, BUFFER_SIZE)) > 0) {
		done_size += read_count;
		for(ssize_t i = 0; i < read_count; i++) {
			buffer[i] += total_offset;
		}
		if(write(wfd, (void*)buffer, read_count) == -1) {
			perror("wfd\n");
		}
		printf("\r%03.3f%%", 100.0f * ((float)done_size / (float)total_size));
	}

	printf("\n");

	printf("%s --> %s\n", file, output);

	close(rfd);
	close(wfd);
}

void decrypt_file(char *file, char *output, char *key) {
	char hashstr[97];
	hash(key, hashstr);
	
	unsigned int header_offset = get_offset(hashstr);
	unsigned int body_offset = get_offset(key);
	unsigned int total_offset = (header_offset + body_offset) % 256;
	
	struct stat stat_buffer;
	if(stat(file, &stat_buffer) == -1) {
		printf("%s: %s\n", file, strerror(errno));
		return;
	}

	int rfd = open(file, O_SYNC, O_RDONLY);
	if(rfd == -1) {
		printf("%s: %s\n", file, strerror(errno));
		return;
	}

	off_t total_size = stat_buffer.st_size - sizeof(FileHeader);

	char *buffer;
	buffer = (char*)malloc(sizeof(FileHeader));
	FileHeader *header = (FileHeader*) buffer;
	if(read(rfd, (void*)buffer, sizeof(FileHeader)) == -1) {
		perror("rfd\n");
	}

	for(ssize_t i = 0; i < sizeof(FileHeader); i++) {
		buffer[i] -= header_offset;
	}

	if(strncmp(header->hash, hashstr, 96) != 0) {
		printf("[ERROR] key is incorrect!\n");
		close(rfd);
		return;
	}

	if(output == NULL) output = header->filename;

	if(stat(output, &stat_buffer) != -1) {
		printf("%s: %s\n", output, "file already exists!");
		close(rfd);
		return;
	}

	int wfd = creat(output, header->mode);
	if(wfd == -1) {
		printf("%s: %s\n", output, strerror(errno));
		close(rfd);
		return;
	}
	header = NULL;
	free(buffer);

	buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);
	ssize_t read_count = 0;

	off_t done_size = 0;
	printf("decrypting...\n");
	while((read_count = read(rfd, (void*)buffer, BUFFER_SIZE)) > 0) {
		done_size += read_count;
		for(ssize_t i = 0; i < read_count; i++) {
			buffer[i] -= total_offset;
		}
		if(write(wfd, buffer, read_count) == -1) {
			perror("wfd\n");
		}
		printf("\r%3.3f", 100.0f * ((float)done_size / (float)total_size));
	}

	printf("\n");

	printf("%s --> %s\n", file, output);

	close(rfd);
	close(wfd);
}

int main(int argc, char **argv) {

	char *help;
	char *encrypt;
	char *decrypt;
	char *key;
	char *file;
	char *output;

	ArgsParser *parser = (ArgsParser*) malloc(sizeof(ArgsParser));
	args_parser_create(parser);

	args_parser_add_option(parser, "help", ARGS_PARSER_BOOL, &help);
	args_parser_add_option(parser, "h", ARGS_PARSER_SHORT | ARGS_PARSER_BOOL, &help);

	args_parser_add_option(parser, "encrypt", ARGS_PARSER_BOOL, &encrypt);
	args_parser_add_option(parser, "e", ARGS_PARSER_SHORT | ARGS_PARSER_BOOL, &encrypt);

	args_parser_add_option(parser, "decrypt", ARGS_PARSER_BOOL, &decrypt);
	args_parser_add_option(parser, "d", ARGS_PARSER_SHORT | ARGS_PARSER_BOOL, &decrypt);

	args_parser_add_option(parser, "key", ARGS_PARSER_NORMAL, &key);
	args_parser_add_option(parser, "k", ARGS_PARSER_NORMAL | ARGS_PARSER_SHORT, &key);

	args_parser_add_option(parser, "file", ARGS_PARSER_NORMAL, &file);
	args_parser_add_option(parser, "f", ARGS_PARSER_NORMAL | ARGS_PARSER_SHORT, &file);

	args_parser_add_option(parser, "output", ARGS_PARSER_NORMAL, &output);
	args_parser_add_option(parser, "o", ARGS_PARSER_NORMAL | ARGS_PARSER_SHORT, &output);

	args_parser_parse(parser, argc, argv);

	args_parser_destroy(parser);
	free(parser);

	if(help) {
		show_help();
		return 0;
	}

	if(encrypt) {
		if(file == NULL)
			printf("[ERROR] source file is not set (--file [file_path] or -f [file_path])\n");
		if(output == NULL)
			printf("[ERROR] output file is not set (--output [file_path] or -o [file_path])\n");
		if(key == NULL)
			printf("[ERROR] encryption key is not set (--key [key] or -k [key])\n");
		if(file == NULL || key == NULL || output == NULL)
			return 0;
	} else if(decrypt) {
		if(file == NULL)
			printf("[ERROR] source file is not set (--file [file_path] or -f [file_path])\n");
		if(key == NULL)
			printf("[ERROR] encryption key is not set (--key [key] or -k [key])\n");
		if(file == NULL || key == NULL)
			return 0;
	}

	if(encrypt) {
		encrypt_file(file, output, key);
	} else if(decrypt) {
		decrypt_file(file, output, key);
	} else {
		show_help();	
	}

	return 0;
}
