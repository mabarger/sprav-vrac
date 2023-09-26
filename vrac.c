/*
 * Copyright (c) 2023 Maximilian Barger
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>

#include <oqs/oqs.h>

#define TTY_PATH ("/dev/ttyUSB0")

#define PUB_KEY_PATH ("./keys/dilithium2.pub")
#define SPRAV_SIG_SIZE (OQS_SIG_dilithium_2_length_signature)
#define OQS_SIG_VERIFY OQS_SIG_dilithium_2_verify
#define OQS_SIG_PUB_KEY_LENGTH OQS_SIG_dilithium_2_length_public_key

#define ATTEST_REGION_ADDR (0x40380000)
#define ATTEST_REGION_SIZE (0x2000)

#define SHA_256_DIGEST_SIZE (32)
#define MESSAGE_LEN (SHA_256_DIGEST_SIZE + sizeof(uint32_t))

const uint8_t default_hash[SHA_256_DIGEST_SIZE] = {
	0x5a, 0x42, 0x2b, 0x44, 0x30, 0xc4, 0x5f, 0xbb,
	0x11, 0x73, 0xc3, 0x55, 0x28, 0xe6, 0xcd, 0x8e,
	0xb8, 0x4e, 0x46, 0x9d, 0x96, 0x3e, 0x9f, 0x51,
	0xc5, 0x53, 0x0f, 0xa0, 0xad, 0x48, 0xe9, 0xc8,
};

struct __attribute__((packed)) attest_request {
	char     magic[5];
	uint32_t addr;
	uint32_t size;
	uint32_t nonce;
	char     end;
};

struct __attribute__((packed)) attest_response {
	char     magic[5];
	bool     success;
	uint8_t  signature[SPRAV_SIG_SIZE];
};

int check_signature(uint8_t *signature, uint32_t nonce) {
	OQS_STATUS ret = 0;
	uint8_t public_key[OQS_SIG_PUB_KEY_LENGTH];

	uint8_t msg[MESSAGE_LEN];
	uint32_t *nonce_ptr = (uint32_t *) (msg + SHA_256_DIGEST_SIZE);
	FILE *public_key_file = NULL;

	/* Read in public key */
	if ((public_key_file = fopen(PUB_KEY_PATH, "r")) == NULL) {
		perror("[!] Failed to open public key file");
		return errno;
	}
	if (fread(public_key, 1, OQS_SIG_PUB_KEY_LENGTH, public_key_file) != OQS_SIG_PUB_KEY_LENGTH) {
		fprintf(stderr, "[!] File %s does not contain a valid public key\n", PUB_KEY_PATH);
		return ENOENT;
	}
	fclose(public_key_file);

	/* Build message */
	memcpy(msg, default_hash, SHA_256_DIGEST_SIZE);
	*nonce_ptr = nonce;

	/* Check signature */
	return OQS_SIG_VERIFY(msg, MESSAGE_LEN, signature, SPRAV_SIG_SIZE, public_key);
}

int main(int argc, char **argv)
{
	struct termios uart_config;
	char *uart_path = TTY_PATH;
	int uart_fd = 0;
	int status = 0;
	struct attest_request req = {{'s', 'p', 'r', 'a', 'v'}};
	struct attest_response resp = {0};
	size_t buf_pos = 0;

	/* Open and configure UART device */
	if ((uart_fd = open(uart_path, O_RDWR | O_NOCTTY)) == -1) {
		perror("[!] Failed to open UART device");
		return errno;
	}
	tcgetattr(uart_fd, &uart_config);
	cfsetospeed(&uart_config, B115200);
	cfsetispeed(&uart_config, B115200);
	tcflush(uart_fd, TCIFLUSH);
	tcsetattr(uart_fd, TCSANOW, &uart_config);

	/* Build attestation request */
	req.addr = ATTEST_REGION_ADDR;
	req.size = ATTEST_REGION_SIZE;
	getrandom(&req.nonce, sizeof(uint32_t), GRND_RANDOM);
	req.end = 0x0a;

	/* Send attestation request */
	status = write(uart_fd, (void *) &req, sizeof(struct attest_request) );
	if (status != sizeof(struct attest_request)) {
		perror("[!] Failed to send attestation request to prover");
		return errno;
	}
	printf("[~] attestation request sent to prover\n");
	printf("    |- addr:  0x%08x\n", req.addr);
	printf("    |- size:  0x%08x\n", req.size);
	printf("    |- nonce: 0x%08x\n", req.nonce);

	/* Receive data */
	printf("[~] waiting for attestation response\n");
	uint8_t *recv_buf = (uint8_t *) &resp;
	while (buf_pos != sizeof(struct attest_response)) {
		status = read(uart_fd, &recv_buf[buf_pos], 1);
		if (status == 1) {
			buf_pos++;
		}
	}

	/* Check message format */
	if (memcmp(resp.magic, "sprav", 5) != 0) {
		printf("[!] did not receive valid response\n");
		return EXIT_FAILURE;
	}

	printf("[~] received attestation response\n");
	if (resp.success != true) {
		printf("[!] prover failed to compute a signature\n");
		return EXIT_FAILURE;
	}

	/* Check signature */
	status = check_signature(resp.signature, req.nonce);

	if (status == OQS_SUCCESS) {
		printf("[+] signature is valid\n");
	} else {
		printf("[!] signature is invalid\n");
	}

	/* Close UART device */
	close(uart_fd);

	return EXIT_SUCCESS;
}
