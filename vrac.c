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

#define DEFAULT_TTY_PATH ("/dev/ttyUSB0")

#define ATTEST_REGION_ADDR (0x40380000)
#define ATTEST_REGION_SIZE (0x2000)
#define SPRAV_SIG_SIZE (2420)

//#include <oqs/oqs.h>

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

int main(int argc, char **argv)
{
	struct termios uart_config;
	char *uart_path = DEFAULT_TTY_PATH;
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

	/* Check signature */
	printf("[~] received attestation response\n");
	if (resp.success != true) {
		printf("[!] prover failed to compute a signature\n");
		return EXIT_FAILURE;
	}

	printf("Signature:\n");
	for (size_t i = 0; i < SPRAV_SIG_SIZE; i++) {
		printf("%02x", resp.signature[i]);
	}
	printf("\n");


	/* Close UART device */
	close(uart_fd);

	return EXIT_SUCCESS;
}
