#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }

    int fd = open("/dev/mouselog", O_WRONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    ssize_t written = write(fd, argv[1], strlen(argv[1]));
    if (written < 0) {
        perror("Failed to write");
        close(fd);
        return 1;
    }

    printf("Wrote %zd bytes: %s\n", written, argv[1]);
    close(fd);
    return 0;
}