#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

int main(void) {
    char buffer[BUFFER_SIZE];
    int fd = open("/dev/mouselog", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    ssize_t read_bytes = read(fd, buffer, BUFFER_SIZE - 1);
    if (read_bytes < 0) {
        perror("Failed to read");
        close(fd);
        return 1;
    }

    buffer[read_bytes] = '\0';
    printf("Read %zd bytes: %s\n", read_bytes, buffer);
    close(fd);
    return 0;
}