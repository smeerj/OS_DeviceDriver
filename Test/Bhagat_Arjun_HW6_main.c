/**************************************************************
 * Class::  CSC-415-01 Fall 2024
 * Name::  Arjun Bhagat
 * Student ID::  917129686
 * GitHub-Name::  smeerj
 * Project:: Assignment 6 - Device Driver
 *
 * File:: Bhagat_Arjun_HW6_main.c
 *
 * Description:: Program to test the device driver
 *
 **************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int fd = open("/dev/cryptographer", O_RDWR);

    if (fd < 0)
    {
        perror("Device open error");
        return -1;
    }

    char mssg[256] = "Greetings grader";
    int test_shifts[3] = {0, 13, 25};

    for (int i = 0; i < 3; i++)
    {
        if (ioctl(fd, 3, &test_shifts[i]) < 0)
        {
            perror("ioctl error");
            close(fd);
            return -1;
        }

        if (write(fd, mssg, strlen(mssg) + 1) < 0)
        {
            perror("Write error");
            close(fd);
            return -1;
        }

        if (read(fd, mssg, sizeof(mssg) - 1) < 0)
        {
            perror("Read error");
            close(fd);
            return -1;
        }

        printf("Encrypted message: %s\n", mssg);
        printf("Keyshift used: %d\n", test_shifts[i]);

        if (ioctl(fd, 4, &test_shifts[i]) < 0)
        {
            perror("ioctl error");
            close(fd);
            return -1;
        }

        if (write(fd, &mssg, strlen(mssg) + 1) < 1)
        {
            return -1;
        }

        if (read(fd, &mssg, sizeof(mssg) - 1) < 0)
        {
            return -1;
        }

        printf("Decrypted message: %s\n", mssg);
        printf("Keyshift used: %d\n\n", test_shifts[i]);
    }

    close(fd);
    return 0;
}