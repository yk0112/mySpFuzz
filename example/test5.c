#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define ARRAY1_SIZE 16
uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t array2[256 * 512];
uint8_t temp = 0;

void var(size_t index) {
    if (index < ARRAY1_SIZE / 2) {
        temp &= array2[array1[index] * 512]; // order2で検出
        if (index < ARRAY1_SIZE / 4) {
            temp &= array2[array1[index] * 512]; // order3で検出
        }
    }
}

void foo(size_t index) {
  while (index < ARRAY1_SIZE) { 
    temp &= array2[array1[index] * 512]; // order1で検出
    var(index);
    ++index;
  }
}

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "r");
    char value[1024];
    fscanf(f, " %1023s", value);
  
    int index = atoi(value);

    foo(index);
    return 0;
}
