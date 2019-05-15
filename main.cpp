#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <iomanip>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <iostream>
#include <set>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "bch.h"

#define CONFIG_M 13
#define CONFIG_T 8

#define READ_LENGTH 4096
#define SEC_LENGTH 512

#define BCH_LENGTH (13 * 8)
#define SHA1_LENGTH 20

uint64_t total_count = 0;
uint64_t bch_unique_count = 0;
uint64_t bch_4KB_unique_count = 0;
uint64_t sha1_unique_count = 0;

std::set<std::string> list_bch; // 8 * 512B
std::set<std::string> list_bch_4KB; //4096B
std::set<std::string> list_sha1;

struct bch_control *bch;

void usage(){
    std::cout << "-a: The data set path."<< std::endl;
    std::cout << "-b: The device path."<< std::endl;
    std::cout << "-c: The deduplication scheme."<< std::endl;
    std::cout << "-d: The strategy to read data sets."<< std::endl;
    std::cout << "-e: Whether use cache."<< std::endl;
    std::cout << "-f: The cache size."<< std::endl;
    std::cout << "-g: The prefetch cache length."<< std::endl;
}

void content_generator(uint8_t *hash, uint8_t *content, int length) {
    int rep_num = length / 8;
    uint8_t temp[rep_num + 1];
    int i = 0, j = 0;

    for(; i < 8; i++) {
        memcpy(temp, hash + i * rep_num, rep_num);
        for(j = 0; j < SEC_LENGTH; j++) {
            content[i * SEC_LENGTH + j] = temp[j % rep_num];
        }

    }
    //std::cout << hash << std::endl;
    //std::cout << content << std::endl;
}

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen) {
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i++)
    {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f ;

        highByte += 0x30;

        if (highByte > 0x39)
            dest[i * 2] = highByte + 0x07;
        else
            dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return ;
}

int file_reader(char *path) {
    uint8_t bch_4KB[(CONFIG_T * CONFIG_M / 8) + 1];
    uint8_t bch_ori[BCH_LENGTH + 1];
    uint8_t sha1_ori[SHA1_LENGTH + 1];
    char bch_4KB_result[2 * (CONFIG_T * CONFIG_M / 8) + 1];
    char bch_result[2 * BCH_LENGTH + 1];
    char sha1_result[2 * SHA1_LENGTH + 1];
    uint8_t generated_content[READ_LENGTH + 1];
    FILE *fp = NULL;
    uint8_t chk_cont[4097];

    uint8_t mid_bch[(CONFIG_T * CONFIG_M / 8) + 1];
    uint8_t mid_content[SEC_LENGTH + 1];

    std::string mid_str;

    int i;

    //char blk_num_str[30];

    if((fp = fopen(path, "r")) == NULL){
        std::cout<<"Open file error!The file name is: "<<path<<std::endl;
        return 0;
    }

    while(1){
        if(fread(chk_cont, sizeof(char), READ_LENGTH, fp) == 0)
            break;

        ++total_count;
        memset(bch_ori, 0, BCH_LENGTH + 1);
        memset(bch_result, 0, 2 * BCH_LENGTH + 1);
        memset(bch_4KB, 0, (CONFIG_T * CONFIG_M / 8) + 1);
        memset(bch_4KB_result, 0, 2 * (CONFIG_T * CONFIG_M / 8) + 1);
        memset(sha1_ori, 0, SHA1_LENGTH + 1);
        memset(sha1_result, 0, 2 * SHA1_LENGTH + 1);



        SHA1((unsigned char *)chk_cont, (size_t)4096, (unsigned char *)sha1_ori);
        ByteToHexStr(sha1_ori, sha1_result, SHA1_LENGTH);
        mid_str = sha1_result;
        if(list_sha1.find(mid_str) == list_sha1.end()){
            sha1_unique_count++;
            list_sha1.insert(mid_str);
        }

        memset(generated_content, 0, READ_LENGTH + 1);
        content_generator((uint8_t *)sha1_result, generated_content, 2 * SHA1_LENGTH);
        for(i = 0; i < 8; i++){
            memset(mid_content, 0, SEC_LENGTH + 1);
            memcpy(mid_content, generated_content + (SEC_LENGTH * i), SEC_LENGTH);
            encode_bch(bch, mid_content, SEC_LENGTH, mid_bch);
            memcpy(bch_ori + ((CONFIG_T * CONFIG_M / 8) * i), mid_bch, CONFIG_T * CONFIG_M / 8);

        }
        ByteToHexStr(bch_ori, bch_result, BCH_LENGTH);
        bch_result[2 * BCH_LENGTH] = '\0';
        mid_str = bch_result;
        //std::cout << mid_str << std::endl;
        if(list_bch.find(mid_str) == list_bch.end()){
            bch_unique_count++;
            list_bch.insert(mid_str);
        }

        encode_bch(bch, chk_cont, READ_LENGTH, bch_4KB);
        ByteToHexStr(bch_4KB, bch_4KB_result, CONFIG_T * CONFIG_M / 8);
        bch_4KB_result[2 * (CONFIG_T * CONFIG_M / 8)] = '\0';
        mid_str = bch_4KB_result;
        std::cout<< mid_str << std::endl;
        if(list_bch_4KB.find(mid_str) == list_bch_4KB.end()){
            bch_4KB_unique_count++;
            list_bch_4KB.insert(mid_str);
        }




    }
}

void travel_dir(char *path) {
    DIR *pdir;
    struct dirent *ent;
    char child_path[512];
    pdir = opendir(path);
    if(pdir == NULL){
        std::cout<<"Open dir error!"<<std::endl;
        exit(-1);
    }

//    std::cout<<"1"<<std::endl;
    while((ent = readdir(pdir)) != NULL){
        memset(child_path, 0, 512);
        if(ent->d_type & DT_DIR){ //if the ent is dir
            if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
            sprintf(child_path,"%s/%s",path,ent->d_name);
            travel_dir(child_path);
        }
        else{
            sprintf(child_path,"%s/%s",path,ent->d_name);
//            std::cout<<child_path <<std::endl;
            file_reader(child_path);
        }
    }
}




int main(int argc, char *argv[]) {
    char path[256] = {};
    int ch;

    bch = init_bch(CONFIG_M, CONFIG_T, 0);
    while((ch = getopt(argc, argv, "p:") ) != -1){
        switch (ch){
            case 'p':
                strcpy(path, optarg);
                break;

            default:
                usage();
                exit(-1);

        }
    }
    if(strlen(path) == 0){
        std::cout << "There is no data set path input." << std::endl;
        exit(0);
    } else{
        std::cout << "The data set path is: " << path << std::endl;
    }

    travel_dir(path);

    //std::cout << "Please input the enter to start the test! " << std::endl;
    //getchar();

    std::cout << "The dedupe rate of SHA1 is " <<  (total_count - sha1_unique_count) * 100.0 / total_count <<"%"<<std::endl;
    std::cout << "The dedupe rate of 4KB bch is " <<  (total_count - bch_4KB_unique_count) * 100.0 / total_count <<"%"<<std::endl;
    std::cout << "The dedupe rate of SSD bch is " <<  (total_count - bch_unique_count) * 100.0 / total_count <<"%"<<std::endl;
    std::cout << total_count << std::endl;
    std::cout << sha1_unique_count << std::endl;
    std::cout << bch_unique_count << std::endl;
    return 0;
}

