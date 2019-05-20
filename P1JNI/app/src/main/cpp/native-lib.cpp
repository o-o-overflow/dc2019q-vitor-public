#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <jni.h>
#include <string>
#include <android/log.h>

#define  LOG_TAG    "OOO"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG ,LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define P3ENCFN "xtszswemcwohpluqmi"
#define P5ENCFN "cxnvhaekljlkjxxqkq"

unsigned int g2(unsigned char *flag) {
    unsigned int K2 = 0;
//    LOGE("g2: flag is: %s", flag);
    flag += 4; // skip the OOO{
    int i, j;
    for (i=3; i<10; i+=3) {
        K2 = K2 ^ *((unsigned int *)&(flag[4*(i-1)]));
//        LOGE("g2: i=%d, new K2=0x%08x", i, K2);
    }
//    LOGE("K2: %02x%02x%02x%02x", ((K2>>24)&0xff), ((K2>>16)&0xff), ((K2>>8)&0xff),(K2&0xff));
    return K2;
}

void dp3(unsigned char *p3enc, unsigned int K2) {
    // decrypt in place
    int i;
    for (i = 0; i < 100; i++) {
        (*(unsigned int *) (p3enc+4*i)) ^= K2;
        K2 += 0x31333337;
    }
}


extern "C" JNIEXPORT jstring

JNICALL
Java_ooo_p1_P1_xxx(
        JNIEnv *env,
        jobject /* this */,
        jstring fs,
        jstring fds) {

//    LOGE("inside P2:checkFlag \\o/");

    const char *ff = env->GetStringUTFChars(fs, NULL);
    if (NULL == ff) return NULL;

    const char *fd = env->GetStringUTFChars(fds, NULL);
    if (NULL == fd) return NULL;

//    LOGE("JNI fd: %s", fd);

    // allocate memory and copy the shellcode / P3
    unsigned char *sb = (unsigned char *) mmap(NULL, 1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sb == MAP_FAILED) return NULL;

    char* sfe = (char*) malloc(strlen(fd) + 1 + strlen(P3ENCFN));
    strcpy(sfe, fd);
    strcat(sfe, "/");
    strcat(sfe, P3ENCFN);
//    LOGE("sfe: %s", sfe);

    FILE *shF = fopen(sfe, "rb");
    if (shF == NULL) return NULL;
    fread(sb, 400, 1, shF);
    fclose(shF);
    unlink(sfe);

    // sb now stores the encrypted shellcode

    unsigned int K2 = g2((unsigned char *) ff);
    dp3(sb, K2);

    // sb now stores the decrypted shellcode

    // p5encfp
    char* qwe = (char*) malloc(strlen(fd) + 1 + strlen(P5ENCFN));
    strcpy(qwe, fd);
    strcat(qwe, "/");
    strcat(qwe, P5ENCFN);

    // read in memory p5enc
    FILE *fffe = fopen(qwe, "rb");
    if (fffe == NULL) return NULL;
    fseek(fffe, 0, SEEK_END);
    long req = ftell(fffe); // req
    fseek(fffe, 0, SEEK_SET);  /* same as rewind(f); */

    // mmm
    unsigned char *mmm = (unsigned char*) malloc(req);
    fread(mmm, req, 1, fffe);
    fclose(fffe);
    unlink(qwe);

    // mmm stores encrypted p5

    // IMPORTANT: leave this comment here so that they know to expect 909090
    LOGD("Jumping to nopsled in 3, 2, 1, ...");

    // The shellcode takes two arguments: pointers to ff and mmm
    // The shellcode (P3) computes K3, decrypts P4, and jumps on it
    // P4 computes K4, computes P5, then returns here
    int (*foo)(void*,void*,unsigned int) = (int(*)(void*,void*,unsigned int))sb;
    int ret = foo((void*)ff, (void*)mmm, req);

//    LOGE("ret value from shellcode: 0x%08x", ret);

    if (ret != 0x31337) {
//        LOGE("Some error occurred while shellcode execution");
        return NULL;
    }

    // now mmm stores the decrypted p5

    if (memcmp(mmm, "<html>", 6) != 0) {
        return NULL;
    }

    // save the new mmm in p5.apk
    char *oeipuy = (char *) malloc(strlen(fd) + 1 + strlen("bam.html"));
    strcpy(oeipuy, fd);
    strcat(oeipuy, "/");
    strcat(oeipuy, "bam.html");

    FILE *eeq = fopen(oeipuy, "wb");
    if (eeq == NULL) return NULL;
    fwrite(mmm, req, 1, eeq);
    fclose(eeq);

    free(sfe);
    free(qwe);

    // path to p5.apk
    std::string oiu = std::string(oeipuy);

    env->ReleaseStringUTFChars(fs, ff);
    env->ReleaseStringUTFChars(fds, fd);

    return env->NewStringUTF(oiu.c_str());
}