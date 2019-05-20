#include <sys/mman.h>
#include <errno.h>
#include <jni.h>
#include <string>
#include <android/log.h>

#define  LOG_TAG    "OOO"
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jstring

JNICALL
Java_ooo_p1_P1_xxx(
        JNIEnv *env,
        jobject /* this */,
        jstring flagStr,
        jstring filesDirStr) {

    // placeholder
    LOGE("this flag doesn't look too good ;-)");

    return NULL;
}
