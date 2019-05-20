#!/bin/bash

set -x
set -e

# NOTE: this should be run within a python virtualenv, check requirements.txt

#####
# P0: main app
# P1: DEX code
# P2: .so code
# P3: shellcode
# P4: ROP
# P5: JavaScript

P1ENCFN="ckxalskuaewlkszdva"
P2ENCFN="mmdffuoscjdamcnssn"
P3ENCFN="xtszswemcwohpluqmi"
P5ENCFN="cxnvhaekljlkjxxqkq"

# uninstall vitor app, if present
if (adb shell pm list packages | grep -q ooo.vitor); then adb uninstall ooo.vitor; fi

# build P1, DEX
cd ./P1 && ./gradlew clean && ./gradlew assembleDebug && cd ..

# build encryptor
javac cryptor.java

# encrypt p1 (with K0)
java Cryptor ./P1/app/build/outputs/apk/debug/app-debug.apk ./Vitor/app/src/main/assets/$P1ENCFN $(python x.py getkey 0)

# build P1JNI, which contains P2, .so
cd ./P1JNI && ./gradlew clean && ./gradlew assembleDebug && cd ..
# encrypt and copy .so from P1JNI to P0 (it will be used by P1). The .so in P1 is just a stub
java Cryptor ./P1JNI/app/build/intermediates/cmake/debug/obj/x86/libnative-lib.so ./Vitor/app/src/main/assets/$P2ENCFN $(python x.py getkey 1)


# build P3, shellcode.bin
python x.py genshellcode shellcode.bin
# encrypt and copy P3 in in P0 (it will be used by P2)
python x.py encp3 ./shellcode.bin ./Vitor/app/src/main/assets/$P3ENCFN
rm -f ./shellcode.bin

# Note: P3 already contains P4 in encrypted form. P4 will then decrypt P5.

# encrypt P5 and copy it in P0 (it will be used by P4)
python x.py encp5 ./p5.html ./Vitor/app/src/main/assets/$P5ENCFN

# build main app, P0
cd Vitor && ./gradlew clean && ./gradlew assemble && cd ..

cp ./Vitor/app/build/outputs/apk/release/app-release-unsigned.apk ./vitor.apk
./sign_apk.sh vitor.apk

echo "[+] APK generated successfully: vitor.apk"

# install and test it
adb install vitor.apk
echo "[+] APK installed. You can now test it."
