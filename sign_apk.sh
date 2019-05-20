#!/bin/bash

#keytool -genkey -v -keystore debug.keystore -alias androiddebugkey -keyalg DSA -sigalg SHA1withDSA -keysize 1024 -validity 10000

jarsigner -keystore `dirname $0`/debug.keystore -verbose -storepass android -keypass android -sigalg SHA1withDSA -digestalg SHA1 $1 androiddebugkey

#jarsigner -verify -verbose -certs $1
