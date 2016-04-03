## Mac OSX

### Install Andy from http://www.andyroid.net/

### Install adb

    brew install fb-adb
    android update sdk --no-ui --filter 'platform-tools'

# Root Andy by the follwoing step

    adb kill-server
    adb root

    adb install Superuser.apk
    adb push su /storage/sdcard0/
    adb shell


    su
    mount -o remount,rw /system
    mv /system/xbin/su /system/xbin/su.old
    cp /storage/sdcard0/su /system/xbin/su
    chmod 06755 /system/xbin/su
    mount -o remount,ro /system


** works on OSX Andy 4.3
