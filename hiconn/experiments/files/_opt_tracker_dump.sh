#!/bin/bash
if [ -s "/data/nginx/access.log" ]; then
    FILE_NAME=$(date +%Y%m%d%H%M%S)_NODE_NAME
    mv /data/nginx/access.log /data/tracker/raw/${FILE_NAME}
    [ $? -ne 0 ] && exit $?
    kill -USR1 `cat /run/nginx.pid`
    counter=1
    while [ ! -f "/data/nginx/access.log" ]
    do
        if (( $counter > 3 )); then
           echo "something wrong, report it"
           exit 1
        fi
        echo "Waiting for nginx log to a new file $counter seconds"
        counter=$((counter+1))
        sleep 2
    done
    # lzop -U /data/tracker/raw/"$FILE_NAME"
    # [ $? -eq 0 ] && s3cmd put /data/tracker/raw/"$FILE_NAME".lzo s3://thescore-tracker-dump/$(date +%Y%m)/$(date +%d%H)/
    gzip /data/tracker/raw/"$FILE_NAME"
    [ $? -eq 0 ] && s3cmd put /data/tracker/raw/"$FILE_NAME".gz s3://S3_BUCKET_NAME/$(date +%Y%m)/$(date +%d%H)/
    if [ $? -eq 0 ]; then
        # mv /data/tracker/raw/"$FILE_NAME".lzo /data/tracker/success/
        rm /data/tracker/raw/"$FILE_NAME".gz
    else
        mv /data/tracker/raw/"$FILE_NAME".gz /data/tracker/fail/
    fi
else
    echo "The size of log is zero. Skip."
fi
