#!/bin/bash
DUMPFILE=/tmp/echo.cgi.dump
echo -n > $DUMPFILE
echo "$CONTENT_TYPE" | grep -q "multipart/form-data"
LENGTH=0
if [ $? -eq 0 ]; then
  read BOUNDARY
  LENGTH=$(($LENGTH + $(echo $BOUNDARY | wc -c) ))
  read BOUNDARY_HEADER
  LENGTH=$(($LENGTH + $(echo $BOUNDARY_HEADER | wc -c) ))
  BOUNDARY_HEADER=$(echo -n $BOUNDARY_HEADER | head -c -1 )
  while [ -n "$BOUNDARY_HEADER" ]; do
    echo "$BOUNDARY_HEADER" | grep -q "Content-Type"
    if [ $? -eq 0 ]; then
      CONTENT_TYPE=$(echo $BOUNDARY_HEADER | cut -d":" -f 2-)
    fi
    echo "$BOUNDARY_HEADER" | grep -q "Content-Length"
    if [ $? -eq 0 ]; then
      CONTENT_LENGTH=$(echo $BOUNDARY_HEADER | cut -d":" -f 2-)
    fi
    read BOUNDARY_HEADER
    LENGTH=$(($LENGTH + $(echo $BOUNDARY_HEADER | wc -c) ))
    BOUNDARY_HEADER=$(echo -n $BOUNDARY_HEADER | head -c -1 )
  done
fi
printf "Content-Type: $CONTENT_TYPE\r\n"
if [ -n "$CONTENT_LENGTH" -a "$CONTENT_LENGTH" != "0" ]; then
  CONTENT_LENGTH=$(($CONTENT_LENGTH - $LENGTH))
  printf "Content-Length: $CONTENT_LENGTH\r\n"
fi
printf "\r\n"
cat /dev/stdin | tee -a $DUMPFILE
