#!/bin/bash
if [ -n "$CONTENT_LENGTH" -a "$CONTENT_LENGTH" != "0" ]; then
  read CONTENT
  RESPONSE_LEN=$(echo $CONTENT | wc -c)
  RESPONSE_LEN=$(($RESPONSE_LEN + 26))
  printf "Content-Length: $RESPONSE_LEN\r\n"
else
  printf "Content-Length: 32\r\n"
fi
printf "\r\n"
printf "<html><body>"
if [ -n "$CONTENT" ]; then
  printf $CONTENT
else
  printf "hello"
fi
printf "</body></html>\r\n"
