#!/bin/bash

if [ "x$REQUEST_METHOD" == "xGET" ]; then
echo "Content-Type: text/html; charset=iso-8859-1"
echo  ""
sleep 0.1
cat << EOF
<html>
	<body>
		<form action="" method="POST">
			<label for="name">Name:</label>
			<input id="name" type="text" name="name">
			<input id="passwd" type="password" name="passwd">
			<input type="submit" value="signin">
		</form>
	</body>
</html>
EOF
fi
if [ "x$REQUEST_METHOD" == "xPOST" ]; then
echo "Content-Type: text/plain; charset=iso-8859-1"
echo  ""
sleep 0.1
echo $REQUEST_METHOD
echo $CONTENT_TYPE
echo $QUERY_STRING
read CONTENT
echo $CONTENT
while [ -n "$CONTENT" ]; do
	read CONTENT
	echo $CONTENT
done
fi
