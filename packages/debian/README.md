To build debian package:
 * copy the *package/debian* directory into the root directory of "ouistiti"
```shell
> cp -r package/debian .
```
 * create a link from the libouistiti into the root directory, named "libhttpserver"
```shell
> ln -s ../libouistiti libhttpserver
```
 * create an archive of the source:  
```shell
> cd ..
> tar -czf ouistiti-3.3.0.orig.tar.gz ouistiti
```
 * use *debuild* to generate the package


