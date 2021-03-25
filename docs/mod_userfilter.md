User filtering
--------------

# Description
After authentication and before document delivery, userfilter checks if
the user is allowed to use the URI with the requested's method.

**There is a check on the method, the role of the user and the URI.**

## User's role

A *role* is the name of the user or his group. It referers to the authentication's
information.

There is 3 specific roles:

* _superuser_: the first role allowed to add rules.
* _\*_: any authenticate's user or annonymous.
* "_annonymous_": the authentication allows to access to some URI whitout
credential (cf [mod_auth](mod_auth.md) "allow" configuration field).

# Configuration

		userfilter = {
			dbname = "/etc/ouistiti/filter.db";
			allow = "^token$,^trust/,.jpg$";
			superuser = "root";
			configuri = "/filter/config";
		};

## dbname

This entry contains the path to a sqlite3 DataBase. The database is used
to store the user's roles and the rules.

## allow

This entry is used to bypass the checking. Use this entry carefully.
Each element is separated by a coma, and use a regular expression:

* ^token$ : accept only request like

        GET /token?redirect=http://myserver/index.html HTTP/1.1

* ^trust/ : accept all URI located inside the trust directory. The leading /
is mandatory otherwise trustfoobar.html may be accessible too.

* .jpg$ : accept to deliver all jpeg ressources located on the server.

## superuser

The super user is the first user allowed to add rules. This user must be known
by the authentication.

The field is used only during the database creation. It may be deleted
when the database is created, even if all rule is not stored.

## configuri

This is an URI to POST rules. The superuser is the only one allowed to send
request on this URI. This URI **must NOT** be changed all the time of the database.

The rights on this URI is always checked.

# Database

A sqlite Database stores the rules. 3 tables are used:

 * **rules** : *methodid* *roleid* *pathexp*
 * **methods** : *id* *name[GET,POST,HEAD,PUT,DELETE,OPTIONS,...]*
 * **roles** : *id* *name[root,anonymous,users,clients,...]*

A rule is build with

 * a *role* : the user or the group after authentication must be strictly the same.
 * a *method* : the HTTP method is an uppercased string, and every method are allowed.
 * an *expression*: a regular expression on the URI.

Only few rules are available when the database is created:

        <superuser> GET *
        <superuser> PUT ^<configuri>*
        <superuser> DELETE ^<configuri>*


**superuser** and **configuri** are defined in the module configuration and must
not be changed after the database creation.

The Database may updated by the "sqlite3" tool or with a webservice in REST API.

# Webservice for rules management

The webservice is available from the **configuri** configuration string.

It accepts the methods:
 * **GET** to retrieve the list of rules.
 * **PUT** to append a new rule.
 * **DELETE** to remove a rule.

## Retrieve the rules

A **GET** request on **configuri** returns a JSON string
with a table of rules.

The JSON format of a rule is:
 * "id" : the id in the table, usefull to remove it.
 * "method" : the method to filter.
 * "role" : the user's role allowed.
 * "pathexp" : the regular expression on the URI to check.

### Example

        [{"id":1,"method":"GET","role":"root","pathexp":"*"},
        {"id":2,"method":"PUT","role":"root","pathexp":"^/filter/config*"},
        {"id":3,"method":"DELETE","role":"root","pathexp":"^/filter/config*"}]

## Add a rule to the database

The rules are appended in the database with a **PUT** request on
**configuri**. The data must be and in x-www-form-urlencoded format:

```config
 role=<user or group name>
 method=<GET, POST, PUT, DELETE...>
 pathexp=<regexp>
```

### Example

		PUT /filter/config HTTP/1.1
		HOST: 127.0.0.1
		Authorization: Basic cm9vdDp0ZXN0
		Content-Type: application/x-www-form-urlencoded
		Content-Length: 38

		role=users&method=GET&pathexp=^cgi-bin/*.cgi

This allow all user of the group "users" to access to all ressources containing
the string ".cgi" and located inside the "cgi-bin" directory.

## Remove a rule

A rule may be removed by its **ID** with a **DELETE** request on the
**configuri**/**ID** URI.

### Example

		DELETE /filter/config/4 HTTP/1.1
		HOST: 127.0.0.1
		Authorization: Basic cm9vdDp0ZXN0

## URI expression

The URI of a rule may be a regular expression with some limitations and specific
features.

There is some special characters:

 - ^ : means the beginning of the URI, and no character must be present before.
 - $ : means the end of the URI, and no character must be present after.
 - \* : is the standard wildcard.
 - ~~ \. : is not available. ~~
 - %u : is replaced by the user name.
 - %g : is replaced by the user's group name.
 - %h : is replaced by the user's home path.

### Example:

        role=users&method=PUT&pathexp=^%g/%u/\*

All user of the group "users" is allowed to put file on /users/<user>/.
For "foo", /users/foo/test.txt is allowed, but /users/test/test.txt is
disallowed, /root/root/test.txt is disallowed,
/cgi-bin/users/foo/text.cgi is disallowed.

