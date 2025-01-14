# Patterns

Available:

- [x] [Flask/Django] SQL Injection
- [x] [Flask/Django] Command Injection
- [x] [Flask/Django] Path traversal
- [x] [Flask/Django] Deserialization of untrusted data
- [x] [Flask/Django] Unvalidated Redirects


## [Flask/Django] SQL Injection

In Django, the request might be in a variable which doesn't have a fixed name. This
means, the names that are presented are likely variable names
(`request`, `req`, `r`, `http_request`, `user_request` will be used as sources).
In Flask, the request is available in the `request` variable. Values that come
from this object were also added as sources.

Django uses most of the time an ORM, which means that usually there won't be 
SQL Injections. However, there are situations where the ORM is not a good fit,
so Django provides support for executing SQL statements directly (as is usual in Flask),
which is using `RawSQL`, `raw` and `execute`. Sometimes `handy` might also be used (so `handy`'s
database related functions are also considered as sinks). Note other database drivers
(different from `pycopg2` might be used). As an example, we also considered `MySQL Connector`
and `sqlite3`. For this reason the following sinks are added:

- `MySQL Connector`: (`execute`)
- `sqlite3`: (`execute`), `executemany`, `execute_script`, `create_function`, `create_aggregate`, `create_window_function`

(`SQLAlchemy`'s method is also `execute`)

The sanitizers considered are `psycopg2.mogrify`, `psycopg2.sql.SQL.format` (when `psycopg2`
is being used) and `mysql.connection.connector.escape_string` (for `MySQL Connector`) (no extra
sanitizers where found for `sqlite3`).

Other drivers can be considered (check [docs here](https://docs.djangoproject.com/en/5.0/ref/databases)),
but aren't added because it would be analogous and for demonstration purpose
has no added value.

## [Flask] Command Injection

Detects flows from values in the HTTP request (provided by flask) into shell calls
(using either the `subprocess` module, the `os` module, and the `popen2` module).
The considered sinks are the following:

- from `subprocess`: `call`, `check_call`, `check_output`, `run`, `Popen`, `getstatusoutput`, `getoutput`
- from `os`: `system`, `posix_spawn`, `posix_spawnp`, `spawnl`, `spawnle`, `spawnlp`, `spawnlpe`, `spawnv`, `spawnve`, `spawnvp`, `spawnvpe`, `startfile`, `popen`
- from `popen2`: `popen2`, `popen3`, `popen4`, `Popen3`, `Popen4`
- from `asyncio`: `create_subprocess_exec` and `create_subprocess_shell`

The sanitizers that can be used are `shlex.quote`.

## [Flask] Path traversal

Detects flows from values in the HTTP request (provided by flask) into actions on
files.

The sanitizers considered are:
- `os.path.normpath`, `os.path.commonpath`
- `werkzeug.secure_filename` and `werkzeug.security.safe_join`
- `sanitize_filename.sanitize`
-  functions from `pathvalidate`: `sanitize_filename`, `sanitize_filepath`, `replace_symbol`

The sinks considered will be any functions that perform actions based on filepaths:
- Functions from `shutil` module: `copyfile`, `copymode`, `copystat`, `copy`, `copy2`, `copytree`, `rmtree`, `move`, `disk_usage`, `chown`
- `open`
- Functions from `os` module: `chdir`, `access`, `chflags`, `chmod`, `chown`, `chroot`, `lchflags`, `lchmod`, `lchown`, `link`, `listdir`, `lstat`, `mkdir`, `makedirs`, `mkfifo`, `mknod`, `remove`, `removedirs`, `rename`, `renames`, `replace`, `rmdir`, `stat`, `symlink`, `truncate`, `unlink`, `getxattr`, `listxattr`, `removexattr`, `setxattr`, `walk`, `readlink`

## [Flask/pickle] Deserialization of untrusted data

The sinks are taken from the `pickle` python module.

No sanitizers were found for this problem.

## [Flask] Unvalidated redirects

Detects flows from the user provided data to the URL provided for redirects.

Were considered as sanitizers (follwing [this](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)):

- Regular expressions (`re` module): `match`, `search` and `fullmatch` 
- Functions from the `urllib.parse` module (both sanitization of user data and
safe builders for URLs are considered)

The sinks are the redirect functions from both [Flask](https://flask.palletsprojects.com/en/3.0.x/api/#flask.Flask.redirect) and [Django](https://docs.djangoproject.com/en/5.0/topics/http/shortcuts/#redirect).

---

## Useful links

- [Flask API](https://flask.palletsprojects.com/en/3.0.x/api/)
- [`subprocess` docs](https://docs.python.org/3/library/subprocess.html#module-subprocess)
- [`os` docs](https://docs.python.org/3/library/os.html#)
- [`popen2` docs](https://python.readthedocs.io/en/v2.7.2/library/popen2.html#module-popen2)
- [`handy` database related function docs](https://handy.readthedocs.io/en/latest/db.html)
- Djangos's [raw queries](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-raw-queries) and [direct custom SQL](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-custom-sql)
- [MySQL Connector driver docs](https://dev.mysql.com/doc/connector-python/en/connector-python-examples.html)
- [sqlite3 driver docs](https://docs.python.org/3/library/sqlite3.html)
- [`sanitize-filename` package](https://pypi.org/project/sanitize-filename/)
- [Usage of `os.path.commonpath` to check is path is safe](https://security.openstack.org/guidelines/dg_using-file-paths.html)
- [`urllib.parse` docs](https://docs.python.org/3/library/urllib.parse.html#module-urllib.parse)
