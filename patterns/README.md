# Patterns

Available:

- [ ] [SQLAlchemy/Flask] SQL Injection 1
- [ ] [SQLAlchemy/Flask] SQL Injection 2
- [x] [Django] SQL Injection
- [x] [Flask/Django] Command Injection
- [x] [Flask/Django] Path traversal
- [x] [Flask/Django] Deserialization of untrusted data
- [ ] [Flask] Unvalidated Redirects


## [SQL Alchemy/Flask] SQL Injection 1

Detects flows from values in the request (provided by flask) into raw database
functions (using SQL Alchemy)

The sources are functions/variables whose value are taken from the HTTP request
(i.e. user controlled):

- Methods/attributes of `request` object (didn't include `request`, because
it would trigger a lot of false positives)
- `get`

Sanitizers are SQL sanitizers:

// TODO

The sinks are ...:

// TODO

## [SQL Alchemy/Flask] SQL Injection 2

**// TODO: improve this explanation**

Detects flows from values in the request (provided by flask) into raw database
functions (using SQL Alchemy). The difference here is that an arbitrary command
can't be run, because the whole command is not built, but rather arguments for the 
command are provided

Sources - same as before

Sinks:

- where is `filter` defined?
- where is `where` defined?

## [Django/] SQL Injection - raw SQL

In Django, the request variable doesn't have a fixed name (as in Flask). This
means, the names that are presented are likely variable names
(`request`, `req`, `r`, `http_request`, `user_request` will be used)

Django uses most of the time an ORM, which means that usually there won't be 
SQL Injections. However, there are situations where the ORM is not a good fit,
so Django provides support for executing SQL statements directly, which is using
`RawSQL`, `raw` and `execute`. Sometimes `handy` might also be used (so `handy`'s
database related functions are also considered as sinks). Note another database driver
that not `pycopg2` might being used (for example `mysql` - for this driver the
method to execute the SQL command is the same, so no source is added).

The sanitizers considered are `psycopg2.mogrify`, `psycopg2.sql.SQL.format` (when `psycopg2`
is being used) and `mysql.connection.connector.escape_string` (for `mysql`).

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
- Functions from `os` module: `chdir`, `access`, `chflags`, `chmod`, `chown`, `chroot`, `lchflags`, `lchmod`, `lchown`, `link`, `listdir`, `lstat`, `mkdir`, `makedirs`, `mkfifo`, `mknod`, `remove`, `removedirs`, `rename`, `renames`, `replace`, `rmdir`, `stat`, `symlink`, `truncate`, `unlink`, `getxattr`, `listxattr`, `removexattr`, `setxattr`
- Functions from `pathlib` module: `Path`, `PurePath`, `PurePosixPath`, `PosixPath`, `PureWindowsPath`, `WindowsPath`

## [Flask/pickle] Deserialization of untrusted data

The sinks are taken from the `pickle` python module.

No sanitizers were found for this problem.

## [Flask/pickle] Unvalidated redirects

Detects flows from the user provided data to the URL provided for redirects.

Were considered as sanitizers (follwing [this](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html):

- Regular expressions (`re` module): `match`, `search` and `fullmatch` 
- `urlparse`

---

## Useful links

- [Flask API](https://flask.palletsprojects.com/en/3.0.x/api/)
- [SQLAlchmey - SQL Statements and Expressions API](https://docs.sqlalchemy.org/en/20/core/expression_api.html)
- [`subprocess` docs](https://docs.python.org/3/library/subprocess.html#module-subprocess)
- [`os` docs](https://docs.python.org/3/library/os.html#)
- [`popen2` docs](https://python.readthedocs.io/en/v2.7.2/library/popen2.html#module-popen2)
- [`handy` database related function docs](https://handy.readthedocs.io/en/latest/db.html)
- Djangos's [raw queries](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-raw-queries) and [direct custom SQL](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-custom-sql)
- [MySQL driver docs](https://dev.mysql.com/doc/connector-python/en/connector-python-examples.html)
- [`sanitize-filename` package](https://pypi.org/project/sanitize-filename/)
- [Usage of `os.path.commonpath` to check is path is safe](https://security.openstack.org/guidelines/dg_using-file-paths.html)
