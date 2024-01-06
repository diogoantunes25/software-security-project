# Patterns

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
means, the name that are presented are the likely variable name (`request`, `req`, `r`, `http_request`, `user_request` will be used)

Django uses most of the time an ORM, which means that usually there won't be 
SQL Injections. However, there are situations where the ORM is not a good fit,
so Django provides support for executing SQL statements directly, which is using
`RawSQL`, `raw` and `execute`. Sometimes `handy` might also be used (so `handy`'s
database related functions are also considered as sinks)

## [Flask] Command Injection

Detects flows from values in the HTTP request (provided by flask) into shell calls
(using either the `subprocess` module, the `os` module, and the `popen2` module).
The considered sinks are the following:

From `subprocess`: `call`, `check_call`, `check_output`, `run`, `Popen`, `getstatusoutput`, `getoutput`

From `os`: `system`, `posix_spawn`, `posix_spawnp`, `spawnl`, `spawnle`, `spawnlp`, `spawnlpe`, `spawnv`, `spawnve`, `spawnvp`, `spawnvpe`, `startfile`, `popen`

From `popen2`: `popen2`, `popen3`, `popen4`, `Popen3`, `Popen4`

## [Flask] Path traversal

Detects flows from values in the HTTP request (provided by flask) into actions on
files.

Sanitizers:
- `os.path.normpath`
- `secure_filename`: CHECK (from `werkzeug.utils`)
// TODO

Sinks:
- Functions from `shutil` module: `copyfile`, `copymode`, `copystat`, `copy`, `copy2`, `copytree`, `rmtree`, `move`, `disk_usage`, `chown`
- `open`
- Functions from `os` module: `chdir`, `access`, `chflags`, `chmod`, `chown`, `chroot`, `lchflags`, `lchmod`, `lchown`, `link`, `listdir`, `lstat`, `mkdir`, `makedirs`, `mkfifo`, `mknod`, `remove`, `removedirs`, `rename`, `renames`, `replace`, `rmdir`, `stat`, `symlink`, `truncate`, `unlink`, `getxattr`, `listxattr`, `removexattr`, `setxattr`
- Functions from `os.path` module: `exists`, `lexists`, `getatime`, `getmtime`, `getctime`, `getsize`
- Functions from `pathlib` module: `Path`, `PurePath`, `PurePosixPath`, `PosixPath`, `PureWindowsPath`, `WindowsPath` // TODO: might make sense to add more

## [Flask] XSS

Detects flows from values in the HTTP request of one user (provided by flask) into objects
that will be rendered by other users

Sanitizers:
- `Markup.escape`

Sinks:
- `render_template`
- `Markup`

## [Flask/pickle] Deserialization of untrusted data

The sinks are taken from the `pickle` python module

// TODO: check if I don't want implicit flows (I don't think I do)

## [Flask/pickle] Unvalidated redirects

Here, the entire `request` object is considered as a source. However, this 
would result in most redirects being flagged with a vulnerability.

// TODO: solve problem of too many positives

---

## Useful links

- [Flask API](https://flask.palletsprojects.com/en/3.0.x/api/)
- [SQLAlchmey - SQL Statements and Expressions API](https://docs.sqlalchemy.org/en/20/core/expression_api.html)
- [`subprocess` docs](https://docs.python.org/3/library/subprocess.html#module-subprocess)
- [`os` docs](https://docs.python.org/3/library/os.html#)
- [`popen2` docs](https://python.readthedocs.io/en/v2.7.2/library/popen2.html#module-popen2)
- [`handy` database related function docs](https://handy.readthedocs.io/en/latest/db.html)
- Djangos's [raw queries](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-raw-queries) and [direct custom SQL](https://docs.djangoproject.com/en/dev/topics/db/sql/#executing-custom-sql)
