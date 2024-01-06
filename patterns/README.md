# Patterns

## [SQL Alchemy/Flask] SQL Injection - raw SQL

Detects flows from values in the request (provided by flask) into raw database
functions (using SQL Alchemy)


## [Flask] Command Injection

Detects flows from values in the HTTP request (provided by flask) into shell calls
(using either the `subprocess` module, the `os` module, and the `popen2` module).
The considered sinks are the following:

From `subprocess`: `call`, `check_call`, `check_output`, `run`, `Popen`, `getstatusoutput`, `getoutput`
From `os`: `system`, `posix_spawn`, `posix_spawnp`, `spawnl`, `spawnle`, `spawnlp`, `spawnlpe`, `spawnv`, `spawnve`, `spawnvp`, `spawnvpe`, `startfile`, `popen`
From `popen2`: `popen2`, `popen3`, `popen4`, `Popen3`, `Popen4`

---

## Useful links

- [Flask API](https://flask.palletsprojects.com/en/3.0.x/api/)
- [SQLAlchmey - SQL Statements and Expressions API](https://docs.sqlalchemy.org/en/20/core/expression_api.html)
- [`subprocess` docs](https://docs.python.org/3/library/subprocess.html#module-subprocess)
- [`os` docs](https://docs.python.org/3/library/os.html#)
- [`popen2` docs](https://python.readthedocs.io/en/v2.7.2/library/popen2.html#module-popen2)
