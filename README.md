Diskwalker
==========

a simple script to walk your disk and keep track of interesting sets of files
-----------------------------------------------------------------------------

After gaining access to a remote machine during penetration testing, you might want to find interesting configuration files or binaries to attempt a privilege escalation.

The script is self contained, and works on both Python3 and Python2.7, so as to be compatible with both recent machines (who don't ship python2 by default) and not-so-recent as well.

Instead of executing several `find` commands, this simple script just keep track of them by doing a single pass over your whole disk tree structure, by applying all the predicates (the functions ending in `_p` or `_filep` for predicates to be applied only to files).

Still a WIP, but the code is really tight and it's very easy to write your own predicates: it just needs to be a function that receives a file path and returns a boolean.

At the end, all the sets of files are stored in a dictionary called `d`, its keys are the predicate names. To get access to it simply execute `python3 -i diskwalk.py`. You will be dropped in a python repl, and since these are python sets you can easily do operations like

```python
d['executable_files'] & d['writable_files']
```

To get the set of files that are both writable and executable


```python
d['executable_files'] - d['readable_files']
```

To get the files executable but not readable


```python
d['owned_by_nobody_dirs'] | d['owned_by_nobody_files']
```

To get the union of directories and files owned by the `nobody` user

The obtained data will be saved to a pickled and compressed file `dump.gz`, simply supply it as an argument to load it and avoid scanning the disk again

`python -i diskwalk.py dump.gz`

Due to how python's pickle works, the usual caveats apply: you won't be able to load this same file into a different python interpreter from the one that you used to generate the file, for example.
