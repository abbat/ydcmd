# ydcmd

Linux/FreeBSD command line client for interacting with cloud storage [Yandex.Disk](https://disk.yandex.com/) by means of [REST API](http://api.yandex.com/disk/api/concepts/about.xml).

## Download / Install

* [Debian, Ubuntu](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Fedora, openSUSE, CentOS](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Ubuntu PPA](https://launchpad.net/~abbat/+archive/ubuntu/ydcmd) - `ppa:abbat/ydcmd`
* [Arch AUR](https://aur.archlinux.org/packages/ydcmd/) (see also [AUR Helpers](https://wiki.archlinux.org/index.php/AUR_Helpers))
* From source code:

```
$ git clone https://github.com/abbat/ydcmd.git
$ sudo cp ydcmd/ydcmd.py /usr/local/bin/ydcmd
```

## Pre-starting procedure

To run the client you need a OAuth debugging token. To obtain one, [register the application on Yandex](https://oauth.yandex.com/client/new):

* `Name` - `ydcmd` (can be arbitrary)
* `Permissions` - `Yandex.Disk REST API`
* `Client for development` - select check box

After registering the application, copy `application id` and follow the next link:

* `https://oauth.yandex.com/authorize?response_type=token&client_id=<id_application>`

After granting access, service will redirect you to the link of the following form:

* `https://oauth.yandex.com/verification_code?dev=True#access_token=<token>`

Value "token" is the required one. For more info please follow the link [manually obtaining a debugging token](http://api.yandex.com/oauth/doc/dg/tasks/get-oauth-token.xml).

## Running

You can access help (brief info) within the command line by running a script with no parameters or by entering `help` command. The general invocation format:

```
ydcmd [command] [options] [arguments]
```

**Commands**:

* `help` - returns brief info on application's commands and options;
* `ls` - returns a list of files and directories;
* `rm` - deletes a file or directory;
* `cp` - copies a file or directory;
* `mv` - moves a file or directory;
* `put` - uploads a file or directory into the storage;
* `get` - retrieves a file or directory from the storage;
* `mkdir` - creates a directory;
* `stat` - returns meta-information about an object;
* `info` - returns meta-information about a storage;
* `last` - returns meta-information about last uploaded files;
* `du` - evaluates the disk space used by files within the storage;
* `clean` - cleans files and directories.

**Options**:

* `--timeout=<N>` - timeout (in seconds) for establishing a network connection;
* `--retries=<N>` - number of attempts of API method invocation before returning an error code;
* `--delay=<N>` - timeout (in seconds) between attempts of API method invocation;
* `--limit=<N>` - the number of items returned after a single invocation of a method for obtaining a list of files and directories;
* `--token=<S>` - oauth token (for security purposes, should be specified in the configuration file or through an environment variable `YDCMD_TOKEN`);
* `--quiet` - error output suppression, return code determines a successful operation result;
* `--verbose` - returns expanded information;
* `--debug` - returns debug information;
* `--chunk=<N>` - data block size (in KB) for I/O operations;
* `--ca-file=<S>` - file name with certificates of trusted certification authorities (if the value is null, certificate validation is not performed);
* `--ciphers=<S>` - set of encryption algorithms (see [ciphers(1)](https://www.openssl.org/docs/apps/ciphers.html)).

### Returning a list of files and directories

```
ydcmd ls [options] [disk:/object]
```

**Options**:

* `--human` - returns file size (in human-readable form);
* `--short` - returns a list of files and directories without additional information (one name per line);
* `--long` - returns an extended list (creation time, modification time, size, file name).

If a target object is not specified, then the storage's root directory will be used.

### Deleting a file or directory

```
ydcmd rm disk:/object
```

**Options**:

* `--poll=<N>` - interval (in seconds) between status polls during an asynchronous operation;
* `--async` - runs a command without waiting for operation to terminate (`poll`).

Files are deleted permanently. Directories are deleted recursively (including sub files and sub directories).

### Copying a file or directory

```
ydcmd cp disk:/object1 disk:/object2
```

**Options**:

* `--poll=<N>` - interval (in seconds) between status polls during asynchronous operations;
* `--async` - runs a command without waiting for operation to terminate (`poll`).

In case of name coincidence, directories and files will be overwritten. Directories are copied recursively (including sub folders and sub directories).

### Moving a file or directory

```
ydcmd mv disk:/object1 disk:/object2
```

**Options**:

* `--poll=<N>` - interval (in seconds) between status polls during asynchronous operations;
* `--async` - runs a command without waiting for operation to terminate (`poll`).

In case of name coincidence, directories and files will be overwritten.

### Uploading a file into the storage

```
ydcmd put <file> [disk:/object]
```

**Options**:

* `--rsync` - synchronizes a tree of files and directories in the storage with a local tree;
* `--encrypt` - encryption of files using `--encrypt-cmd` before uploading to the storage;
* `--encrypt-cmd` - command sending to `stdin` the contents of the local (unencrypted) file and sending its encrypted version to `stdout`;
* `--temp-dir` - a directory for storing temporary encrypted files.

If a target object is not specified, then the storage's root directory will be used for uploading a file. If a target object denotes a directory (ends with `/`), then the source file name will be added to the directory's name. If a target object exists, it will be overwritten without a confirmation prompt. Symbolic links are ignored.

### Retrieving a file from the storage

```
ydcmd get <disk:/object> [file]
```

**Options**:

* `--rsync` - synchronizes a local tree of files and directories with a tree in the storage;
* `--decrypt` - decryption of files using `--decrypt-cmd` after obtaining them from the storage;
* `--decrypt-cmd` - command sending to `stdin` the contents of an encrypted file from the storage and sending its unencrypted version to `stdout`;
* `--temp-dir` - a directory for storing temporary encrypted files.

If the target file's name is not specified, the file's name within the storage will be used. If a target object exists, it will be overwritten without a confirmation prompt.

### Creating a directory

```
ydcmd mkdir disk:/path
```

### Obtaining meta-information about an object

```
ydcmd stat [disk:/object]
```

If a target object is not specified, then the storage's root directory will be used.

### Obtaining meta-information about a storage

```
ydcmd info
```

**Options**:

* `--long` - returns sizes in bytes instead of human-readable form.

### Obtaining meta-information about last uploaded files

```
ydcmd last [N]
```

**Options**:

* `--human` - returns file size (in human-readable form);
* `--short` - returns a list of files without additional information (one name per line);
* `--long` - returns an extended list (creation time, modification time, size, file name).

If argument N is not specified, default REST API value will be used.

### Evaluating the disk space used

```
ydcmd du [disk:/object]
```

**Options**:

* `--depth=<N>` - returns the sizes of directories up to the level N;
* `--long` - returns sizes in bytes instead of human-readable form.

If a target object is not specified, then the storage's root directory will be used.

### Cleaning files and directories

```
ydcmd clean <options> [disk:/object]
```

**Options**:

* `--dry` - returns a list of objects for removal, instead of deleting;
* `--type=<S>` - the type of objects for removal (`file` - files, `dir` - directories, `all` - all);
* `--keep=<S>` - value of selection criteria related to objects to be saved:
  * A date string in ISO format can be used to select a date **up to which** you want to delete the data (for example, `2014-02-12T12:19:05+04:00`);
  * For selecting a relative time, you can use a number and a dimension (for example, `7d`, `4w`, `1m`, `1y`);
  * For selecting the number of copies, you can use a number without a dimension (for example, `31`).

If a target object is not specified, then the storage's root directory will be used. Objects are sorted and filtered according to modification date (not by creation date).

## Configuration

For convenience, we recommend creating a configuration file named `~/.ydcmd.cfg` and granting it file permissions `0600` or `0400`. File format:

```
[ydcmd]
# comment
<option> = <value>
```

For example:

```
[ydcmd]
token   = 1234567890
verbose = yes
ca-file = /etc/ssl/certs/ca-certificates.crt
```

## Environment variables

* `YDCMD_TOKEN` - oauth token, has priority over the option `--token`.

## Exit code

When operating in automatic mode (cron), it may be useful to get the result of the command's execution:

* `0` - successful completion;
* `1` - general application error;
* `4xx` - HTTP status code 4xx (client error);
* `5xx` - HTTP status code 5xx (server error).
