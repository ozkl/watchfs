# WatchFS
WatchFS is a file event monitoring utility for Mac OS. Ever wondered which process deleted a file? You can watch all kind of file events with WatchFS.

In simplest form:

```
sudo ./watchfs myfile
```

Filter with a specifif event:

```
sudo ./watchfs -e 6 myfile
```

where -e for event filtering and 6 means unlink event. To list all events use -l:

```
./watchfs -l
```

Also use -p for process filtering.

WatchFS uses audit pipe under the hood. Since audit pipe is also available in FreeBSD, WatchFS should be usable there!
