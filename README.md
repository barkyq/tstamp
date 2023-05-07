# tstamp
Timestamps git commits, so that [opentimestamps](https://opentimestamps.org) proofs can be generated.

## storage
Timestamp `.ots` files attesting existence of commits are stored in `refs/timestamps/commits` (this ref points to a commit object whose associated tree references the blobs containing `.ots` files).

Pending timestamps (unsubmitted and/or not yet included in bitcoin blockchain) are listed in `refs/timestamps/pending`. The ref points to a binary blob which can be read using:
```
git cat-file blob refs/timestamps/pending | xxd -c 53 -g 21
```
The first byte is either `0x00` or `0x01` depending on whether the digest is unsubmitted, or the timestamp is pending.

Calendar URLs are contained in `refs/timestamps/calendars`. The ref points to a blob which can be read using:
```
git cat-file blob refs/timestamps/calendars
```

Commit objects which have been timestamped will have a "note" listing the block height which attests to their existence. See [git-notes](https://git-scm.com/docs/git-notes) for more details. Timestamped commits can be searched using: 
```
git log --grep "bitcoin attests existence as of height" --grep "pending timestamp submitted on"
```

## usage
To create a merkle root digest for tree of `<COMMIT-ID>`, run:
```
tstamp -i <COMMIT-ID>
```
To set calendar the URLs:
```
tstamp -c https://alice.btc.calendar.opentimestamps.org \
-c https://bob.btc.calendar.opentimestamps.org \
-c https://btc.calendar.catallaxy.com \
-c https://finney.calendar.eternitywall.com \
```
To submit unsubmitted digests, and upgrade any pending timestamps which are ready:
```
tstamp -u
```
With `-d` flag, delete any unsubmitted digests instead of submitting them:
```
tstamp -u -d
```

### generating ots proofs
Suppose that `<COMMIT-ID>` has been timestamped in the above fashion, and `file.txt` is a file in the tree referenced by the commit.
Generate an `.ots` proof for `file.txt`:
```
tstamp -i <COMMIT-ID> -f file.txt
```
The resulting `file.txt_<GIT-BLOB-ID>.ots` file can be verified on [opentimestamps](https://opentimestamps.org) using the version of file.txt corresponding to `<GIT-BLOB-ID>`. The file data can be output using, e.g., 
```
git cat-file blob <GIT-BLOB-ID> > file.txt_<GIT-BLOB-ID>
```
As a special case, one can also generate a proof for the commit data:
```
tstamp -i <COMMIT-ID> --commit-proof
```
The resulting file `<COMMIT-ID>.ots` is a timestamp for the data returned by:
```
git cat-file commit <COMMIT-ID>
```
See the [example](example/) for an `.ots` file for `init commit` in this repository.