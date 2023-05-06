# tstamp
Timestamps git commits, so that [opentimestamps](https://opentimestamps.org) proofs can be generated.

## storage
Timestamp .ots files attesting existence of commits are stored in `refs/timestamps/commits` (pointing to a commit object whose associated tree references the blobs containing the `.ots` files).

Pending timestamps (unsubmitted and/or not yet included in bitcoin blockchain) are listed in `refs/timestamps/pending` (pointing to a binary blob object). Can be read using 
```
git cat-file blob refs/timestamps/pending | xxd
```

Calendar URLs are contained in `refs/timestamps/calendars` (pointing to a blob). The blob can be read using :
```
git cat-file blob refs/timestamps/calendars
```

Commit objects which have been timestamped will have a "note" listing the block height which attests to their existence. See [git-notes](https://git-scm.com/docs/git-notes) for more details. Timestamped commits can be searched using: 
```
git log --grep "bitcoin attests existence as of height" --grep "pending timestamp submitted on"
```

## usage
Create a merkle root digest for tree of `<COMMIT-ID>`:
```
tstamp -i <COMMIT-ID>
```
Set calendar URLs:
```
tstamp -c https://alice.btc.calendar.opentimestamps.org \
-c https://bob.btc.calendar.opentimestamps.org
```
Submit unsubmitted digests, and upgrade any pending timestamps which are ready:
```
tstamp -u
```
With `-d` flag, delete any unsubmitted digests instead of submitting them:
```
tstamp -u -d
```
Suppose that `<COMMIT-ID>` has been timestamped in the above fashion, and `file.txt` is a file in the tree referenced by the commit.
Generate an `.ots` proof for `file.txt`:
```
tstamp -i <COMMIT-ID> -f file.txt
```
The resulting `file.txt_<GIT_BLOB_ID>.ots` file can be verified on [opentimestamps](https://opentimestamps.org) using the file data returned by `git cat-file blob <GIT_BLOB_ID>`.
