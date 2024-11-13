#!/bin/bash
if find /data/ -type f -mtime +5; then
cd /data
tar -cvf /backup/archive.tar testfile*
rm -rf /data/testfile*
else
echo "No files"
fi