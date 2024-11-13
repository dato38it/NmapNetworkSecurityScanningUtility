#!/bin/bash
mkdir /var/log/reports
ls -l /data > /var/log/reports/$(date +"%d.%m.%Y")
tar -tf /backup/archive.tar >> /var/log/reports/$(date +"%d.%m.%Y")