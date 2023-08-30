dd if=/dev/zero of=/tmp-part bs=1 count=0 seek=5G
mkfs.xfs /tmp-part
echo "/tmp-part /tmp xfs loop,nosuid,nodev,rw 0 0" >> /etc/fstab
mount -a
chmod 3777 /tmp
