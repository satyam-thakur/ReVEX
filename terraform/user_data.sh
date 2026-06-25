#!/bin/bash
set -e
echo "Installing docker..."

apt-get -q update
apt-get -q install -y apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
apt-get -q update
apt-cache policy docker-ce
apt-get -q install -y docker-ce

systemctl enable docker
systemctl start docker
systemctl status docker || true

# Allow default user (ubuntu) to run docker without sudo
usermod -aG docker ubuntu
newgrp docker <<EONG
docker version
EONG

echo "Installing docker-compose..."
curl -sL https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version

echo "Checking for persistent disk..."
# Check if disk attached to /dev/sdb exists
if [ -b /dev/sdb ]; then
  echo "Disk /dev/sdb found."
  # Check if disk is formatted
  if ! blkid /dev/sdb; then
    echo "Formatting disk /dev/sdb..."
    mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/sdb
  else
    echo "Disk /dev/sdb already formatted."
  fi

  # Create mount point
  mkdir -p /data
  mount /dev/sdb /data
  
  # Configure auto-mount on reboot
  echo UUID=`blkid -s UUID -o value /dev/sdb` /data ext4 discard,defaults,nofail 0 2 | tee -a /etc/fstab
  
  # Set permissions
  chown -R ubuntu:ubuntu /data
  chmod 755 /data
  
  echo "Persistent disk mounted at /data"
else
  echo "Disk /dev/sdb not found."
fi
