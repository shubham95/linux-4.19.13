#!/bin/bash
git add .
git commit -am `$date`
git push
sudo make bzImage
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-4.19.13Connoisseur
#sudo init 0
