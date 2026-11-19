#!/system/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
# Sony discard-data adaptation of official dual_sys/twrp.sh. No formatter.
set -eu
set -o pipefail
cd "$(dirname "$0")"
stop() { echo "STOP: $*" >&2; exit 1; }
sha256sum -c SHA256SUMS || stop 'bundle changed'
. ./plan.env
[ "$(id -u)" = 0 ] || stop 'root required'
[ "$(getprop sys.boot_completed)" != 1 ] || stop 'Android is running'
[ "$(getprop ro.product.device)" = XQ-DQ72 ] || stop 'wrong product'
[ "$(getprop ro.serialno)" = PDX_DEVICE_SERIAL ] || stop 'wrong hardware serial'
[ "$(uname -r)" = "$KERNEL" ] || stop 'kernel changed'
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$BOOT_ID" ] || stop 'recovery session changed'
[ "$(readlink -f /dev/block/by-name/userdata)" = /dev/block/sda96 ] || stop 'userdata mapping changed'
[ "$(readlink -f /dev/block/by-name/rddata)" = /dev/block/sda97 ] || stop 'rddata mapping changed'
[ "$(readlink -f /dev/block/by-name/metadata)" = /dev/block/sda52 ] || stop 'metadata mapping changed'
[ "$(blockdev --getsize64 /dev/block/sda)" = 255844155392 ] || stop 'disk capacity changed'
[ "$(blockdev --getss /dev/block/sda)" = 4096 ] || stop 'sector size changed'
for command in sha256sum cmp dd blockdev readlink sync find cat mkdir; do
    command -v "$command" >/dev/null || stop "missing command: $command"
done

offline() {
    [ "$(blockdev --getsize64 /dev/block/sda96)" = 231519965184 ] || stop 'old userdata view differs'
    [ "$(cat /sys/class/block/sda96/start)" = 47467184 ] || stop 'userdata start differs'
    [ ! -d /sys/class/block/sda98 ] || stop 'partition98 already exists'
    for part in sda96 sda52; do
        [ -z "$(find "/sys/class/block/$part/holders" -mindepth 1 -maxdepth 1)" ] || stop "$part has holders"
        dev=$(cat "/sys/class/block/$part/dev")
        # Include all visible process mount namespaces, not only this shell.
        for info in /proc/[0-9]*/mountinfo; do
            [ -r "$info" ] || continue
            while read -r mount_id parent mounted root point rest; do
                [ "$mounted" != "$dev" ] || stop 'Data/metadata device mounted'
                case "$point" in /data|/metadata) stop 'Data/metadata mount exists' ;; esac
            done < "$info"
        done
    done
    sha256sum -c PROTECTED || stop 'rddata or metadata changed'
}
compare_gpt() {
    dd if=/dev/block/sda of=primary.read bs=4096 count=6 status=none
    dd if=/dev/block/sda of=backup.read bs=4096 skip=62461947 count=5 status=none
    cmp primary.read "gpt-primary.$1" || stop 'primary GPT differs'
    cmp backup.read "gpt-backup.$1" || stop 'backup GPT differs'
}
case "${1:-check}" in
    check) offline; compare_gpt before; echo 'CHECK OK; no block-device writes'; exit 0 ;;
    refresh)
        offline
        compare_gpt after
        [ -d started ] || stop 'no successful apply in this bundle'
        echo 'Refreshing reviewed kernel partition views' > stage
        ./sony-refresh refresh-reviewed-sony64
        echo 'Kernel96/98 refreshed; Android encrypted Data initialization pending' > stage
        exit 0 ;;
    verify) compare_gpt after; sha256sum -c PROTECTED; exit 0 ;;
    apply) [ "${2:-}" = 'PDX_DEVICE_SERIAL DISCARD-DATA unixnu 68719476736' ] || stop 'confirmation differs' ;;
    *) stop 'usage: check | apply CONFIRM' ;;
esac
offline
compare_gpt before
mkdir /tmp/unixnu-dual.lock || stop 'apply already started; inspect stage, never retry'
mkdir started || stop 'bundle already started'
echo 'Invalidate old encrypted Data; GPT still original' > stage
# Explicitly authorized data-discard mode. AOSP partition_wiped() recognizes
# zero first4K and init/vold formats THROUGH dm-default-key on next Android boot.
# Do not create a plaintext F2FS on raw metadata-encrypted userdata.
dd if=/dev/zero of=/dev/block/sda96 bs=4096 count=256 conv=notrunc,fsync
dd if=/dev/block/sda96 of=data-marker.read bs=4096 count=256 status=none
cmp data-marker.read zero-marker.bin || stop 'Data invalidation readback failed'
echo 'Old Data invalidated; writing backup GPT' > stage
dd if=gpt-backup.after of=/dev/block/sda bs=4096 seek=62461947 conv=notrunc,fsync
sync
dd if=/dev/block/sda of=backup.read bs=4096 skip=62461947 count=5 status=none
cmp backup.read gpt-backup.after || stop 'backup readback failed; keep recovery running'
echo 'Backup GPT verified; writing primary GPT' > stage
dd if=gpt-primary.after of=/dev/block/sda bs=4096 conv=notrunc,fsync
sync
compare_gpt after
sha256sum -c PROTECTED || stop 'protected contents differ'
echo 'Both GPT copies read back; Data awaits encrypted Android initialization' > stage
echo 'GPT COMPLETE; kernel partition refresh required before any image write'
